# LEGION

Code for **LEGION: Benchmarking Language Agents on Sparse-Signal Investigation Under Adversarial Noise**.

LEGION couples a stochastic enterprise-telemetry simulator (**LEGION-SIM**) with a library of 74 expert-crafted attack scenarios (**LEGION-BENCH**). A company is simulated once; each scenario is then injected into it against a sampled victim, an agent investigates from the alert alone through a SOC tool interface, and its trajectory and report are scored against the ground truth recorded at injection time.

## Repository layout

```
src/
  company_generation/   LEGION-SIM: static company generator + event enrichment (logins, email,
                        files, processes, apps, MFA, devices, network, admin, cloud, confounders)
    static/configurations/static_companies/   company YAMLs (Meridian, NexusTech)
  attacks/              the 74 scenario templates, the injection engine and alert generation
  soc_tools/            SOC tool catalog exposed to agents (+ tool ablations)
  agents/               Direct, ReAct, SPA, Reflexion, Multi-Agent
  baselines/golden/     deterministic Golden Workflow baseline
  evaluation/           Event Recall, Findings Recall (LLM judge), IoC recall / precision
  bench/                benchmark harness, runner, reports and bootstrap CIs
twin/generators/        company JSON -> SQLite converter used by the SOC tools
golden_workflows/       expert playbooks the Golden Workflow follows
constants/<company>/    LLM-generated email scenarios and file catalog per company
scripts/                generate_variations.py (difficulty variants of a company)
bench/fixtures/         simulated companies (distributed separately, see below)
```

## Installation

```bash
poetry install                # or: pip install -e .
export OPENAI_API_KEY=...     # agents (GPT-5.5) and the Findings Recall judge (gpt-4o-mini)
export ANTHROPIC_API_KEY=...  # only for generating constants for a new company (default: Claude Sonnet)
```

All model calls go through [LiteLLM](https://docs.litellm.ai/), so set the keys for whichever providers you use. Tested with Python 3.13 and 3.14. All commands below are run from the repository root.

## 1. Companies

### Use the companies from the paper

Download the released fixtures (**TODO: link**) into `bench/fixtures/`. The per-company `constants/` are already in the repo.

```
bench/fixtures/meridian_healthcare/baseline/meridian_healthcare/company_enriched.json
bench/fixtures/nexustech_global/baseline/nexustech_global/company_enriched.json
bench/fixtures/meridian_healthcare/confounder_rate_x3.0/meridian_healthcare/company_enriched.json
bench/fixtures/meridian_healthcare/event_density_x3.0/meridian_healthcare/company_enriched.json
```

### Generate a company

Generating a company has three steps. Step 0 is only needed for a new company; Meridian and NexusTech already ship their constants.

```bash
COMPANY=meridian_healthcare
CONFIG=src/company_generation/static/configurations/static_companies/$COMPANY.yaml
OUT=bench/fixtures/$COMPANY/baseline

# 0. (new companies only) generate email scenarios + file catalog with an LLM -> constants/$COMPANY/
#    (overwrites existing constants for that company; --model selects the LiteLLM model)
python -m company_generation.variable.generate_company_constants --config $CONFIG

# 1. Static company: employees, org graph, devices, networks, groups, mailboxes, cloud assets
python -m company_generation.static.company_static_generator \
  --config $CONFIG --out-dir $OUT --seed 1337

# 2. Enrich with ~30 days of telemetry (all event streams, correlations, bursts, confounders)
python -m company_generation.variable.enrich_events_cli \
  --company $OUT/$COMPANY/company_static.json \
  --out     $OUT/$COMPANY/company_enriched.json \
  --seed 1337 --email-scenarios 12 --min-email-scenarios 8
```

To add a new company, write a YAML next to the existing ones (see Appendix B of the paper for the schema), then run steps 0–2.

### Difficulty variants (Table 3)

The variants change one setting on top of step 2:

```bash
# 3x confounders
python -m company_generation.variable.enrich_events_cli ... --confounder-rate-scale 3.0

# 3x events
python -m company_generation.variable.enrich_events_cli ... \
  --logins-multiplier 3.0 --file-events-multiplier 3.0 --admin-actions-multiplier 3.0 \
  --app-events-multiplier 3.0 --process-events-multiplier 3.0 --device-events-multiplier 3.0 \
  --network-events-multiplier 3.0 --cloud-events-multiplier 3.0
```

`python scripts/generate_variations.py --companies meridian_healthcare` generates the baseline plus every single-setting variant (employees, event density, confounder rate, correlation ratio, baseline std) under `bench/fixtures/<company>/<variant>/`.

## 2. Running agents

Each scenario is injected into a fresh copy of the company against `--n-victims` sampled employees. Each agent then investigates, and the run is scored.

```bash
python -m bench.run_evaluation isolated \
  --company bench/fixtures/meridian_healthcare/baseline/meridian_healthcare/company_enriched.json \
  --agents direct,react,spa,reflexion,multi \
  --models gpt-5.5 \
  --n-victims 5 --seed 42 \
  --max-turns 20 \
  --eval-model gpt-4o-mini \
  --output-dir results/meridian/baseline \
  --workers 8 --progress --resume
```

These are the settings used in the paper: GPT-5.5 agents, a budget of 20 LLM calls, 5 victims per scenario, and a `gpt-4o-mini` judge.

- `--scenario <id>` or `--scenarios <id1,id2,...>` restricts the run to a subset of scenarios. `python -m bench.run_evaluation list-scenarios` lists all 74.
- `--models` takes any LiteLLM model name, e.g. `gpt-5.6-terra`, `gpt-5.6-luna`, `claude-opus-4-7`, `gemini/gemini-pro-latest`.
- `--ablation` restricts the tools available to the agent; the company data is unchanged:
  - `no_analysis` removes the tools that contain their own detection logic (risky users, suspicious processes, ...) and reduces threat-intel lookups to a Malicious/Benign verdict.
  - `ti_and_query` leaves only raw SQL queries (`splunk_run_query`) and threat intel.
  - `query_only` leaves only raw SQL, with no threat intel.
- `--resume` skips runs that already have a trace, so an interrupted run can be restarted.

### Paper experiments

| Experiment | Fixture | Flags that differ from the command above |
|---|---|---|
| Main results (Fig. 2, Table 2) | `meridian_healthcare/baseline`, `nexustech_global/baseline` | none; for NexusTech add `--scenarios $(cat scripts/nexustech_scenarios.txt)` (the 43 scenarios used in the paper) |
| Confounders / event volume (Table 3) | `meridian_healthcare/confounder_rate_x3.0`, `event_density_x3.0` | `--agents react` |
| Backbone models (Table 4) | `meridian_healthcare/baseline` | `--agents direct,react,multi --models <model> --n-victims 1 --max-turns 45` (these runs used a 45-call budget) |
| Tool ablations (Table 5) | `meridian_healthcare/baseline` | `--agents direct,react --n-victims 1 --ablation no_analysis` or `--ablation ti_and_query` |
| Golden Workflow (Fig. 2) | both baselines | see below, `--n-victims 1` |

### Golden Workflow baseline

```bash
python -m bench.run_baseline isolated --baseline golden_workflow \
  --company bench/fixtures/meridian_healthcare/baseline/meridian_healthcare/company_enriched.json \
  --model gpt-5.5 --n-victims 1 --seed 42 --eval-model gpt-4o-mini \
  --output-dir results/meridian/golden_workflow
```

The tool calls are deterministic. `--model` is the LLM that makes the single call that writes the report from the collected evidence.

## 3. Outputs

Each `--output-dir` contains:

- `single_results/<scenario>_<instance>__<agent>__<model>[__ablation_<name>].json`: one file per run, where `<instance>` is the id of the injected attack (one per victim) and `no_analysis` is saved under its full name, `no_tier1_ti_verdict_only`. Each holds the full trace (messages, tool calls), the report, the victim, the ground truth and the evaluation.
- `results.csv`: one row per run with Event Recall, Findings Recall, IoC recall / precision / F1 and related columns.
- `report.md` and `metrics_ci.csv`: per-agent aggregates with 95% cluster-bootstrap CIs over scenarios.
- `errors.jsonl`: runs that failed (e.g. API errors). The paper's tables exclude errored runs.

During a run, the company is converted once into a SQLite database under `<output-dir>/_tmp/`. The directory is deleted when the run finishes.

To rebuild the report from existing traces, run `python -m bench.report <output-dir>`.

## Reproducibility notes

- **Victim sampling** is seeded with `hash((seed, scenario_id))`, and Python randomizes string hashes per process. Set `PYTHONHASHSEED=0` to get the same victims across runs. The paper's runs did not fix it, so their victims cannot be re-derived from `--seed`; each trace records its `victim_id`.
- **Company generation** anchors the 30-day telemetry window on the current time and uses random UUIDs for some IDs. A regenerated company is statistically equivalent to the released one but not byte-identical. Use the released fixtures to reproduce the paper.
- LLM agents are stochastic, so expect small run-to-run differences.

## Cost

A full Meridian run is 74 scenarios × 5 victims × 5 agents ≈ 1,850 investigations. For a quick check, use `--n-victims 1 --agents react --scenarios aitm_phishing`.
