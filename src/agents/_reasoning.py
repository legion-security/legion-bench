"""Optional reasoning_effort injection for models that require it.

Some OpenAI reasoning models (the gpt-5.6 family) reject function tools on
/v1/chat/completions unless reasoning_effort is explicitly set to 'none':

    OpenAIException - Function tools with reasoning_effort are not supported
    for gpt-5.6-luna in /v1/chat/completions. To use function tools, use
    /v1/responses or set reasoning_effort to 'none'.

The scaffolds call litellm.completion() directly in nine places, so we patch
the entry point once here instead of threading a parameter through each one.

Opt in per run:

    LEGION_REASONING_EFFORT=none python -m bench.run_evaluation isolated ...

Unset (the default) means no change whatsoever, so existing gpt-5.5 results
stay reproducible.

Whether a given (model, effort) pair is legal varies by provider *and* by
litellm version, and the model_cost flags do not predict it reliably -- on
litellm 1.80.11, claude accepts low/medium/high but raises on 'none', gemini
rejects reasoning_effort outright, gpt-4o has no such parameter, and 'xhigh'
fails even though the registry advertises support. So rather than guess, we
ask litellm to build the request params and only inject when that succeeds.
A model we cannot inject for is left exactly as the scaffold called it.
"""

import logging
import os
from typing import Dict, Tuple

import litellm

logger = logging.getLogger(__name__)

_ORIGINAL_COMPLETION = litellm.completion

# Minimal tool payload: presence of `tools` is part of what makes some
# (model, effort) combinations illegal, so the probe has to include it.
_PROBE_TOOLS = [{"type": "function", "function": {"name": "_probe", "parameters": {}}}]

_ACCEPTS: Dict[Tuple[str, str], bool] = {}


def _accepts_effort(model: str, effort: str) -> bool:
    """True if litellm will build a valid request for this model at this effort."""
    key = (model, effort)
    if key in _ACCEPTS:
        return _ACCEPTS[key]

    ok = False
    try:
        from litellm import get_llm_provider
        from litellm.utils import get_optional_params

        resolved, provider, *_ = get_llm_provider(model=model)
        get_optional_params(
            model=resolved,
            custom_llm_provider=provider,
            tools=_PROBE_TOOLS,
            reasoning_effort=effort,
        )
        ok = True
    except Exception as exc:  # unsupported param, unmapped effort, unknown model
        logger.debug("reasoning_effort=%r not applicable to %s (%s)", effort, model, exc)

    _ACCEPTS[key] = ok
    return ok


def _completion(*args, **kwargs):
    effort = os.environ.get("LEGION_REASONING_EFFORT")
    if effort and "reasoning_effort" not in kwargs:
        model = kwargs.get("model") or (args[0] if args else "")
        if model and _accepts_effort(model, effort):
            kwargs["reasoning_effort"] = effort
    return _ORIGINAL_COMPLETION(*args, **kwargs)


_completion._legion_patched = True


def install() -> None:
    """Patch litellm.completion once. Safe to call repeatedly."""
    if getattr(litellm.completion, "_legion_patched", False):
        return
    litellm.completion = _completion
