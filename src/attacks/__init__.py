"""
Attack scenario generation for security investigation benchmarks.

This package provides tools for generating realistic attack event chains
to test AI agents' investigation capabilities.

Usage:
    from attacks import (
        # Data classes
        AttackScenario,
        AttackEvent,
        AttackInstance,

        # Scenario registry
        ATTACK_SCENARIOS,

        # Generation functions
        generate_attack,
        generate_attacks,
        generate_multi_victim_attack,

        # Ground truth retrieval
        get_attack_ground_truth,
        get_attack_by_id,
        get_attacks_for_victim,
        clear_attack_ground_truth,

        # Utilities
        resolve_attack_parameters,
        render_template,
        get_scenario_iocs,
    )
"""
from .scenarios import (
    AttackScenario,
    AttackEvent,
    AttackInstance,
    ATTACK_SCENARIOS,
    resolve_attack_parameters,
    render_template,
    get_scenario_iocs,
)
from .engine import (
    generate_attack,
    generate_attacks,
    generate_multi_victim_attack,
    get_attack_ground_truth,
    get_attack_by_id,
    get_attacks_for_victim,
    clear_attack_ground_truth,
)
from .ticket_generator import generate_tickets, save_tickets

__all__ = [
    # Data classes
    "AttackScenario",
    "AttackEvent",
    "AttackInstance",
    # Scenario registry
    "ATTACK_SCENARIOS",
    # Generation functions
    "generate_attack",
    "generate_attacks",
    "generate_multi_victim_attack",
    # Ground truth retrieval
    "get_attack_ground_truth",
    "get_attack_by_id",
    "get_attacks_for_victim",
    "clear_attack_ground_truth",
    # Utilities
    "resolve_attack_parameters",
    "render_template",
    "get_scenario_iocs",
    # Ticket generation
    "generate_tickets",
    "save_tickets",
]
