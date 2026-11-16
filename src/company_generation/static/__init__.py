"""
Static company generation API re-exports (local src versions).

Note: The full company generator (CompanyConfig, generate_company) is now at
company_generation.company_generator. This module re-exports for backwards compatibility.
"""

# Delay import to avoid circular dependency
def __getattr__(name: str):
    if name == "CompanyConfig":
        from ..company_generator import CompanyConfig
        return CompanyConfig
    if name == "generate_company":
        from ..company_generator import generate_company
        return generate_company
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["CompanyConfig", "generate_company"]


