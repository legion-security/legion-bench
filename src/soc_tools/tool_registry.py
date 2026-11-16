"""Tool registry — loads YAML tool catalog, activates tools per scenario, dispatches queries."""

import importlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from soc_tools.ablation import NO_ABLATION, AblationConfig


_CATALOG_DIR = Path(__file__).resolve().parent / "catalog"

# Map capability module short names to their import paths
_CAPABILITY_MODULES = {
    "siem": "soc_tools.capabilities.siem",
    "edr": "soc_tools.capabilities.edr",
    "identity": "soc_tools.capabilities.identity",
    "email_gateway": "soc_tools.capabilities.email_gateway",
    "email_security": "soc_tools.capabilities.email_gateway",
    "dlp": "soc_tools.capabilities.dlp",
    "threat_intel": "soc_tools.capabilities.threat_intel",
    "cnapp": "soc_tools.capabilities.cnapp",
}

# Legacy tool ID → (category_id, platform_id) mapping for backward compatibility
_LEGACY_TOOL_MAP: Dict[str, tuple] = {
    "splunk_es": ("siem", "splunk"),
    "crowdstrike": ("edr", "crowdstrike"),
    "entra_id": ("identity", "entra_id"),
    "defender_o365": ("email_security", "defender_o365"),
    "purview": ("dlp", "purview"),
    "threat_intel": ("threat_intel", "virustotal"),
    "cnapp": ("cnapp", "wiz"),
}


class ToolRegistry:
    """Registry that loads tool YAML definitions, activates a subset per scenario,
    generates LLM function-calling schemas, and dispatches queries to capability functions.

    Usage (new format):
        registry = ToolRegistry("path/to/db.sqlite")
        registry.activate_platforms({"siem": "splunk", "identity": "entra_id"})
        tools = registry.get_llm_tools()
        result = registry.execute("splunk_run_query", {"query": "SELECT ..."})

    Usage (legacy format):
        registry = ToolRegistry("path/to/db.sqlite")
        registry.activate_tools(["splunk_es", "entra_id", "threat_intel"])
        tools = registry.get_llm_tools()
        result = registry.execute("splunk_run_query", {"query": "SELECT ..."})

    Usage (ablated arm):
        registry = ToolRegistry(db_path, ablation=ablation.resolve("no_analysis"))
        registry.activate_all()   # tier-1 tools absent from get_llm_tools()
    """

    def __init__(
        self,
        db_path: str,
        catalog_dir: Optional[str] = None,
        ablation: Optional[AblationConfig] = None,
    ):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._catalog_dir = Path(catalog_dir) if catalog_dir else _CATALOG_DIR
        self._ablation = ablation or NO_ABLATION

        # Category-based catalog: {category_id: parsed_yaml}
        self._categories: Dict[str, Dict[str, Any]] = {}
        # Active platforms: {category_id: platform_id}
        self._active_platforms: Dict[str, str] = {}
        # Dispatch map: {query_name: (capability_func, yaml_query_def)}
        self._dispatch: Dict[str, tuple] = {}
        # Resolved capability functions cache
        self._func_cache: Dict[str, Callable] = {}

        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load all YAML category definitions from catalog directory."""
        if not self._catalog_dir.exists():
            return
        for yaml_path in sorted(self._catalog_dir.glob("*.yaml")):
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
            if "category" in data:
                category_id = data["category"]["id"]
                self._categories[category_id] = data

    def _resolve_capability(self, capability_ref: str) -> Callable:
        """Resolve a capability reference like 'siem.search_logs' to a Python function."""
        if capability_ref in self._func_cache:
            return self._func_cache[capability_ref]

        module_name, func_name = capability_ref.rsplit(".", 1)
        import_path = _CAPABILITY_MODULES.get(module_name)
        if not import_path:
            raise ValueError(f"Unknown capability module: {module_name}")

        mod = importlib.import_module(import_path)
        func = getattr(mod, func_name)
        self._func_cache[capability_ref] = func
        return func

    def activate_platforms(self, platform_map: Dict[str, str]) -> None:
        """Activate platforms for the current scenario.

        A platform whose every function is removed by the active ablation is not
        registered as active — otherwise the scenario would advertise a platform
        with no callable queries.

        Args:
            platform_map: Dict mapping category_id to platform_id,
                          e.g. {"siem": "splunk", "edr": "crowdstrike"}.
        """
        self._active_platforms = {}
        self._dispatch = {}

        for category_id, platform_id in platform_map.items():
            if category_id not in self._categories:
                raise ValueError(
                    f"Unknown category: {category_id}. "
                    f"Available: {list(self._categories.keys())}"
                )

            cat_data = self._categories[category_id]
            platforms = cat_data.get("platforms", {})

            if platform_id not in platforms:
                raise ValueError(
                    f"Unknown platform '{platform_id}' for category '{category_id}'. "
                    f"Available: {list(platforms.keys())}"
                )

            platform_def = platforms[platform_id]
            prefix = platform_def["prefix"]
            all_functions = cat_data.get("functions", {})
            activated = 0

            for func_name in platform_def.get("functions", []):
                if func_name not in all_functions:
                    raise ValueError(
                        f"Function '{func_name}' listed in platform '{platform_id}' "
                        f"but not defined in category '{category_id}'"
                    )
                func_def = all_functions[func_name]
                capability_ref = func_def["capability"]

                # Ablated arms drop the capability before it reaches the schema,
                # so the agent never learns the tool existed.
                if not self._ablation.allows(capability_ref):
                    continue

                override = self._ablation.description_for(capability_ref)
                if override is not None:
                    func_def = {**func_def, "description": override}

                query_name = f"{prefix}_{func_name}"
                func = self._resolve_capability(capability_ref)
                self._dispatch[query_name] = (func, func_def)
                activated += 1

            if activated:
                self._active_platforms[category_id] = platform_id

    def activate_all(self) -> None:
        """Activate every platform in the catalog (one per category).

        For each category, the first platform listed is activated.
        This gives the agent access to all available SOC tools.
        """
        platform_map: Dict[str, str] = {}
        for category_id, cat_data in self._categories.items():
            platforms = cat_data.get("platforms", {})
            if platforms:
                # Pick the first platform in the category
                platform_map[category_id] = next(iter(platforms))
        self.activate_platforms(platform_map)

    def activate_tools(self, tool_ids: List[str]) -> None:
        """Activate tools by legacy tool IDs (backward compatibility).

        Translates legacy tool IDs to category/platform pairs and delegates
        to activate_platforms().

        Args:
            tool_ids: List of legacy tool IDs (e.g. ["splunk_es", "entra_id"]).
        """
        platform_map: Dict[str, str] = {}
        for tool_id in tool_ids:
            if tool_id not in _LEGACY_TOOL_MAP:
                raise ValueError(
                    f"Unknown legacy tool: {tool_id}. "
                    f"Known legacy tools: {list(_LEGACY_TOOL_MAP.keys())}"
                )
            category_id, platform_id = _LEGACY_TOOL_MAP[tool_id]
            platform_map[category_id] = platform_id
        self.activate_platforms(platform_map)

    def get_llm_tools(self) -> List[Dict[str, Any]]:
        """Generate OpenAI function-calling tool schemas for all active queries.

        Returns:
            List of tool definitions in OpenAI function-calling format.
        """
        tools = []
        for query_name, (_, query_def) in self._dispatch.items():
            properties = {}
            required = []

            for param_name, param_def in query_def.get("parameters", {}).items():
                prop: Dict[str, Any] = {
                    "description": param_def.get("description", ""),
                }

                param_type = param_def.get("type", "string")
                if param_type == "array":
                    prop["type"] = "array"
                    items = param_def.get("items", {})
                    prop["items"] = {"type": items.get("type", "string")}
                    if "enum" in items:
                        prop["items"]["enum"] = items["enum"]
                elif param_type == "object":
                    prop["type"] = "object"
                else:
                    prop["type"] = param_type

                if "enum" in param_def:
                    prop["enum"] = param_def["enum"]

                properties[param_name] = prop

                if param_def.get("required", False):
                    required.append(param_name)

            tool = {
                "type": "function",
                "function": {
                    "name": query_name,
                    "description": query_def.get("description", ""),
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                },
            }
            tools.append(tool)

        return tools

    def execute(self, function_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a query by function name.

        Args:
            function_name: The query name (e.g. "splunk_run_query").
            arguments: Query arguments as a dict.

        Returns:
            Query result (list or dict).

        Raises:
            ValueError: If function_name is not in the active dispatch map.
        """
        if function_name not in self._dispatch:
            available = list(self._dispatch.keys())
            raise ValueError(
                f"Unknown query: {function_name}. Available queries: {available}"
            )

        func, query_def = self._dispatch[function_name]
        args = arguments or {}
        result = func(self._conn, **args)
        return self._ablation.sanitize_result(query_def["capability"], result)

    @property
    def ablation(self) -> AblationConfig:
        """The ablation restricting this registry (NO_ABLATION if unrestricted)."""
        return self._ablation

    def get_active_tool_ids(self) -> List[str]:
        """Return the list of currently active platform IDs."""
        return list(self._active_platforms.values())

    def get_active_platforms(self) -> Dict[str, str]:
        """Return the active platform map {category_id: platform_id}."""
        return dict(self._active_platforms)

    def get_tool_info(self, platform_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific platform.

        Counts reflect the active ablation: capabilities it excludes are omitted.

        Args:
            platform_id: Platform ID to look up (e.g. "crowdstrike", "splunk").

        Returns:
            Tool metadata dict or None.
        """
        for cat_id, cat_data in self._categories.items():
            platforms = cat_data.get("platforms", {})
            if platform_id in platforms:
                plat = platforms[platform_id]
                prefix = plat["prefix"]
                all_functions = cat_data.get("functions", {})
                func_names = [
                    fn for fn in plat.get("functions", [])
                    if self._ablation.allows(
                        all_functions.get(fn, {}).get("capability", "")
                    )
                ]
                query_names = [f"{prefix}_{fn}" for fn in func_names]
                return {
                    "id": platform_id,
                    "name": plat["name"],
                    "vendor": plat.get("vendor"),
                    "category": cat_id,
                    "description": plat.get("description"),
                    "data_scope": cat_data.get("data_scope", []),
                    "query_count": len(func_names),
                    "queries": query_names,
                }
        return None

    def list_all_tools(self) -> List[Dict[str, Any]]:
        """List all platforms across all categories.

        Returns:
            List of tool info dicts.
        """
        result = []
        for cat_id, cat_data in self._categories.items():
            for plat_id in cat_data.get("platforms", {}):
                info = self.get_tool_info(plat_id)
                if info:
                    result.append(info)
        return result

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
