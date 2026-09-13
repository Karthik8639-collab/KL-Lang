"""
KL AI Agent & Model Context Protocol (MCP) Adapter v10.5
Exports KL schemas to OpenAI Function Calling and Anthropic MCP Tool Definitions,
and executes AI tool calls safely via the Anti-DoS Capability Sandbox.
"""
import json
import copy
from typing import Dict, Any
try:
    from .engine import KLCodec, KLCompiler, KLActionRunner, KLDecimal, KLGuardError
except ImportError:
    from engine import KLCodec, KLCompiler, KLActionRunner, KLDecimal, KLGuardError


class KLAgentBridge:
    @classmethod
    def _map_json_type(cls, kl_type: str) -> dict:
        t = kl_type.strip()
        if t.startswith("Optional<") and t.endswith(">"):
            return cls._map_json_type(t[9:-1])
        if t.startswith("List<") and t.endswith(">"):
            return {
                "type": "array",
                "items": cls._map_json_type(t[5:-1])
            }
        if t.startswith("Map<") and t.endswith(">"):
            return {
                "type": "object",
                "additionalProperties": True
            }
        if t in ("String", "str"):
            return {"type": "string"}
        if t in ("Int", "int"):
            return {"type": "integer"}
        if t in ("Float", "float"):
            return {"type": "number"}
        if t in ("Bool", "bool"):
            return {"type": "boolean"}
        if t in ("Decimal", "decimal"):
            return {
                "type": "string",
                "description": "Fixed-point numeric decimal value (e.g. '100.00d')"
            }
        return {"type": "string"}

    @classmethod
    def export_openai_function_schema(cls, parsed_ast: dict) -> dict:
        """Exports a KL action schema as an OpenAI Function Calling tool object."""
        action = parsed_ast.get("action")
        s_name = parsed_ast.get("schema_name", "ToolAction")
        a_name = action.get("name", f"Execute{s_name}") if action else f"Execute{s_name}"
        schema_meta = parsed_ast.get("schema_meta", [])

        properties = {}
        required = []

        for field in schema_meta:
            fname = field["name"]
            ftype = field["type"]
            tag = field["tag"]
            properties[fname] = cls._map_json_type(ftype)
            properties[fname]["description"] = f"Field tag @{tag}"
            if not ftype.startswith("Optional"):
                required.append(fname)

        return {
            "type": "function",
            "function": {
                "name": a_name,
                "description": f"Sandboxed KL Protocol Tool: {s_name}",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        }

    @classmethod
    def export_mcp_tool_definition(cls, parsed_ast: dict) -> dict:
        """Exports a KL action schema as an Anthropic Model Context Protocol (MCP) tool object."""
        openai_fmt = cls.export_openai_function_schema(parsed_ast)
        func = openai_fmt["function"]

        return {
            "name": func["name"],
            "description": func["description"],
            "inputSchema": func["parameters"]
        }

    @classmethod
    def execute_tool_call(cls, parsed_ast: dict, raw_json_args: dict) -> dict:
        """
        Receives raw JSON arguments from an LLM tool call, converts types to KL native scalars,
        evaluates sandboxed GUARD boundary conditions, and returns structured result.
        """
        schema_meta = parsed_ast.get("schema_meta", [])
        payload = {}

        for field in schema_meta:
            fname = field["name"]
            ftype = field["type"]
            val = raw_json_args.get(fname)

            if val is None:
                if ftype.startswith("Optional"):
                    payload[fname] = None
                else:
                    payload[fname] = None
            elif ftype in ("Decimal", "decimal"):
                payload[fname] = KLDecimal(str(val))
            elif ftype in ("Int", "int"):
                payload[fname] = int(val)
            elif ftype in ("Float", "float"):
                payload[fname] = float(val)
            elif ftype in ("Bool", "bool"):
                payload[fname] = bool(val)
            else:
                payload[fname] = str(val)

        try:
            res = KLActionRunner.execute_action(parsed_ast, payload)
            if isinstance(res, KLDecimal):
                res_out = str(res)
            elif isinstance(res, dict):
                res_out = {k: str(v) if isinstance(v, KLDecimal) else v for k, v in res.items()}
            else:
                res_out = res

            return {
                "status": "SUCCESS",
                "schema": parsed_ast.get("schema_name"),
                "result": res_out
            }
        except KLGuardError as ge:
            return {
                "status": "GUARD_VIOLATION",
                "error_code": ge.error_code,
                "message": ge.message
            }
        except Exception as e:
            return {
                "status": "EXECUTION_ERROR",
                "error_code": "InternalRuntimeFault",
                "message": str(e)
            }
