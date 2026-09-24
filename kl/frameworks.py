"""
KL Framework Adapters v10.5
One-line drop-in adapters for LangChain, OpenAI Function Calling, and Anthropic MCP AI Agents.
"""
from typing import Any, Callable, Dict
try:
    from .engine import KLCompiler, KLDecimal, KLGuardError
    from .agent_bridge import KLAgentBridge
    from .gateway import KLGateway
except ImportError:
    from engine import KLCompiler, KLDecimal, KLGuardError
    from agent_bridge import KLAgentBridge
    from gateway import KLGateway


class KLLangChainTool:
    """Drop-in LangChain Tool wrapper that enforces KL sandboxed GUARD rules and Decimal precision."""
    def __init__(self, kl_source: str, handler_fn: Callable = None):
        self.parsed_ast = KLCompiler.parse_kl_source(kl_source)
        self.schema_name = self.parsed_ast["schema_name"]
        self.action_name = self.parsed_ast.get("action_name", f"Execute{self.schema_name}")
        self.handler_fn = handler_fn
        self.openai_schema = KLAgentBridge.export_openai_function_schema(self.parsed_ast)

    @property
    def name(self) -> str:
        return self.action_name

    @property
    def description(self) -> str:
        return f"Sandboxed KL Protocol Tool for {self.schema_name}"

    @property
    def args_schema(self) -> dict:
        return self.openai_schema["function"]["parameters"]

    def run(self, **kwargs) -> dict:
        """Executes tool arguments through KL AST Sandbox & GUARD validation."""
        tool_res = KLAgentBridge.execute_tool_call(self.parsed_ast, kwargs)
        if tool_res["status"] == "SUCCESS" and self.handler_fn:
            tool_res["result"] = self.handler_fn(tool_res["result"])
        return tool_res


class KLOpenAIAdapter:
    """Drop-in OpenAI Client tool caller with automatic KL GUARD interception."""
    def __init__(self, kl_source: str):
        self.parsed_ast = KLCompiler.parse_kl_source(kl_source)

    def get_tool_definition(self) -> dict:
        """Returns valid OpenAI ChatCompletions tools parameter dict."""
        return KLAgentBridge.export_openai_function_schema(self.parsed_ast)

    def handle_tool_call(self, tool_call_arguments_json: str) -> dict:
        """Parses OpenAI tool arguments string and executes inside KL sandbox."""
        import json
        if isinstance(tool_call_arguments_json, str):
            args = json.loads(tool_call_arguments_json)
        else:
            args = tool_call_arguments_json
        return KLAgentBridge.execute_tool_call(self.parsed_ast, args)
