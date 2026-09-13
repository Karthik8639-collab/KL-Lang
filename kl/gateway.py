"""
KL Fast JSON/REST Transcoder Gateway v10.5
Converts REST JSON HTTP payloads into 8-byte aligned .klb VTable binary frames with SHA-256 seals,
and decodes binary frames back to JSON payloads for legacy API interop.
"""
import json
from typing import Dict, Any, Tuple
try:
    from .engine import KLCodec, KLDecimal, KLActionRunner, KLGuardError
    from .agent_bridge import KLAgentBridge
except ImportError:
    from engine import KLCodec, KLDecimal, KLActionRunner, KLGuardError
    from agent_bridge import KLAgentBridge


class KLGateway:
    @classmethod
    def json_to_klb(cls, schema_name: str, json_data: dict, schema_meta: list) -> bytes:
        """Transcodes a REST JSON dictionary directly into an 8-byte aligned .klb binary frame."""
        typed_payload = {}
        for f in schema_meta:
            fname = f["name"]
            ftype = f["type"]
            val = json_data.get(fname)

            if val is None:
                typed_payload[fname] = None
            elif ftype in ("Decimal", "decimal"):
                typed_payload[fname] = KLDecimal(str(val))
            elif ftype in ("Int", "int"):
                typed_payload[fname] = int(val)
            elif ftype in ("Float", "float"):
                typed_payload[fname] = float(val)
            elif ftype in ("Bool", "bool"):
                typed_payload[fname] = bool(val)
            else:
                typed_payload[fname] = str(val)

        return KLCodec.serialize_frame(schema_name, typed_payload, schema_meta)

    @classmethod
    def klb_to_json(cls, klb_bytes: bytes, schema_meta: list) -> dict:
        """Decodes an 8-byte aligned .klb binary frame into a JSON dictionary."""
        result = {}
        for f in schema_meta:
            tag = f["tag"]
            fname = f["name"]
            ftype = f["type"]
            val = KLCodec.read_field_by_tag(klb_bytes, tag, ftype)
            if isinstance(val, KLDecimal):
                result[fname] = str(val)
            else:
                result[fname] = val
        return result

    @classmethod
    def process_json_action(cls, parsed_ast: dict, json_payload: dict) -> Tuple[bytes, dict]:
        """
        Processes a REST JSON request end-to-end:
        1. Transcodes JSON -> .klb binary frame with SHA-256 seal.
        2. Decodes binary frame into typed scalars.
        3. Executes sandboxed GUARD rules and ACTION logic.
        4. Returns (klb_binary_bytes, json_response_dict).
        """
        schema_name = parsed_ast["schema_name"]
        schema_meta = parsed_ast["schema_meta"]

        klb_frame = cls.json_to_klb(schema_name, json_payload, schema_meta)
        decoded_json = cls.klb_to_json(klb_frame, schema_meta)
        exec_res = KLAgentBridge.execute_tool_call(parsed_ast, decoded_json)

        return klb_frame, exec_res
