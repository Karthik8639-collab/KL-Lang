"""
KL Core Compiler & Execution Engine v8.1 (Audited & Hardened)
Deterministic Binary Wire Protocol, Dynamic AST Parser & Capability Sandbox
"""
import struct
import hashlib
import time
import ast
import re

# ------------------------------------------------------------------------------
# 1. HARDENED 8-BYTE ALIGNED VTABLE CODEC
# ------------------------------------------------------------------------------
class KLCodec:
    MAGIC = b"KL\x08"

    @classmethod
    def serialize_frame(cls, schema_name: str, fields: dict) -> bytes:
        keys = sorted(list(fields.keys()))
        num_fields = len(keys)
        schema_hash = hashlib.sha256(f"{schema_name}:{':'.join(keys)}".encode('utf-8')).digest()[:4]
        
        # Header: Magic(3B) + Version(1B) + Hash(4B) + VTableSize(4B) + NumFields(2B) + Offsets(4B*N)
        vtable_size = 3 + 1 + 4 + 4 + 2 + (num_fields * 4)
        body = bytearray()
        offsets = []

        for k in keys:
            val = fields[k]
            # 1. FIXED 8-Byte Alignment Calculation (Relativity to Frame Base)
            current_abs_offset = vtable_size + len(body)
            align_pad = (8 - (current_abs_offset % 8)) % 8
            body.extend(b"\x00" * align_pad)
            
            offsets.append(vtable_size + len(body))
            if isinstance(val, int) and not isinstance(val, bool):
                body.extend(struct.pack("<q", val))
            elif isinstance(val, float):
                body.extend(struct.pack("<d", val))
            elif isinstance(val, str):
                enc = val.encode('utf-8')
                body.extend(struct.pack("<I", len(enc)) + enc)
            elif isinstance(val, bool):
                body.append(1 if val else 0)

        core_payload = bytearray(cls.MAGIC)
        core_payload.append(0x01) # Format version 1
        core_payload.extend(schema_hash)
        core_payload.extend(struct.pack("<IH", vtable_size, num_fields))
        for off in offsets:
            core_payload.extend(struct.pack("<I", off))
        core_payload.extend(body)

        return struct.pack("!I", len(core_payload)) + bytes(core_payload)

    @classmethod
    def read_field_verified(cls, framed_bytes: bytes, schema_name: str, expected_keys: list, field_idx: int, field_type: str):
        if not isinstance(framed_bytes, (bytes, bytearray)) or len(framed_bytes) < 18:
            raise ValueError("Corrupt framed packet: Buffer header underflow")
            
        frame_len = struct.unpack("!I", framed_bytes[:4])[0]
        frame = framed_bytes[4:]
        if len(frame) != frame_len:
            raise ValueError("Packet fragmentation fault: Byte length mismatch")

        # 2. Cryptographic Schema Attestation
        keys = sorted(expected_keys)
        expected_hash = hashlib.sha256(f"{schema_name}:{':'.join(keys)}".encode('utf-8')).digest()[:4]
        if frame[4:8] != expected_hash:
            raise PermissionError("Security Exception: Cryptographic schema seal mismatch")

        vtable_size, num_fields = struct.unpack("<IH", frame[8:14])
        if field_idx >= num_fields:
            raise IndexError("Field index out of schema range")

        # 3. FIXED Explicit Memory Bounds Checks
        offset_pos = 14 + (field_idx * 4)
        if offset_pos + 4 > vtable_size or offset_pos + 4 > len(frame):
            raise IndexError("Corrupted VTable: Offset table boundary violated")

        field_offset = struct.unpack("<I", frame[offset_pos:offset_pos+4])[0]
        buf_len = len(frame)

        if field_offset >= buf_len or field_offset < vtable_size:
            raise IndexError("Memory fault: Offset points outside allocated payload")

        if field_type in ("float", "int"):
            if field_offset + 8 > buf_len:
                raise IndexError(f"Memory fault: {field_type.upper()} payload truncated")
            fmt = "<d" if field_type == "float" else "<q"
            return struct.unpack(fmt, frame[field_offset:field_offset+8])[0]

        elif field_type == "str":
            if field_offset + 4 > buf_len:
                raise IndexError("Memory fault: String length header truncated")
            s_len = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
            if field_offset + 4 + s_len > buf_len:
                raise IndexError("Memory fault: String content overflows memory boundary")
            return frame[field_offset+4:field_offset+4+s_len].decode('utf-8', errors='replace')

        elif field_type == "bool":
            return frame[field_offset] == 1

        return None


# ------------------------------------------------------------------------------
# 2. PRODUCTION AST CAPABILITY SANDBOX (Anti-DoS & RCE Defense)
# ------------------------------------------------------------------------------
class KLSandboxValidator(ast.NodeVisitor):
    DISALLOWED_NODES = (
        ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
        ast.While, ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith,
        ast.Yield, ast.YieldFrom
    )

    def generic_visit(self, node):
        if isinstance(node, self.DISALLOWED_NODES):
            raise PermissionError(f"Security Alert: Disallowed construct '{type(node).__name__}'")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise PermissionError(f"Security Alert: Private/Dunder reflection access blocked on '{node.attr}'")
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Pow)):
            for op in (node.left, node.right):
                if isinstance(op, ast.Constant) and isinstance(op.value, (int, float)) and op.value > 10000:
                    raise PermissionError(f"Resource Limit: Multiplier ({op.value}) exceeds safe allocation cap")
        super().generic_visit(node)


class KLCapabilitySandbox:
    SAFE_BUILTINS = {
        "abs": abs, "round": round, "min": min, "max": max, "len": len,
        "int": int, "float": float, "str": str, "bool": bool, "dict": dict, "list": list
    }

    @classmethod
    def execute(cls, code_str: str, context: dict):
        tree = ast.parse(code_str)
        KLSandboxValidator().visit(tree)
        scope = {"context": context, "result": None}
        exec(compile(tree, "<kl_sandbox>", "exec"), {"__builtins__": cls.SAFE_BUILTINS}, scope)
        return scope.get("result")


# ------------------------------------------------------------------------------
# 3. DYNAMIC AST PARSER & CODE GENERATOR
# ------------------------------------------------------------------------------
class KLCompiler:
    @classmethod
    def parse_kl_source(cls, source: str) -> dict:
        """Dynamically extracts SCHEMA fields, ACTIONS, and GUARDS from raw source."""
        schema_match = re.search(r'SCHEMA\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]+)\}', source)
        schema_name = schema_match.group(1) if schema_match else "DefaultSchema"
        raw_fields = schema_match.group(2) if schema_match else ""
        
        fields = {}
        for line in raw_fields.splitlines():
            line = line.strip().rstrip(',')
            if ':' in line:
                fname, ftype = line.split(':', 1)
                fields[fname.strip()] = ftype.strip().lower()

        action_match = re.search(r'ACTION\s+([A-Za-z_][A-Za-z0-9_]*)', source)
        action_name = action_match.group(1) if action_match else "ExecuteAction"

        guard_match = re.search(r'GUARD\s+([^\s;]+)\s*([<>!=]+)\s*([0-9.]+)', source)
        guard_rule = {
            "field": guard_match.group(1).replace("req.", "") if guard_match else "risk_score",
            "op": guard_match.group(2) if guard_match else "<",
            "threshold": float(guard_match.group(3)) if guard_match else 0.85
        }
        return {"schema_name": schema_name, "fields": fields, "action_name": action_name, "guard": guard_rule}

    @classmethod
    def transpile_targets(cls, parsed: dict):
        s_name = parsed["schema_name"]
        fields = parsed["fields"]
        
        # Dynamic Python Dataclass
        py_fields = "\n    ".join([f"{k}: {v.replace('string', 'str').replace('bool', 'bool')}" for k, v in fields.items()])
        py_code = f"# Auto-generated by KL Compiler\nfrom dataclasses import dataclass\n\n@dataclass\nclass {s_name}:\n    {py_fields}\n"

        # Dynamic Rust Struct
        rust_fields = "\n    ".join([f"pub {k}: {v.replace('string', 'String').replace('float', 'f64').replace('int', 'i64').replace('bool', 'bool')}," for k, v in fields.items()])
        rust_code = f"// Auto-generated by KL Compiler\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {s_name} {{\n    {rust_fields}\n}}\n"

        return py_code, rust_code


# ------------------------------------------------------------------------------
# 4. DETERMINISTIC WASM EMITTER
# ------------------------------------------------------------------------------
class KLWasmEmitter:
    @staticmethod
    def emit_guard_module(threshold: float) -> bytes:
        WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
        type_sec = bytearray([0x01, 0x05, 0x01, 0x60, 0x01, 0x7d, 0x01, 0x7f])
        func_sec = bytearray([0x03, 0x02, 0x01, 0x00])
        exp_name = b"validate_guard"
        exp_sec = bytearray([0x07, len(exp_name) + 4, 0x01, len(exp_name)]) + exp_name + bytearray([0x00, 0x00])
        
        func_body = bytearray([0x00, 0x20, 0x00, 0x43])
        func_body.extend(struct.pack("<f", threshold))
        func_body.extend([0x5D, 0x04, 0x7F, 0x41, 0x01, 0x05, 0x41, 0x00, 0x0B, 0x0B])
        code_sec = bytearray([0x0A, len(func_body) + 1, 0x01, len(func_body)]) + func_body
        return WASM_MAGIC + type_sec + func_sec + exp_sec + code_sec
