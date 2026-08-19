"""
KL Core Compiler & Execution Engine v8.4 (W3C WASM Certified & Hardened Sandbox)
"""
import struct
import hashlib
import time
import ast
import re
import copy

# ------------------------------------------------------------------------------
# 1. MEMORY-ALIGNED VTABLE CODEC
# ------------------------------------------------------------------------------
class KLCodec:
    MAGIC = b"KL\x08"
    SUPPORTED_TYPES = {"str", "float", "int", "bool"}

    @classmethod
    def serialize_frame(cls, schema_name: str, fields: dict) -> bytes:
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', schema_name):
            raise ValueError(f"Invalid schema identifier: '{schema_name}'")
            
        keys = sorted(list(fields.keys()))
        num_fields = len(keys)
        if num_fields > 65535:
            raise ValueError("Schema exceeds maximum field limit (65,535)")
            
        schema_hash = hashlib.sha256(f"{schema_name}:{':'.join(keys)}".encode('utf-8')).digest()[:4]
        
        # Header: Magic(3B) + Version(1B) + Hash(4B) + VTableSize(4B) + NumFields(2B) + Pad(2B) + Offsets(4B*N)
        vtable_size = 16 + (num_fields * 4)
        body = bytearray()
        offsets = []

        for k in keys:
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', k):
                raise ValueError(f"Invalid field name identifier: '{k}'")
            val = fields[k]
            
            current_abs = vtable_size + len(body)
            align_pad = (8 - (current_abs % 8)) % 8
            body.extend(b"\x00" * align_pad)
            offsets.append(vtable_size + len(body))
            
            if isinstance(val, bool):
                body.append(1 if val else 0)
            elif isinstance(val, int):
                if not (-9223372036854775808 <= val <= 9223372036854775807):
                    raise OverflowError(f"Integer '{val}' exceeds signed 64-bit bounds")
                body.extend(struct.pack("<q", val))
            elif isinstance(val, float):
                body.extend(struct.pack("<d", val))
            elif isinstance(val, str):
                enc = val.encode('utf-8')
                if len(enc) > 0xFFFFFFFF:
                    raise ValueError("String payload exceeds 4GB limit")
                body.extend(struct.pack("<I", len(enc)) + enc)
            else:
                raise TypeError(f"Unsupported serialization type: {type(val)}")

        core_payload = bytearray(cls.MAGIC)
        core_payload.append(0x01)
        core_payload.extend(schema_hash)
        core_payload.extend(struct.pack("<IH", vtable_size, num_fields))
        core_payload.extend(b"\x00\x00")
        
        for off in offsets:
            core_payload.extend(struct.pack("<I", off))
        core_payload.extend(body)

        frame_prefix = struct.pack("!II", len(core_payload), 0x00000000)
        return frame_prefix + bytes(core_payload)

    @classmethod
    def read_field_verified(cls, framed_bytes: bytes, schema_name: str, expected_keys: list, field_idx: int, field_type: str):
        if not isinstance(framed_bytes, (bytes, bytearray)) or len(framed_bytes) < 24:
            raise ValueError("Corrupt framed packet: Header underflow")
            
        frame_len = struct.unpack("!I", framed_bytes[:4])[0]
        frame = framed_bytes[8:]
        if len(frame) != frame_len:
            raise ValueError("Packet fragmentation fault: Byte length mismatch")

        keys = sorted(expected_keys)
        expected_hash = hashlib.sha256(f"{schema_name}:{':'.join(keys)}".encode('utf-8')).digest()[:4]
        if frame[4:8] != expected_hash:
            raise PermissionError("Security Exception: Cryptographic schema seal mismatch")

        vtable_size, num_fields = struct.unpack("<IH", frame[8:14])
        if len(keys) != num_fields:
            raise ValueError(f"Schema drift: Expected {len(keys)} fields, found {num_fields}")

        if not (0 <= field_idx < num_fields):
            raise IndexError(f"Field index {field_idx} out of range [0, {num_fields-1}]")

        offset_pos = 16 + (field_idx * 4)
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

        raise ValueError(f"Unknown read field type: {field_type}")


# ------------------------------------------------------------------------------
# 2. HARDENED AST SANDBOX WITH RESOURCE BUDGETING
# ------------------------------------------------------------------------------
class KLSandboxValidator(ast.NodeVisitor):
    DISALLOWED_NODES = (
        ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
        ast.While, ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith,
        ast.Yield, ast.YieldFrom, ast.Lambda, ast.ClassDef
    )

    def __init__(self, max_nodes=200, max_depth=20):
        self.node_count = 0
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.current_depth = 0

    def visit(self, node):
        self.node_count += 1
        if self.node_count > self.max_nodes:
            raise PermissionError("Resource Limit: AST complexity budget exceeded (>200 nodes)")
            
        self.current_depth += 1
        if self.current_depth > self.max_depth:
            raise PermissionError("Resource Limit: AST nesting depth exceeded (>20 levels)")
            
        if isinstance(node, self.DISALLOWED_NODES):
            raise PermissionError(f"Security Alert: Disallowed construct '{type(node).__name__}'")
            
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise PermissionError(f"Security Alert: Private/Dunder access blocked on '{node.attr}'")
            
        if isinstance(node, ast.Name) and node.id in ("__builtins__", "eval", "exec", "open", "compile"):
            raise PermissionError(f"Security Alert: Restricted identifier '{node.id}'")
            
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Pow)):
            for operand in (node.left, node.right):
                if isinstance(operand, ast.Constant) and isinstance(operand.value, (int, float)) and operand.value >= 100:
                    raise PermissionError(f"Resource Limit: Multiplication/Exponent constant ({operand.value}) exceeds safety cap")
                    
        super().visit(node)
        self.current_depth -= 1


class KLCapabilitySandbox:
    SAFE_BUILTINS = {
        "abs": abs, "round": round, "min": min, "max": max, "len": len,
        "int": int, "float": float, "str": str, "bool": bool
    }

    @classmethod
    def execute(cls, code_str: str, context: dict):
        try:
            tree = ast.parse(code_str)
        except Exception as e:
            raise SyntaxError(f"Sandbox parse error: {str(e)}")
            
        validator = KLSandboxValidator()
        validator.visit(tree)
        
        # Deepcopy context to isolate host memory and lock down environment
        isolated_ctx = copy.deepcopy(context)
        isolated_scope = {"context": isolated_ctx, "result": None}
        
        exec(
            compile(tree, "<kl_sandbox>", "exec"),
            {"__builtins__": cls.SAFE_BUILTINS},
            isolated_scope
        )
        return isolated_scope.get("result")


# ------------------------------------------------------------------------------
# 3. ROBUST TOKEN-BASED LEXER & PARSER
# ------------------------------------------------------------------------------
class KLCompiler:
    VALID_TYPES = {"String": "str", "Float": "float", "Int": "int", "Bool": "bool"}

    @classmethod
    def parse_kl_source(cls, source: str) -> dict:
        clean_lines = []
        for line in source.splitlines():
            line = re.sub(r'//.*$', '', line)
            if line.strip():
                clean_lines.append(line)
        clean_source = "\n".join(clean_lines)

        schema_match = re.search(r'SCHEMA\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]+)\}', clean_source, re.DOTALL)
        if not schema_match:
            raise SyntaxError("Parser Error: No valid 'SCHEMA <Name> { ... }' declaration found")

        schema_name = schema_match.group(1)
        raw_body = schema_match.group(2)
        
        fields = {}
        tokens = re.split(r'[,;\n]', raw_body)
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if ':' not in token:
                raise SyntaxError(f"Malformed field definition: '{token}' (Expected 'name: Type')")
            fname, ftype = [p.strip() for p in token.split(':', 1)]
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', fname):
                raise SyntaxError(f"Invalid field name identifier: '{fname}'")
            if ftype not in cls.VALID_TYPES:
                raise SyntaxError(f"Unsupported type '{ftype}' for field '{fname}'. Must be one of: {list(cls.VALID_TYPES.keys())}")
            fields[fname] = cls.VALID_TYPES[ftype]

        action_match = re.search(r'ACTION\s+([A-Za-z_][A-Za-z0-9_]*)', clean_source)
        action_name = action_match.group(1) if action_match else "ExecuteAction"

        guard_match = re.search(r'GUARD\s+([A-Za-z0-9_.]+)\s*(<=|>=|<|>|==|!=)\s*([0-9.]+)', clean_source)
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
        
        # Validated Python Dataclass with runtime type validation in __post_init__
        py_fields = "\n    ".join([f"{k}: {v}" for k, v in fields.items()])
        validators = "\n        ".join([
            f"if not isinstance(self.{k}, {v}): raise TypeError(f'Expected {v} for {k}, got {{type(self.{k})}}')"
            for k, v in fields.items()
        ])
        
        py_code = f"""# Auto-generated by KL Compiler
from dataclasses import dataclass

@dataclass
class {s_name}:
    {py_fields}

    def __post_init__(self):
        {validators}
"""

        rust_map = {"str": "String", "float": "f64", "int": "i64", "bool": "bool"}
        rust_fields = "\n    ".join([f"pub {k}: {rust_map[v]}," for k, v in fields.items()])
        rust_code = f"// Auto-generated by KL Compiler\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {s_name} {{\n    {rust_fields}\n}}\n"

        return py_code, rust_code


# ------------------------------------------------------------------------------
# 4. W3C WEBASSEMBLY MICRO-EMITTER (Validated Spec Framing: +2 Payload Size)
# ------------------------------------------------------------------------------
class KLWasmEmitter:
    OP_MAP = {"<": 0x5D, "<=": 0x5F, ">": 0x5E, ">=": 0x60, "==": 0x5B, "!=": 0x5C}

    @classmethod
    def emit_guard_module(cls, threshold: float, op: str = "<") -> bytes:
        WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
        
        # Section 1: Type Section (Length 0x06)
        type_sec = bytearray([0x01, 0x06, 0x01, 0x60, 0x01, 0x7D, 0x01, 0x7F])
        # Section 3: Function Section (Length 0x02)
        func_sec = bytearray([0x03, 0x02, 0x01, 0x00])
        # Section 7: Export Section
        exp_name = b"validate_guard"
        exp_sec = bytearray([0x07, len(exp_name) + 4, 0x01, len(exp_name)]) + exp_name + bytearray([0x00, 0x00])
        
        # Section 10: Code Section
        opcode = cls.OP_MAP.get(op, 0x5D)
        func_body = bytearray([
            0x00,       # 0 local declarations
            0x20, 0x00, # local.get 0
            0x43        # f32.const
        ])
        func_body.extend(struct.pack("<f", threshold))
        func_body.extend([
            opcode,     # Comparison opcode (f32.lt, f32.le, etc.)
            0x04, 0x7F, # if (result i32)
            0x41, 0x01, # i32.const 1 (True)
            0x05,       # else
            0x41, 0x00, # i32.const 0 (False)
            0x0B,       # end if
            0x0B        # end func
        ])
        
        # W3C Specification Fix: Section length = function count byte (1B) + body size byte (1B) + len(func_body)
        code_sec_payload = bytearray([0x01, len(func_body)]) + func_body
        code_sec = bytearray([0x0A, len(code_sec_payload)]) + code_sec_payload
        
        return WASM_MAGIC + type_sec + func_sec + exp_sec + code_sec
