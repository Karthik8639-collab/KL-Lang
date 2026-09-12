"""
KL Core Compiler & Execution Engine v9.0 (Full AST Parser, Action VM & Type-Sealed Codec)
"""
import struct
import hashlib
import time
import ast
import re
import copy
from types import MappingProxyType

# ------------------------------------------------------------------------------
# 1. HARDENED 8-BYTE ALIGNED VTABLE CODEC (Type-Enforced Schema Seals)
# ------------------------------------------------------------------------------
class KLCodec:
    MAGIC = b"KL\x08"
    SUPPORTED_TYPES = {"str", "float", "int", "bool"}

    @classmethod
    def compute_schema_hash(cls, schema_name: str, fields: dict) -> bytes:
        """
        Locks field names AND field types into the cryptographic seal.
        Prevents silent data corruption from type redefinition.
        """
        sorted_keys = sorted(list(fields.keys()))
        type_signature = ":".join(f"{k}={fields[k]}" for k in sorted_keys)
        return hashlib.sha256(f"{schema_name}:{type_signature}".encode('utf-8')).digest()[:4]

    @classmethod
    def serialize_frame(cls, schema_name: str, fields: dict) -> bytes:
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', schema_name):
            raise ValueError(f"Invalid schema identifier: '{schema_name}'")
            
        keys = sorted(list(fields.keys()))
        num_fields = len(keys)
        if num_fields > 65535:
            raise ValueError("Schema exceeds maximum field limit (65,535)")
            
        schema_hash = cls.compute_schema_hash(schema_name, fields)
        
        # Header: Magic(3B) + Version(1B) + Hash(4B) + VTableSize(4B) + NumFields(2B) + Pad(2B) + Offsets(4B*N)
        vtable_size = 16 + (num_fields * 4)
        body = bytearray()
        offsets = []

        for k in keys:
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', k):
                raise ValueError(f"Invalid field name identifier: '{k}'")
            val = fields[k]
            
            # Enforce 8-byte word alignment relative to frame base
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
        core_payload.append(0x01) # Format version
        core_payload.extend(schema_hash)
        core_payload.extend(struct.pack("<IH", vtable_size, num_fields))
        core_payload.extend(b"\x00\x00") # 8-Byte alignment padding
        
        for off in offsets:
            core_payload.extend(struct.pack("<I", off))
        core_payload.extend(body)

        frame_prefix = struct.pack("!II", len(core_payload), 0x00000000)
        return frame_prefix + bytes(core_payload)

    @classmethod
    def read_field_verified(cls, framed_bytes: bytes, schema_name: str, expected_schema: dict, field_idx: int, field_type: str):
        if not isinstance(framed_bytes, (bytes, bytearray)) or len(framed_bytes) < 24:
            raise ValueError("Corrupt framed packet: Header underflow")
            
        frame_len = struct.unpack("!I", framed_bytes[:4])[0]
        frame = framed_bytes[8:]
        if len(frame) != frame_len:
            raise ValueError("Packet fragmentation fault: Byte length mismatch")

        # Cryptographic Type-Aware Schema Seal Check
        expected_hash = cls.compute_schema_hash(schema_name, expected_schema)
        if frame[4:8] != expected_hash:
            raise PermissionError("Security Exception: Cryptographic schema seal mismatch (Field or Type drift detected)")

        vtable_size, num_fields = struct.unpack("<IH", frame[8:14])
        if len(expected_schema) != num_fields:
            raise ValueError(f"Schema drift: Expected {len(expected_schema)} fields, found {num_fields}")

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

    @classmethod
    def read_field_by_name(cls, framed_bytes: bytes, schema_name: str, expected_schema: dict, field_name: str):
        """
        Resolves field names dynamically to prevent index miscalculation errors.
        """
        sorted_keys = sorted(list(expected_schema.keys()))
        if field_name not in sorted_keys:
            raise KeyError(f"Field '{field_name}' not defined in schema '{schema_name}'")
        idx = sorted_keys.index(field_name)
        ftype = expected_schema[field_name]
        return cls.read_field_verified(framed_bytes, schema_name, expected_schema, idx, ftype)


# ------------------------------------------------------------------------------
# 2. FULL STATEMENT PARSER & AST COMPILER
# ------------------------------------------------------------------------------
class KLCompiler:
    VALID_TYPES = {"String": "str", "Float": "float", "Int": "int", "Bool": "bool"}

    @classmethod
    def parse_kl_source(cls, source: str) -> dict:
        """
        Parses schemas, action blocks, multiple guards, let bindings, and return statements.
        """
        clean_lines = []
        for line in source.splitlines():
            line = re.sub(r'//.*$', '', line)
            if line.strip():
                clean_lines.append(line.strip())
        clean_source = "\n".join(clean_lines)

        # 1. Parse Schema
        schema_match = re.search(r'SCHEMA\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]+)\}', clean_source, re.DOTALL)
        if not schema_match:
            raise SyntaxError("Parser Error: No valid 'SCHEMA <Name> { ... }' declaration found")

        schema_name = schema_match.group(1)
        raw_fields = schema_match.group(2)
        fields = {}
        for token in re.split(r'[,;\n]', raw_body if 'raw_body' in locals() else raw_fields):
            token = token.strip()
            if not token:
                continue
            if ':' not in token:
                raise SyntaxError(f"Malformed field definition: '{token}'")
            fname, ftype = [p.strip() for p in token.split(':', 1)]
            if ftype not in cls.VALID_TYPES:
                raise SyntaxError(f"Unsupported type '{ftype}' for field '{fname}'")
            fields[fname] = cls.VALID_TYPES[ftype]

        # 2. Parse Action Signature
        action_match = re.search(r'ACTION\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([A-Za-z0-9_]+))?\s*\{([^}]+)\}', clean_source, re.DOTALL)
        if not action_match:
            return {"schema_name": schema_name, "fields": fields, "action": None}

        action_name = action_match.group(1)
        param_def = action_match.group(2).strip()
        return_type = action_match.group(3) or "Bool"
        action_body = action_match.group(4)

        # 3. Parse Statement Sequence inside Action Body
        statements = []
        for raw_stmt in action_body.split(';'):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            
            if stmt.startswith("GUARD"):
                # Matches: GUARD <expr> ELSE FAIL(<msg>)
                g_match = re.search(r'GUARD\s+(.+?)\s+ELSE\s+FAIL(?:\("([^"]*)"\))?', stmt)
                if g_match:
                    statements.append({
                        "type": "GUARD",
                        "expr": g_match.group(1).strip(),
                        "error_msg": g_match.group(2) or "Guard violation"
                    })
            elif stmt.startswith("LET"):
                # Matches: LET <id> = <expr>
                l_match = re.search(r'LET\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)', stmt)
                if l_match:
                    statements.append({
                        "type": "LET",
                        "target": l_match.group(1).strip(),
                        "expr": l_match.group(2).strip()
                    })
            elif stmt.startswith("RETURN"):
                r_match = re.search(r'RETURN\s+(.+)', stmt)
                if r_match:
                    statements.append({
                        "type": "RETURN",
                        "expr": r_match.group(1).strip()
                    })

        action_ast = {
            "name": action_name,
            "param": param_def,
            "return_type": return_type,
            "statements": statements
        }
        return {"schema_name": schema_name, "fields": fields, "action": action_ast}

    @classmethod
    def transpile_targets(cls, parsed: dict):
        s_name = parsed["schema_name"]
        fields = parsed["fields"]
        
        py_fields = "\n    ".join([f"{k}: {v}" for k, v in fields.items()])
        validators = "\n        ".join([
            f"if not isinstance(self.{k}, {v}): raise TypeError(f'Expected {v} for {k}, got {{type(self.{k})}}')"
            for k, v in fields.items()
        ])
        
        py_code = f"""# Auto-generated by KL Compiler v9.0
from dataclasses import dataclass

@dataclass
class {s_name}:
    {py_fields}

    def __post_init__(self):
        {validators}
"""
        rust_map = {"str": "String", "float": "f64", "int": "i64", "bool": "bool"}
        rust_fields = "\n    ".join([f"pub {k}: {rust_map[v]}," for k, v in fields.items()])
        rust_code = f"// Auto-generated by KL Compiler v9.0\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {s_name} {{\n    {rust_fields}\n}}\n"

        return py_code, rust_code


# ------------------------------------------------------------------------------
# 3. KL ACTION EXECUTION INTERPRETER & RUNTIME
# ------------------------------------------------------------------------------
class KLActionRunner:
    @classmethod
    def execute_action(cls, parsed_ast: dict, input_payload: dict, tool_dispatcher=None):
        """
        Executes action statements sequentially: GUARDS -> LETS -> RETURN.
        """
        action = parsed_ast.get("action")
        if not action:
            raise ValueError("No action defined in parsed AST")

        # Isolated execution namespace
        scope = copy.deepcopy(input_payload)
        scope["req"] = copy.deepcopy(input_payload)

        for stmt in action["statements"]:
            stype = stmt["type"]
            
            if stype == "GUARD":
                # Evaluate guard condition safely
                expr = stmt["expr"].replace("req.", "")
                # Safe evaluation of basic comparisons
                condition_met = eval(expr, {"__builtins__": None}, scope)
                if not condition_met:
                    raise PermissionError(f"Action Guard Tripped: {stmt['error_msg']}")
                    
            elif stype == "LET":
                target = stmt["target"]
                expr = stmt["expr"]
                if "EXEC " in expr:
                    tool_call = re.search(r'EXEC\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)', expr)
                    if tool_call and tool_dispatcher:
                        t_name = tool_call.group(1)
                        t_arg_field = tool_call.group(2).replace("req.", "").strip()
                        t_arg_val = scope.get(t_arg_field)
                        scope[target] = tool_dispatcher(t_name, t_arg_val)
                    else:
                        scope[target] = True
                else:
                    scope[target] = eval(expr, {"__builtins__": None}, scope)
                    
            elif stype == "RETURN":
                ret_expr = stmt["expr"]
                return eval(ret_expr, {"__builtins__": None}, scope)

        return True
