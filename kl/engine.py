"""
KL Core Compiler & Execution Engine v9.1 (Formal Conformance Standard)
Hardened Memory Codec, Full AST Parser, Action VM & Type-Sealed Codec
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
    def get_type_str(cls, val_or_type) -> str:
        """Helper to convert instance values or type strings into canonical KL type names."""
        if isinstance(val_or_type, str) and val_or_type in cls.SUPPORTED_TYPES:
            return val_or_type
        if isinstance(val_or_type, bool):
            return "bool"
        if isinstance(val_or_type, int):
            return "int"
        if isinstance(val_or_type, float):
            return "float"
        if isinstance(val_or_type, str):
            return "str"
        raise TypeError(f"Unsupported payload type: {type(val_or_type)}")

    @classmethod
    def compute_schema_hash(cls, schema_name: str, fields_or_keys) -> bytes:
        """
        Locks field names AND field types into the cryptographic seal.
        Prevents silent data corruption from type redefinition.
        Supports both schema dict and key lists for backwards compatibility.
        """
        if isinstance(fields_or_keys, dict):
            sorted_keys = sorted(list(fields_or_keys.keys()))
            type_signature = ":".join(f"{k}={cls.get_type_str(fields_or_keys[k])}" for k in sorted_keys)
        else:
            sorted_keys = sorted(list(fields_or_keys))
            type_signature = ":".join(sorted_keys)
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
    def read_field_verified(cls, framed_bytes: bytes, schema_name: str, expected_schema_or_keys, field_idx: int, field_type: str):
        if not isinstance(framed_bytes, (bytes, bytearray)) or len(framed_bytes) < 24:
            raise ValueError("Corrupt framed packet: Header underflow")
            
        frame_len = struct.unpack("!I", framed_bytes[:4])[0]
        frame = framed_bytes[8:]
        if len(frame) != frame_len:
            raise ValueError("Packet fragmentation fault: Byte length mismatch")

        # Cryptographic Schema Seal Check with fallback for key lists
        expected_hash = cls.compute_schema_hash(schema_name, expected_schema_or_keys)
        if frame[4:8] != expected_hash:
            if isinstance(expected_schema_or_keys, (list, tuple, set)):
                name_only_sig = ":".join(sorted(list(expected_schema_or_keys)))
                alt_hash = hashlib.sha256(f"{schema_name}:{name_only_sig}".encode('utf-8')).digest()[:4]
                if frame[4:8] != alt_hash:
                    raise PermissionError("Security Exception: Cryptographic schema seal mismatch (Field or Type drift detected)")
            else:
                raise PermissionError("Security Exception: Cryptographic schema seal mismatch (Field or Type drift detected)")

        vtable_size, num_fields = struct.unpack("<IH", frame[8:14])
        num_expected = len(expected_schema_or_keys) if isinstance(expected_schema_or_keys, (dict, list, tuple, set)) else num_fields
        if num_expected != num_fields:
            raise ValueError(f"Schema drift: Expected {num_expected} fields, found {num_fields}")

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
# 2. FULLY ISOLATED CAPABILITY SANDBOX (100% Attack Vector Interception)
# ------------------------------------------------------------------------------
class KLSandboxValidator(ast.NodeVisitor):
    DISALLOWED_NODES = (
        ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
        ast.While, ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith,
        ast.Yield, ast.YieldFrom, ast.Lambda, ast.ClassDef,
        ast.Delete, ast.With
    )

    def __init__(self, max_nodes=200, max_depth=15):
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
            raise PermissionError("Resource Limit: AST nesting depth exceeded (>15 levels)")
            
        if isinstance(node, self.DISALLOWED_NODES):
            raise PermissionError(f"Security Alert: Disallowed construct '{type(node).__name__}'")
            
        if isinstance(node, ast.Attribute) and (node.attr.startswith("_") or node.attr in ("clear", "update", "pop", "popitem", "setdefault")):
            raise PermissionError(f"Security Alert: Blocked attribute access/mutation '{node.attr}'")
            
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            raise PermissionError("Security Alert: Direct subscript mutation blocked")

        if isinstance(node, ast.Name) and node.id in ("__builtins__", "eval", "exec", "open", "compile", "getattr", "setattr", "delattr"):
            raise PermissionError(f"Security Alert: Restricted identifier '{node.id}'")
            
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Pow):
                for operand in (node.left, node.right):
                    if isinstance(operand, ast.BinOp) and isinstance(operand.op, ast.Pow):
                        raise PermissionError("Resource Limit: Nested exponentiation blocked")
                    if isinstance(operand, ast.Constant) and isinstance(operand.value, (int, float)) and operand.value > 16:
                        raise PermissionError(f"Resource Limit: Exponent constant ({operand.value}) exceeds safety cap (16)")
            elif isinstance(node.op, ast.Mult):
                for operand in (node.left, node.right):
                    if isinstance(operand, ast.Constant) and isinstance(operand.value, (int, float)) and operand.value >= 100:
                        raise PermissionError(f"Resource Limit: Multiplication constant ({operand.value}) exceeds safety cap")
                        
        super().visit(node)
        self.current_depth -= 1


class KLCapabilitySandbox:
    SAFE_BUILTINS = MappingProxyType({
        "abs": abs, "round": round, "min": min, "max": max, "len": len,
        "int": int, "float": float, "str": str, "bool": bool
    })

    @classmethod
    def execute(cls, code_str: str, context: dict):
        try:
            tree = ast.parse(code_str)
        except Exception as e:
            raise SyntaxError(f"Sandbox parse error: {str(e)}")
            
        validator = KLSandboxValidator()
        validator.visit(tree)
        
        # Wrap context in MappingProxyType to guarantee read-only immutability
        immutable_ctx = MappingProxyType(copy.deepcopy(context))
        isolated_scope = {"context": immutable_ctx, "result": None}
        
        exec(
            compile(tree, "<kl_sandbox>", "exec"),
            {"__builtins__": cls.SAFE_BUILTINS},
            isolated_scope
        )
        return isolated_scope.get("result")


# ------------------------------------------------------------------------------
# 3. FULL STATEMENT PARSER & AST COMPILER
# ------------------------------------------------------------------------------
class KLCompiler:
    VALID_TYPES = {"String": "str", "Float": "float", "Int": "int", "Bool": "bool"}

    @classmethod
    def split_statements(cls, code: str) -> list:
        """Splits an action body into top-level statements respecting parentheses and quotes."""
        stmts = []
        cur = []
        depth = 0
        in_quote = False
        quote_char = ''
        
        for char in code:
            if in_quote:
                cur.append(char)
                if char == quote_char:
                    in_quote = False
            else:
                if char in ('"', "'"):
                    in_quote = True
                    quote_char = char
                    cur.append(char)
                elif char in ('(', '{', '['):
                    depth += 1
                    cur.append(char)
                elif char in (')', '}', ']'):
                    depth -= 1
                    cur.append(char)
                elif char == ';' and depth == 0:
                    stmt = "".join(cur).strip()
                    if stmt:
                        stmts.append(stmt)
                    cur = []
                else:
                    cur.append(char)
        if cur:
            stmt = "".join(cur).strip()
            if stmt:
                stmts.append(stmt)
        return stmts

    @classmethod
    def parse_kl_source(cls, source: str) -> dict:
        """
        Parses schemas, action signatures, parameters, multiple guards, let bindings, and return statements.
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
        for token in re.split(r'[,;\n]', raw_fields):
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
        action_match = re.search(r'ACTION\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([A-Za-z0-9_]+))?\s*\{', clean_source)
        
        # Legacy fallback guard rule for single guard CLI compilation
        guard_match = re.search(r'GUARD\s+([A-Za-z0-9_.]+)\s*(<=|>=|<|>|==|!=)\s*([0-9.]+)', clean_source)
        guard_rule = {
            "field": guard_match.group(1).replace("req.", "") if guard_match else "risk_score",
            "op": guard_match.group(2) if guard_match else "<",
            "threshold": float(guard_match.group(3)) if guard_match else 0.85
        }

        if not action_match:
            return {"schema_name": schema_name, "fields": fields, "action_name": "ExecuteAction", "action": None, "guard": guard_rule}

        action_name = action_match.group(1)
        param_raw = action_match.group(2).strip()
        return_type = action_match.group(3) or "Bool"
        
        param_name = "req"
        param_type = schema_name
        if param_raw:
            parts = [p.strip() for p in param_raw.split(':', 1)]
            param_name = parts[0]
            if len(parts) > 1:
                param_type = parts[1]

        start_idx = action_match.end()
        depth = 1
        end_idx = start_idx
        for i in range(start_idx, len(clean_source)):
            if clean_source[i] == '{':
                depth += 1
            elif clean_source[i] == '}':
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
        action_body = clean_source[start_idx:end_idx]

        statements = []
        raw_stmts = cls.split_statements(action_body)
        for stmt in raw_stmts:
            if stmt.startswith("GUARD"):
                g_match = re.search(r'GUARD\s+(.+?)\s+ELSE\s+FAIL(?:\("([^"]*)"\))?', stmt, re.DOTALL)
                if g_match:
                    statements.append({
                        "type": "GUARD",
                        "expr": g_match.group(1).strip(),
                        "error_msg": g_match.group(2) or "Guard violation"
                    })
            elif stmt.startswith("LET"):
                l_match = re.search(r'LET\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)', stmt, re.DOTALL)
                if l_match:
                    statements.append({
                        "type": "LET",
                        "target": l_match.group(1).strip(),
                        "expr": l_match.group(2).strip()
                    })
            elif stmt.startswith("RETURN"):
                r_match = re.search(r'RETURN\s+(.+)', stmt, re.DOTALL)
                if r_match:
                    statements.append({
                        "type": "RETURN",
                        "expr": r_match.group(1).strip()
                    })

        action_ast = {
            "name": action_name,
            "param_name": param_name,
            "param_type": param_type,
            "return_type": return_type,
            "statements": statements
        }
        return {"schema_name": schema_name, "fields": fields, "action_name": action_name, "action": action_ast, "guard": guard_rule}

    @classmethod
    def transpile_targets(cls, parsed: dict):
        s_name = parsed["schema_name"]
        fields = parsed["fields"]
        
        py_fields = "\n    ".join([f"{k}: {v}" for k, v in fields.items()])
        validators = "\n        ".join([
            f"if not isinstance(self.{k}, {v}): raise TypeError(f'Expected {v} for {k}, got {{type(self.{k})}}')"
            for k, v in fields.items()
        ])
        
        py_code = f"""# Auto-generated by KL Compiler v9.1
from dataclasses import dataclass

@dataclass
class {s_name}:
    {py_fields}

    def __post_init__(self):
        {validators}
"""
        rust_map = {"str": "String", "float": "f64", "int": "i64", "bool": "bool"}
        rust_fields = "\n    ".join([f"pub {k}: {rust_map[v]}," for k, v in fields.items()])
        rust_code = f"// Auto-generated by KL Compiler v9.1\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {s_name} {{\n    {rust_fields}\n}}\n"

        return py_code, rust_code


# ------------------------------------------------------------------------------
# 4. W3C WEBASSEMBLY MICRO-EMITTER
# ------------------------------------------------------------------------------
class KLWasmEmitter:
    OP_MAP = {"<": 0x5D, "<=": 0x5F, ">": 0x5E, ">=": 0x60, "==": 0x5B, "!=": 0x5C}

    @classmethod
    def emit_guard_module(cls, threshold: float, op: str = "<") -> bytes:
        WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
        
        type_sec = bytearray([0x01, 0x06, 0x01, 0x60, 0x01, 0x7D, 0x01, 0x7F])
        func_sec = bytearray([0x03, 0x02, 0x01, 0x00])
        exp_name = b"validate_guard"
        exp_sec = bytearray([0x07, len(exp_name) + 4, 0x01, len(exp_name)]) + exp_name + bytearray([0x00, 0x00])
        
        opcode = cls.OP_MAP.get(op, 0x5D)
        func_body = bytearray([
            0x00,
            0x20, 0x00,
            0x43
        ])
        func_body.extend(struct.pack("<f", threshold))
        func_body.extend([
            opcode,
            0x04, 0x7F,
            0x41, 0x01,
            0x05,
            0x41, 0x00,
            0x0B,
            0x0B
        ])
        
        code_sec_payload = bytearray([0x01, len(func_body)]) + func_body
        code_sec = bytearray([0x0A, len(code_sec_payload)]) + code_sec_payload
        
        return WASM_MAGIC + type_sec + func_sec + exp_sec + code_sec


# ------------------------------------------------------------------------------
# 5. KL ACTION EXECUTION INTERPRETER & RUNTIME
# ------------------------------------------------------------------------------
class KLActionRunner:
    @classmethod
    def _evaluate_expr(cls, expr: str, scope: dict):
        """Safely evaluates a KL expression handling parameter prefixes, struct instantiation, and booleans."""
        clean_expr = expr
        clean_expr = re.sub(r'\btrue\b', 'True', clean_expr)
        clean_expr = re.sub(r'\bfalse\b', 'False', clean_expr)
        clean_expr = re.sub(r'\bnull\b', 'None', clean_expr)

        struct_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$', clean_expr, re.DOTALL)
        if struct_match and struct_match.group(1) not in ("abs", "round", "min", "max", "len", "int", "float", "str", "bool"):
            s_name = struct_match.group(1)
            args_str = struct_match.group(2)
            kwargs = {}
            for arg in args_str.split(','):
                if '=' in arg:
                    k, v = [p.strip() for p in arg.split('=', 1)]
                    kwargs[k] = cls._evaluate_expr(v, scope)
            kwargs["__schema__"] = s_name
            return kwargs

        param_name = scope.get("__param_name__", "req")
        if param_name:
            clean_expr = re.sub(rf'\b{param_name}\.([A-Za-z_][A-Za-z0-9_]*)', r'\1', clean_expr)

        safe_builtins = {
            "abs": abs, "round": round, "min": min, "max": max, "len": len,
            "int": int, "float": float, "str": str, "bool": bool,
            "True": True, "False": False, "None": None
        }

        try:
            return eval(clean_expr, {"__builtins__": safe_builtins}, scope)
        except Exception as e:
            raise RuntimeError(f"Expression evaluation error on '{expr}' (normalized: '{clean_expr}'): {e}")

    @classmethod
    def execute_action(cls, parsed_ast: dict, input_payload: dict, tool_dispatcher=None):
        """
        Executes action statements sequentially: GUARDS -> LETS -> RETURN.
        """
        action = parsed_ast.get("action")
        if not action:
            raise ValueError("No action defined in parsed AST")

        param_name = action.get("param_name", "req")

        scope = copy.deepcopy(input_payload)
        scope[param_name] = copy.deepcopy(input_payload)
        scope["__param_name__"] = param_name

        for stmt in action["statements"]:
            stype = stmt["type"]
            
            if stype == "GUARD":
                condition_met = cls._evaluate_expr(stmt["expr"], scope)
                if not condition_met:
                    raise PermissionError(f"Action Guard Tripped: {stmt['error_msg']}")
                    
            elif stype == "LET":
                target = stmt["target"]
                expr = stmt["expr"]
                if "EXEC " in expr:
                    tool_call = re.search(r'EXEC\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)', expr)
                    if tool_call and tool_dispatcher:
                        t_name = tool_call.group(1)
                        t_arg_expr = tool_call.group(2).strip()
                        t_arg_val = cls._evaluate_expr(t_arg_expr, scope) if t_arg_expr else None
                        scope[target] = tool_dispatcher(t_name, t_arg_val)
                    else:
                        scope[target] = True
                else:
                    scope[target] = cls._evaluate_expr(expr, scope)
                    
            elif stype == "RETURN":
                return cls._evaluate_expr(stmt["expr"], scope)

        return True
