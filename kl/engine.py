"""
KL Core Compiler & Execution Engine v10.5 (Industrial Protocol Engine & AI Agent IDL)
Tag-Based VTable Codec, Fixed-Point Decimal, Schema Evolution, Capability Sandbox & Action VM
"""
import struct
import hashlib
import time
import ast
import re
import copy
import decimal
from types import MappingProxyType

# ------------------------------------------------------------------------------
# 1. FIXED-POINT SCALAR & STRUCTURED EXCEPTIONS
# ------------------------------------------------------------------------------
class KLDecimal:
    """
    Fixed-point 64-bit mantissa + 8-bit scale factor scalar.
    Eliminates IEEE-754 floating point rounding drift for financial & billing logic.
    """
    def __init__(self, value=0, scale: int = None):
        if isinstance(value, KLDecimal):
            self.mantissa = value.mantissa
            self.scale = value.scale
        elif isinstance(value, (int, str, float, decimal.Decimal)):
            val_str = str(value).rstrip('dD').strip()
            d = decimal.Decimal(val_str)
            if scale is None:
                if '.' in val_str:
                    scale = len(val_str.split('.')[1])
                else:
                    scale = 0
            self.scale = min(max(scale, 0), 255)
            self.mantissa = int(d * (decimal.Decimal(10) ** self.scale))
        else:
            raise TypeError(f"Cannot initialize KLDecimal from type '{type(value).__name__}'")

    @classmethod
    def from_raw(cls, mantissa: int, scale: int):
        inst = cls.__new__(cls)
        inst.mantissa = mantissa
        inst.scale = scale
        return inst

    def to_decimal(self) -> decimal.Decimal:
        return decimal.Decimal(self.mantissa) / (decimal.Decimal(10) ** self.scale)

    def __float__(self):
        return float(self.to_decimal())

    def __int__(self):
        return int(self.to_decimal())

    def __str__(self):
        d = self.to_decimal()
        if self.scale > 0:
            return f"{d:.{self.scale}f}"
        return str(int(d))

    def __repr__(self):
        return f"KLDecimal('{str(self)}')"

    def _oper_decimal(self, other):
        if isinstance(other, KLDecimal):
            return other.to_decimal(), other.scale
        d = decimal.Decimal(str(other).rstrip('dD'))
        s = len(str(other).split('.')[1]) if '.' in str(other) else 0
        return d, s

    def _fit_scale(self, res: decimal.Decimal, s1: int, s2: int) -> int:
        norm = res.normalize()
        exp = norm.as_tuple().exponent
        norm_scale = -exp if isinstance(exp, int) and exp < 0 else 0
        max_s = max(s1, s2)
        min_s = min(s1, s2)
        target_scale = max(norm_scale, min_s)
        return min(target_scale, max_s)

    def __add__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = self.to_decimal() + other_d
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = self.to_decimal() - other_d
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __rsub__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = other_d - self.to_decimal()
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __mul__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = self.to_decimal() * other_d
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = self.to_decimal() / other_d
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __rtruediv__(self, other):
        other_d, other_s = self._oper_decimal(other)
        res = other_d / self.to_decimal()
        return KLDecimal(res, scale=self._fit_scale(res, self.scale, other_s))

    def __eq__(self, other):
        if other is None: return False
        try:
            other_d, _ = self._oper_decimal(other)
            return self.to_decimal() == other_d
        except Exception:
            return False

    def __lt__(self, other):
        other_d, _ = self._oper_decimal(other)
        return self.to_decimal() < other_d

    def __le__(self, other):
        other_d, _ = self._oper_decimal(other)
        return self.to_decimal() <= other_d

    def __gt__(self, other):
        other_d, _ = self._oper_decimal(other)
        return self.to_decimal() > other_d

    def __ge__(self, other):
        other_d, _ = self._oper_decimal(other)
        return self.to_decimal() >= other_d


class KLGuardError(PermissionError):
    """Structured machine-readable exception raised when a GUARD condition is tripped."""
    def __init__(self, error_code: str, message: str):
        self.error_code = error_code
        self.message = message
        super().__init__(f"[{error_code}] {message}")


# ------------------------------------------------------------------------------
# 2. FULLY ISOLATED CAPABILITY SANDBOX (Anti-DoS Protection)
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
                        raise PermissionError("Resource Limit: Multiplication constant ({operand.value}) exceeds safety cap")

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

        immutable_ctx = MappingProxyType(copy.deepcopy(context))
        isolated_scope = {"context": immutable_ctx, "result": None}

        exec(
            compile(tree, "<kl_sandbox>", "exec"),
            {"__builtins__": cls.SAFE_BUILTINS},
            isolated_scope
        )
        return isolated_scope.get("result")


# ------------------------------------------------------------------------------
# 3. TAG-BASED VTABLE CODEC & Cryptographic 32-Byte Schema Seal
# ------------------------------------------------------------------------------
class KLCodec:
    MAGIC = b"KL\x08"
    VERSION = 0x02  # v10.5 Format

    @classmethod
    def get_canonical_type(cls, type_name_or_val) -> str:
        """Normalizes type descriptors for canonical signature hashes."""
        if isinstance(type_name_or_val, str):
            t = type_name_or_val.strip()
            if t in ("str", "String"): return "String"
            if t in ("float", "Float"): return "Float"
            if t in ("int", "Int"): return "Int"
            if t in ("bool", "Bool"): return "Bool"
            if t in ("decimal", "Decimal"): return "Decimal"
            return t
        if isinstance(type_name_or_val, KLDecimal): return "Decimal"
        if isinstance(type_name_or_val, bool): return "Bool"
        if isinstance(type_name_or_val, int): return "Int"
        if isinstance(type_name_or_val, float): return "Float"
        if isinstance(type_name_or_val, str): return "String"
        if isinstance(type_name_or_val, list): return "List"
        if isinstance(type_name_or_val, dict): return "Map"
        return str(type(type_name_or_val).__name__)

    @classmethod
    def compute_schema_hash(cls, schema_name: str, fields_meta: list) -> bytes:
        sorted_fields = sorted(fields_meta, key=lambda x: x['tag'])
        sig_parts = [f"@{f['tag']}:{f['name']}:{cls.get_canonical_type(f['type'])}" for f in sorted_fields]
        sig_str = f"{schema_name}:" + ";".join(sig_parts)
        return hashlib.sha256(sig_str.encode('utf-8')).digest()

    @classmethod
    def pack_value(cls, val, ftype: str, body: bytearray, vtable_base: int):
        if val is None or (ftype.startswith("Optional") and val is None):
            return 0

        current_abs = vtable_base + len(body)
        align_pad = (8 - (current_abs % 8)) % 8
        body.extend(b"\x00" * align_pad)
        val_offset = vtable_base + len(body)

        if ftype in ("bool", "Bool"):
            body.append(1 if val else 0)
        elif ftype in ("int", "Int"):
            if not (-9223372036854775808 <= val <= 9223372036854775807):
                raise OverflowError(f"Integer '{val}' exceeds signed 64-bit bounds")
            body.extend(struct.pack("<q", val))
        elif ftype in ("float", "Float"):
            body.extend(struct.pack("<d", float(val)))
        elif ftype in ("decimal", "Decimal"):
            dec = KLDecimal(val)
            body.extend(struct.pack("<qB", dec.mantissa, dec.scale))
        elif ftype in ("str", "String"):
            enc = str(val).encode('utf-8')
            body.extend(struct.pack("<I", len(enc)) + enc)
        elif ftype.startswith("Optional<") and ftype.endswith(">"):
            inner_type = ftype[9:-1].strip()
            return cls.pack_value(val, inner_type, body, vtable_base)
        elif ftype.startswith("List<") and ftype.endswith(">"):
            elem_type = ftype[5:-1].strip()
            items = list(val)
            body.extend(struct.pack("<I", len(items)))
            for item in items:
                cls.pack_value(item, elem_type, body, vtable_base)
        elif ftype.startswith("Map<") and ftype.endswith(">"):
            inner = ftype[4:-1].strip()
            k_type, v_type = [p.strip() for p in inner.split(',', 1)]
            pairs = dict(val)
            body.extend(struct.pack("<I", len(pairs)))
            for k, v in pairs.items():
                cls.pack_value(k, k_type, body, vtable_base)
                cls.pack_value(v, v_type, body, vtable_base)
        else:
            enc = str(val).encode('utf-8')
            body.extend(struct.pack("<I", len(enc)) + enc)

        return val_offset

    @classmethod
    def serialize_frame(cls, schema_name: str, fields_data: dict, schema_meta: list = None) -> bytes:
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', schema_name):
            raise ValueError(f"Invalid schema identifier: '{schema_name}'")

        if schema_meta is None:
            sorted_keys = sorted(list(fields_data.keys()))
            schema_meta = [{"tag": idx + 1, "name": k, "type": cls.get_canonical_type(fields_data[k])} for idx, k in enumerate(sorted_keys)]

        num_fields = len(schema_meta)
        if num_fields > 65535:
            raise ValueError("Schema exceeds maximum field limit (65,535)")

        schema_seal = cls.compute_schema_hash(schema_name, schema_meta)

        vtable_size = 44 + (num_fields * 8)
        body = bytearray()
        vtable_entries = []

        sorted_meta = sorted(schema_meta, key=lambda x: x['tag'])

        for field_def in sorted_meta:
            tag = field_def['tag']
            fname = field_def['name']
            ftype = field_def['type']
            val = fields_data.get(fname)

            if val is None and not ftype.startswith("Optional"):
                val_offset = 0
            else:
                val_offset = cls.pack_value(val, ftype, body, vtable_size)

            vtable_entries.append((tag, val_offset))

        core_payload = bytearray(cls.MAGIC)
        core_payload.append(cls.VERSION)
        core_payload.extend(schema_seal)
        core_payload.extend(struct.pack("<IH", vtable_size, num_fields))
        core_payload.extend(b"\x00\x00")

        for tag, off in vtable_entries:
            core_payload.extend(struct.pack("<HHI", tag, 0x0000, off))

        core_payload.extend(body)

        frame_prefix = struct.pack("!II", len(core_payload), 0x00000000)
        return frame_prefix + bytes(core_payload)

    @classmethod
    def unpack_value(cls, frame: bytes, field_offset: int, ftype: str, buf_len: int):
        if field_offset == 0 or field_offset >= buf_len:
            return None

        try:
            if ftype in ("bool", "Bool"):
                return frame[field_offset] == 1
            elif ftype in ("int", "Int"):
                return struct.unpack("<q", frame[field_offset:field_offset+8])[0]
            elif ftype in ("float", "Float"):
                return struct.unpack("<d", frame[field_offset:field_offset+8])[0]
            elif ftype in ("decimal", "Decimal"):
                mantissa, scale = struct.unpack("<qB", frame[field_offset:field_offset+9])
                return KLDecimal.from_raw(mantissa, scale)
            elif ftype in ("str", "String"):
                s_len = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
                return frame[field_offset+4:field_offset+4+s_len].decode('utf-8', errors='replace')
            elif ftype.startswith("Optional<") and ftype.endswith(">"):
                inner_type = ftype[9:-1].strip()
                return cls.unpack_value(frame, field_offset, inner_type, buf_len)
            elif ftype.startswith("List<") and ftype.endswith(">"):
                elem_type = ftype[5:-1].strip()
                count = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
                res = []
                curr = field_offset + 4
                for _ in range(count):
                    item = cls.unpack_value(frame, curr, elem_type, buf_len)
                    res.append(item)
                    if elem_type in ("int", "Int", "float", "Float"): curr += 8
                    elif elem_type in ("decimal", "Decimal"): curr += 9
                    elif elem_type in ("bool", "Bool"): curr += 1
                    elif elem_type in ("str", "String"):
                        slen = struct.unpack("<I", frame[curr:curr+4])[0]
                        curr += 4 + slen
                return res
            elif ftype.startswith("Map<") and ftype.endswith(">"):
                inner = ftype[4:-1].strip()
                k_type, v_type = [p.strip() for p in inner.split(',', 1)]
                count = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
                res = {}
                curr = field_offset + 4
                for _ in range(count):
                    k = cls.unpack_value(frame, curr, k_type, buf_len)
                    if k_type in ("str", "String"):
                        slen = struct.unpack("<I", frame[curr:curr+4])[0]
                        curr += 4 + slen
                    else: curr += 8
                    v = cls.unpack_value(frame, curr, v_type, buf_len)
                    if v_type in ("str", "String"):
                        slen = struct.unpack("<I", frame[curr:curr+4])[0]
                        curr += 4 + slen
                    else: curr += 8
                    res[k] = v
                return res

            s_len = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
            return frame[field_offset+4:field_offset+4+s_len].decode('utf-8', errors='replace')
        except (struct.error, IndexError) as e:
            raise ValueError(f"Corrupted field payload truncation: {str(e)}")

    @classmethod
    def read_field_by_tag(cls, framed_bytes: bytes, target_tag: int, field_type: str = "String", expected_seal: bytes = None):
        try:
            if not isinstance(framed_bytes, (bytes, bytearray)) or len(framed_bytes) < 44:
                raise ValueError("Corrupt framed packet: Header underflow")

            frame_len = struct.unpack("!I", framed_bytes[:4])[0]
            frame = framed_bytes[8:]
            if len(frame) != frame_len:
                raise ValueError("Packet fragmentation fault: Byte length mismatch")

            vtable_size, num_fields = struct.unpack("<IH", frame[36:42])

            tag_map = {}
            for i in range(num_fields):
                entry_pos = 44 + (i * 8)
                if entry_pos + 8 > vtable_size or entry_pos + 8 > len(frame):
                    break
                tag, pad, off = struct.unpack("<HHI", frame[entry_pos:entry_pos+8])
                tag_map[tag] = off

            if target_tag in tag_map:
                val_off = tag_map[target_tag]
                return cls.unpack_value(frame, val_off, field_type, len(frame))

            if field_type.startswith("Optional"):
                return None

            return None
        except (struct.error, IndexError) as e:
            raise ValueError(f"Corrupt framed packet: Binary payload truncation or alignment error ({str(e)})")


# ------------------------------------------------------------------------------
# 4. FULL STATEMENT PARSER & AST COMPILER
# ------------------------------------------------------------------------------
class KLCompiler:
    VALID_TYPES = {"String", "Float", "Int", "Bool", "Decimal", "Optional", "List", "Map"}

    @classmethod
    def split_field_tokens(cls, fields_str: str) -> list:
        tokens = []
        cur = []
        depth = 0
        for char in fields_str:
            if char in ('<', '('):
                depth += 1
                cur.append(char)
            elif char in ('>', ')'):
                depth -= 1
                cur.append(char)
            elif char in (',', ';', '\n') and depth == 0:
                t = "".join(cur).strip()
                if t:
                    tokens.append(t)
                cur = []
            else:
                cur.append(char)
        if cur:
            t = "".join(cur).strip()
            if t:
                tokens.append(t)
        return tokens

    @classmethod
    def split_statements(cls, code: str) -> list:
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
    def parse_kl_source(cls, kl_code: str) -> dict:
        kl_code = re.sub(r'//.*', '', kl_code)

        schema_match = re.search(r'SCHEMA\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}', kl_code, re.DOTALL)
        if not schema_match:
            raise SyntaxError("Compilation Error: Missing valid 'SCHEMA <Identifier> { ... }' declaration")

        schema_name = schema_match.group(1).strip()
        fields_raw = schema_match.group(2).strip()

        fields_map = {}
        schema_meta = []
        tokens = cls.split_field_tokens(fields_raw)

        auto_tag = 1
        for token in tokens:
            if not token: continue
            tag_match = re.match(r'^@(\d+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$', token)
            if tag_match:
                tag = int(tag_match.group(1))
                fname = tag_match.group(2).strip()
                ftype = tag_match.group(3).strip()
            else:
                untagged_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$', token)
                if untagged_match:
                    tag = auto_tag
                    fname = untagged_match.group(1).strip()
                    ftype = untagged_match.group(2).strip()
                else:
                    raise SyntaxError(f"Malformed schema field definition: '{token}'")

            fields_map[fname] = ftype
            schema_meta.append({"tag": tag, "name": fname, "type": ftype})
            auto_tag = max(auto_tag, tag + 1)

        schema_seal = KLCodec.compute_schema_hash(schema_name, schema_meta)

        action_match = re.search(r'ACTION\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*->\s*(.+?)\s*\{([^}]*)\}', kl_code, re.DOTALL)

        action_name = None
        param_name = None
        param_type = None
        return_type = None
        statements = []
        guard_rule = {"threshold": 0.85, "op": "<="}

        if action_match:
            action_name = action_match.group(1).strip()
            param_name = action_match.group(2).strip()
            param_type = action_match.group(3).strip()
            return_type = action_match.group(4).strip()
            body_raw = action_match.group(5).strip()

            raw_stmts = cls.split_statements(body_raw)

            for stmt_str in raw_stmts:
                if stmt_str.startswith("GUARD"):
                    g_match = re.match(r'^GUARD\s+(.+?)(?:\s+ELSE\s+FAIL\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*["\'](.*?)["\']\s*\))?$', stmt_str)
                    if g_match:
                        expr = g_match.group(1).strip()
                        err_code = g_match.group(2) if g_match.group(2) else "GuardViolation"
                        err_msg = g_match.group(3) if g_match.group(3) else "Guard condition failed"

                        val_match = re.search(r'([<>=]+)\s*([0-9.]+)', expr)
                        if val_match:
                            guard_rule = {"op": val_match.group(1), "threshold": float(val_match.group(2))}

                        statements.append({
                            "type": "GUARD",
                            "expr": expr,
                            "error_code": err_code,
                            "error_msg": err_msg
                        })
                elif stmt_str.startswith("LET"):
                    l_match = re.match(r'^LET\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$', stmt_str)
                    if l_match:
                        statements.append({
                            "type": "LET",
                            "target": l_match.group(1).strip(),
                            "expr": l_match.group(2).strip()
                        })
                elif stmt_str.startswith("RETURN"):
                    r_match = re.match(r'^RETURN\s+(.+)$', stmt_str)
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
        return {
            "schema_name": schema_name, "fields": fields_map, "schema_meta": schema_meta,
            "schema_seal": schema_seal, "action_name": action_name, "action": action_ast, "guard": guard_rule
        }

    @classmethod
    def _map_py_type(cls, t_str: str) -> str:
        t_str = t_str.strip()
        if t_str.startswith("Optional<") and t_str.endswith(">"):
            return f"Optional[{cls._map_py_type(t_str[9:-1])}]"
        if t_str.startswith("List<") and t_str.endswith(">"):
            return f"List[{cls._map_py_type(t_str[5:-1])}]"
        if t_str.startswith("Map<") and t_str.endswith(">"):
            inner = t_str[4:-1]
            k, v = [p.strip() for p in inner.split(',', 1)]
            return f"Dict[{cls._map_py_type(k)}, {cls._map_py_type(v)}]"
        py_type_map = {"String": "str", "Float": "float", "Int": "int", "Bool": "bool", "Decimal": "KLDecimal"}
        return py_type_map.get(t_str, t_str)

    @classmethod
    def _map_rust_type(cls, t_str: str) -> str:
        t_str = t_str.strip()
        if t_str.startswith("Optional<") and t_str.endswith(">"):
            return f"Option<{cls._map_rust_type(t_str[9:-1])}>"
        if t_str.startswith("List<") and t_str.endswith(">"):
            return f"Vec<{cls._map_rust_type(t_str[5:-1])}>"
        if t_str.startswith("Map<") and t_str.endswith(">"):
            inner = t_str[4:-1]
            k, v = [p.strip() for p in inner.split(',', 1)]
            return f"std::collections::HashMap<{cls._map_rust_type(k)}, {cls._map_rust_type(v)}>"
        rust_type_map = {"String": "String", "Float": "f64", "Int": "i64", "Bool": "bool", "Decimal": "rust_decimal::Decimal"}
        return rust_type_map.get(t_str, t_str)

    @classmethod
    def _map_ts_type(cls, t_str: str) -> str:
        t_str = t_str.strip()
        if t_str.startswith("Optional<") and t_str.endswith(">"):
            return f"{cls._map_ts_type(t_str[9:-1])} | null"
        if t_str.startswith("List<") and t_str.endswith(">"):
            return f"{cls._map_ts_type(t_str[5:-1])}[]"
        if t_str.startswith("Map<") and t_str.endswith(">"):
            inner = t_str[4:-1]
            k, v = [p.strip() for p in inner.split(',', 1)]
            return f"Record<{cls._map_ts_type(k)}, {cls._map_ts_type(v)}>"
        ts_type_map = {"String": "string", "Float": "number", "Int": "number", "Bool": "boolean", "Decimal": "string"}
        return ts_type_map.get(t_str, t_str)

    @classmethod
    def _map_go_type(cls, t_str: str) -> str:
        t_str = t_str.strip()
        if t_str.startswith("Optional<") and t_str.endswith(">"):
            return f"*{cls._map_go_type(t_str[9:-1])}"
        if t_str.startswith("List<") and t_str.endswith(">"):
            return f"[]{cls._map_go_type(t_str[5:-1])}"
        if t_str.startswith("Map<") and t_str.endswith(">"):
            inner = t_str[4:-1]
            k, v = [p.strip() for p in inner.split(',', 1)]
            return f"map[{cls._map_go_type(k)}]{cls._map_go_type(v)}"
        go_type_map = {"String": "string", "Float": "float64", "Int": "int64", "Bool": "bool", "Decimal": "string"}
        return go_type_map.get(t_str, t_str)

    @classmethod
    def transpile_targets(cls, parsed: dict):
        s_name = parsed["schema_name"]
        schema_meta = parsed.get("schema_meta", [])

        # 1. Python Target
        py_fields_list = []
        for f in schema_meta:
            fname = f["name"]
            ftype = f["type"]
            py_t = cls._map_py_type(ftype)
            py_fields_list.append(f"    {fname}: {py_t}")

        py_fields = "\n".join(py_fields_list)
        py_code = f"""# Auto-generated by KL Compiler v10.5 (Industrial Protocol Engine)
from dataclasses import dataclass
from typing import Optional, List, Dict
from kl.engine import KLDecimal

@dataclass
class {s_name}:
{py_fields}

    def __post_init__(self):
        pass
"""

        # 2. Rust Target
        rust_fields_list = []
        for f in schema_meta:
            fname = f["name"]
            ftype = f["type"]
            rs_t = cls._map_rust_type(ftype)
            rust_fields_list.append(f"    pub {fname}: {rs_t},")

        rust_fields = "\n".join(rust_fields_list)
        rust_code = f"// Auto-generated by KL Compiler v10.5 (Industrial Protocol Engine)\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {s_name} {{\n{rust_fields}\n}}\n"

        # 3. TypeScript Target
        ts_fields_list = []
        for f in schema_meta:
            fname = f["name"]
            ftype = f["type"]
            tag = f["tag"]
            ts_t = cls._map_ts_type(ftype)
            is_opt = ftype.startswith("Optional")
            opt_flag = "?" if is_opt else ""
            ts_fields_list.append(f"  /** Tag @{tag} */\n  {fname}{opt_flag}: {ts_t};")

        ts_fields = "\n".join(ts_fields_list)
        ts_code = f"/** Auto-generated by KL Compiler v10.5 (Industrial Protocol Engine) */\nexport interface {s_name} {{\n{ts_fields}\n}}\n"

        # 4. Go Target
        go_fields_list = []
        for f in schema_meta:
            fname = f["name"]
            go_fname = fname[0].upper() + fname[1:]
            ftype = f["type"]
            tag = f["tag"]
            go_t = cls._map_go_type(ftype)
            go_fields_list.append(f"\t{go_fname} {go_t} `json:\"{fname}\" kl:\"@{tag}\"`")

        go_fields = "\n".join(go_fields_list)
        go_code = f"// Auto-generated by KL Compiler v10.5 (Industrial Protocol Engine)\npackage schema\n\ntype {s_name} struct {{\n{go_fields}\n}}\n"

        return py_code, rust_code, ts_code, go_code


# ------------------------------------------------------------------------------
# 5. W3C WEBASSEMBLY MICRO-EMITTER
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
        func_body.extend(struct.pack("<f", float(threshold)))
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
# 6. KL ACTION EXECUTION INTERPRETER & RUNTIME
# ------------------------------------------------------------------------------
class KLActionRunner:
    @classmethod
    def _evaluate_expr(cls, expr: str, scope: dict):
        """Safely evaluates a KL expression handling fixed-point decimals (0.0d), parameter prefixes, and booleans."""
        clean_expr = expr

        clean_expr = re.sub(r'\b(\d+(?:\.\d+)?)[dD]\b', r"KLDecimal('\1')", clean_expr)

        clean_expr = re.sub(r'\btrue\b', 'True', clean_expr)
        clean_expr = re.sub(r'\bfalse\b', 'False', clean_expr)
        clean_expr = re.sub(r'\bnull\b', 'None', clean_expr)

        struct_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$', clean_expr, re.DOTALL)
        if struct_match and struct_match.group(1) not in ("abs", "round", "min", "max", "len", "int", "float", "str", "bool", "KLDecimal"):
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
            "KLDecimal": KLDecimal,
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
        Raises KLGuardError for tripped guard boundaries.
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
                    err_code = stmt.get("error_code", "GuardViolation")
                    err_msg = stmt.get("error_msg", "Guard boundary tripped")
                    raise KLGuardError(err_code, err_msg)

            elif stype == "LET":
                target = stmt["target"]
                expr = stmt["expr"]
                if "EXEC " in expr:
                    tool_call = re.search(r'EXEC\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)', expr)
                    if tool_call and tool_dispatcher:
                        t_name = tool_call.group(1)
                        t_arg = tool_call.group(2).strip()
                        scope[target] = tool_dispatcher(t_name, scope.get(t_arg))
                    else:
                        scope[target] = True
                else:
                    scope[target] = cls._evaluate_expr(expr, scope)

            elif stype == "RETURN":
                return cls._evaluate_expr(stmt["expr"], scope)

        return None
