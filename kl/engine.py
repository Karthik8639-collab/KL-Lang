"""
KL Core Compiler & Execution Engine v8.0
Standardized Zero-Copy Binary Wire & Deterministic Protocol
"""
import struct
import hashlib
import time
import ast
import re
import difflib
import os

# ------------------------------------------------------------------------------
# 1. MEMORY-ALIGNED VTABLE CODEC
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
            # 8-byte alignment padding
            align_pad = (8 - (len(body) % 8)) % 8
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
        core_payload.append(0x01) # Format version
        core_payload.extend(schema_hash)
        core_payload.extend(struct.pack("<IH", vtable_size, num_fields))
        for off in offsets:
            core_payload.extend(struct.pack("<I", off))
        core_payload.extend(body)

        return struct.pack("!I", len(core_payload)) + bytes(core_payload)

    @classmethod
    def read_field_verified(cls, framed_bytes: bytes, schema_name: str, expected_keys: list, field_idx: int, field_type: str):
        if len(framed_bytes) < 18:
            raise ValueError("Corrupt framed packet: Header underflow")
            
        frame_len = struct.unpack("!I", framed_bytes[:4])[0]
        frame = framed_bytes[4:]
        if len(frame) != frame_len:
            raise ValueError("Packet fragmentation fault: Length mismatch")

        keys = sorted(expected_keys)
        expected_hash = hashlib.sha256(f"{schema_name}:{':'.join(keys)}".encode('utf-8')).digest()[:4]
        if frame[4:8] != expected_hash:
            raise PermissionError("Security Exception: Cryptographic schema seal mismatch")

        vtable_size, num_fields = struct.unpack("<IH", frame[8:14])
        if field_idx >= num_fields:
            raise IndexError("Field index out of schema range")

        offset_pos = 14 + (field_idx * 4)
        field_offset = struct.unpack("<I", frame[offset_pos:offset_pos+4])[0]
        buf_len = len(frame)

        if field_offset >= buf_len or field_offset < vtable_size:
            raise IndexError("Memory fault: Offset bounds violation")

        if field_type == "float":
            return struct.unpack("<d", frame[field_offset:field_offset+8])[0]
        elif field_type == "int":
            return struct.unpack("<q", frame[field_offset:field_offset+8])[0]
        elif field_type == "str":
            s_len = struct.unpack("<I", frame[field_offset:field_offset+4])[0]
            if field_offset + 4 + s_len > buf_len:
                raise IndexError("String body overflows memory boundary")
            return frame[field_offset+4:field_offset+4+s_len].decode('utf-8', errors='replace')
        elif field_type == "bool":
            return frame[field_offset] == 1
        return None

# ------------------------------------------------------------------------------
# 2. DETERMINISTIC WASM EMITTER
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

# ------------------------------------------------------------------------------
# 3. HEURISTIC PARSER & TRANSPILER
# ------------------------------------------------------------------------------
class KLCompiler:
    KEYWORDS = {"SCHEMA", "ACTION", "GUARD", "ELSE", "FAIL", "EXEC", "IN", "SANDBOX", "LET", "RETURN"}
    ALIASES = {"act": "ACTION", "func": "ACTION", "fn": "ACTION", "struct": "SCHEMA", "model": "SCHEMA", "var": "LET", "check": "GUARD"}

    @classmethod
    def heal_source(cls, source: str):
        tokens = []
        fixes = []
        token_regex = re.compile(
            r'(?P<STRING>"(?:\\.|[^"\\])*")|'
            r'(?P<COMMENT>//[^\n]*)|'
            r'(?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)|'
            r'(?P<OP>[<>!=]=?|[+\-*/=])|'
            r'(?P<PUNCT>[{}();:,])|'
            r'(?P<WS>\s+)'
        )
        for m in token_regex.finditer(source):
            kind = m.lastgroup
            val = m.group()
            if kind == "IDENT":
                low = val.lower()
                if low in cls.ALIASES:
                    tokens.append(cls.ALIASES[low])
                    fixes.append(f"Remapped alias '{val}' -> '{cls.ALIASES[low]}'")
                elif val.upper() in cls.KEYWORDS:
                    tokens.append(val.upper())
                else:
                    close = difflib.get_close_matches(val.upper(), cls.KEYWORDS, n=1, cutoff=0.75)
                    if close:
                        tokens.append(close[0])
                        fixes.append(f"Auto-healed typo '{val}' -> '{close[0]}'")
                    else:
                        tokens.append(val)
            else:
                tokens.append(val)

        repaired = "".join(tokens)
        open_b = repaired.count("{") - repaired.count("}")
        if open_b > 0:
            repaired += "\n" + ("}" * open_b)
            fixes.append(f"Balanced {open_b} unclosed bracket(s)")
        return repaired, fixes

    @classmethod
    def transpile_targets(cls, schema_name: str, fields: dict):
        py_fields = "\n    ".join([f"{k}: {v}" for k, v in fields.items()])
        py_code = f"# Auto-generated by KL Compiler\nfrom dataclasses import dataclass\n\n@dataclass\nclass {schema_name}:\n    {py_fields}\n"
        
        rust_fields = "\n    ".join([f"pub {k}: {v.lower().replace('float', 'f64').replace('str', 'String').replace('int', 'i64')}," for k, v in fields.items()])
        rust_code = f"// Auto-generated by KL Compiler\n#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct {schema_name} {{\n    {rust_fields}\n}}\n"
        
        return py_code, rust_code
