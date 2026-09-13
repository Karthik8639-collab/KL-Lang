# ⚡ KL (`.kl`) - Universal AI Agent Protocol & Industrial IDL (v10.5)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Specification Audit](https://img.shields.io/badge/Specification%20Audit-12%2F12%20Passed-brightgreen.svg)]()
[![Fuzz Resilience](https://img.shields.io/badge/Fuzzing-50k%20Zero%20Fault-purple.svg)]()
[![WASM Micro Core](https://img.shields.io/badge/WASM-62%20Bytes%20(W3C%20Valid)-success.svg)]()
[![Multi-Target CodeGen](https://img.shields.io/badge/Code%20Gen-Py%20%7C%20Rust%20%7C%20TS%20%7C%20Go-orange.svg)]()

> **KL (`.kl`)** is an industrial Interface Definition Language (IDL), 8-byte aligned tagged VTable wire protocol, and sandboxed AI action execution engine. It is engineered specifically for **Autonomous AI Agents, Anthropic Model Context Protocol (MCP) Tools, OpenAI Function Calling, and Zero-Trust Cloud Microservices**.

---

## 📜 Evolutionary Journey (From v1.0 to v10.5 Protocol Standard)
### ⏳ Version Evolution

| Version | Core Architecture | Primary Memory Paradigm | Key Paradigm Enhancements |
| :--- | :--- | :--- | :--- |
| **v1.0 - v8.0** | **Dynamic Scripting** | Unsafe Heap Allocation | Initial scripting implementation relying on dynamic runtimes and unconstrained heap allocations. |
| **v9.0 - v9.1** | **Action VM & Codec** | Fixed Offsets & Seals | Transitioned to absolute compilation offsets and cryptographic schema integrity validation. |
| **v10.0 - v10.5** | **AI Agent Protocol IDL** | MCP & Multi-Target | Modern decoupled schema architecture enabling universal AI tool execution and cross-language generation. |


* **v1.0 – v8.0 (Experimental Prototype):** Dynamic scripting interpreter. Suffered from unconstrained heap allocations, IEEE-754 float drift, and non-deterministic security risks.
* **v9.0 – v9.1 (VTable & Action VM Era):** Introduced 8-byte word alignment, 32-byte cryptographic SHA-256 schema seals, and an AST Capability Sandbox (`KLSandboxValidator`).
* **v10.0 – v10.5 (Industrial AI Protocol Standard):** Refactored KL into a **Specialized IDL & Wire Protocol** for AI Agent tool calling and cloud microservices. Added fixed-point `Decimal` scalars, `Optional<T>`, `List<T>`, `Map<K,V>`, 4 multi-language code generators (Python, Rust, TypeScript, Go), OpenAI & Anthropic MCP exporters, domain-aware realistic payload generators, and a high-throughput JSON/REST transcoder gateway.

---

## 🚨 The Core Problem & Why This Matters

Modern distributed systems, cloud microservices, and AI Agent networks face three major architectural vulnerabilities:

1. **The AI Injection Hazard:** Executing untrusted LLM tool calls directly in Python or JavaScript risks Remote Code Execution (RCE), unconstrained infinite loops, or arbitrary file system access.
2. **Token & Network Serialization Overhead:** Plain-text JSON payloads re-transmit dictionary keys on every HTTP call, inflating network bandwidth by 60%–75% and consuming valuable LLM token context windows.
3. **IEEE-754 Precision Drift:** Standard JSON floating-point numbers distort financial and billing transactions ($0.1 + 0.2 = 0.30000000000000004$), making JSON unsuitable for financial microservices or billing meters.

---

## 💡 KL Core Architecture & Innovations

1. **Tag-Based VTable Codec:** Uses Protobuf-style `@1`, `@2` field tags with 8-byte aligned memory offsets, allowing forward/backward schema evolution without breaking legacy readers.
2. **Cryptographic SHA-256 Schema Seal:** Generates a 32-byte signature seal locking field names and canonical types into binary headers, detecting schema drift instantly.
3. **Fixed-Point `Decimal` Scalar:** 64-bit mantissa + 8-bit scale factor eliminates floating-point drift ($0.1 + 0.2 = 0.3$ exact, $\$12,685.00$ exact).
4. **Anti-DoS AST Capability Sandbox:** Enforces strict AST budgets ($<200$ nodes, $<15$ nesting levels) and blocks file system, network, eval, and multiplier bomb attacks.
5. **Multi-Target Code Generation:** Compiles a single `.kl` contract into Python Dataclasses, Rust Serde Structs, TypeScript Interfaces, Go Structs, `.klb` zero-copy binary frames with real domain payloads, and W3C WebAssembly (`.wasm`).

---

## 📊 Gold Standard Comparison Tables

### Architectural Feature Matrix

| Feature / Metric | JSON-RPC (MCP) | Python (FastAPI) | Google Protobuf | FlatBuffers | **KL Protocol Engine v10.5** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Domain** | AI Tool Calling | Web Backends | Microservice Wire | Game Buffers | **AI Agent IDL & Wire Protocol** |
| **Deserialization** | Full text scan | Full unpack/alloc | Full unpack required | Zero-copy VTable | **$O(1)$ Tagged VTable Memory Offsets** |
| **Schema Seal** | ❌ None | ❌ None | ❌ None | ❌ None | **✅ 32-Byte SHA-256 Signature Seal** |
| **Numeric Math** | IEEE-754 float | IEEE-754 float | IEEE-754 float | IEEE-754 float | **✅ Fixed-point 64-bit mantissa + scale** |
| **Sandbox VM** | ❌ External | ❌ Open Reflection | ❌ Data only | ❌ Data only | **✅ Anti-DoS AST Capability Sandbox** |
| **Schema Evolution**| Manual JSON | Pydantic model | Field tags | Field tags | **✅ Tag-Based Out-of-Order VTable** |
| **Multi-CodeGen** | Manual JSON | Pydantic | C++, Java, Py, Go | C++, C#, Go, Java | **✅ Python, Rust, TS, Go, OpenAI, MCP, WASM** |

---

## 🛠️ Step-by-Step Implementation & Integration Guide

### Step 1: Compile any `.kl` file to 8 targets
```bash
python kl/cli.py build examples/04_iot_settlement.kl

Output

⚡ [KL Protocol Compiler v10.5] Building 'examples/04_iot_settlement.kl'...
✓ Compilation successful for Schema 'SettlementTransaction':
  • examples/04_iot_settlement_schema.py   (Type-Safe Python Dataclass)
  • examples/04_iot_settlement_schema.rs   (Serde Rust Struct)
  • examples/04_iot_settlement_schema.ts   (TypeScript Interface)
  • examples/04_iot_settlement_schema.go   (Go Struct with Tags)
  • examples/04_iot_settlement_openai.json (OpenAI Function Calling Tool Schema)
  • examples/04_iot_settlement_mcp.json    (Anthropic MCP Tool Schema)
  • examples/04_iot_settlement.klb         (8-Byte Aligned Tagged VTable Frame: 145B - Real Payload)
  • examples/04_iot_settlement.wasm        (W3C Validated Micro-WASM: 62B)

Step 2: Run tests and AI Agent MCP integration demo

# Run formal audit verification suite
python kl/cli.py test

# Run AI Agent Anthropic MCP integration demo
python examples/06_ai_agent_mcp_demo.py
