# ⚡ KL (`.kl`) - Universal AI Agent Protocol & Industrial IDL (v10.5)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Specification Audit](https://img.shields.io/badge/Specification%20Audit-13%2F13%20Passed-brightgreen.svg)]()
[![Fuzz Resilience](https://img.shields.io/badge/Fuzzing-50k%20Zero%20Fault-purple.svg)]()
[![WASM Micro Core](https://img.shields.io/badge/WASM-62%20Bytes%20(W3C%20Valid)-success.svg)]()
[![Multi-Target CodeGen](https://img.shields.io/badge/Code%20Gen-Py%20%7C%20Rust%20%7C%20TS%20%7C%20Go-orange.svg)]()

> **KL (`.kl`)** is an industrial Interface Definition Language (IDL), 8-byte aligned tagged VTable wire protocol, and sandboxed AI action execution engine. It is engineered specifically for **Autonomous AI Agents, Anthropic Model Context Protocol (MCP) Tools, OpenAI Function Calling, LangChain, and Zero-Trust Cloud Microservices**.

---

## 📜 Evolutionary Journey (From v1.0 to v10.5 Protocol Standard)

| Version Range | Core Architecture & Feature Focus | Key Attributes & Capabilities |
| :--- | :--- | :--- |
| **v1.0 – v8.0** | Dynamic Scripting | Unsafe Heap Alloc |
| **v9.0 – v9.1** | Action VM & Codec | Fixed Offsets & Seals |
| **v10.0 – v10.5** | AI Agent Protocol IDL | MCP & Multi-Target |



* **v1.0 – v8.0 (Experimental Phase):** Early dynamic scripting engine. Suffered from heap allocation overhead, floating-point precision drift, and unbounded execution risks.
* **v9.0 – v9.1 (VTable & Action VM Phase):** Introduced 8-byte word alignment, 32-byte cryptographic SHA-256 schema seals, and the AST Capability Sandbox (`KLSandboxValidator`).
* **v10.0 – v10.5 (Industrial Protocol Standard):** Refactored KL into a **Specialized IDL and Wire Protocol (Path A)** for AI Agents and Microservices. Added fixed-point `Decimal` scalars, `Optional<T>`, `List<T>`, `Map<K,V>`, multi-language code generators (Python, Rust, TypeScript, Go), OpenAI Function Calling exports, Anthropic MCP adapters, 1-line LangChain tools (`kl/frameworks.py`), and a fast JSON/REST transcoder gateway.

---

## 🌟 Why KL? (Solving the AI Agent Security & Serialization Crisis)

Modern LLM tool calling and microservice architectures face critical bottlenecks:
* **The AI Injection Hazard:** Executing untrusted LLM tool calls directly in Python or Node.js risks remote code execution (RCE) and system crashes.
* **Serialization & Token Bloat:** Plain-text JSON payloads waste 60%–75% of network bandwidth re-transmitting field keys on every call and inflating LLM context tokens.
* **IEEE-754 Precision Drift:** Standard JSON floating-point numbers distort financial and billing transactions ($0.1 + 0.2 = 0.30000000000000004$).

**KL addresses all three challenges natively:**
1. **Anti-DoS AST Capability Sandbox:** Enforces strict AST node budgets ($<200$ nodes, $<15$ nesting levels) and blocks file system, network, eval, and multiplier bomb RCE attacks.
2. **Tag-Based VTable Codec:** Uses Protobuf-style `@1`, `@2` field tags with 8-byte aligned memory offsets, allowing forward/backward schema evolution without breaking legacy readers.
3. **Native Fixed-Point `Decimal` Scalar:** 64-bit mantissa + 8-bit scale factor eliminates floating-point drift ($0.1 + 0.2 = 0.3$ exact, $\$12,685.00$ exact).
4. **Multi-Target Code Generation:** A single `.kl` file compiles into Python Dataclasses, Rust Serde Structs, TypeScript Interfaces, Go Structs, `.klb` zero-copy binary frames with real domain payloads, and W3C WebAssembly (`.wasm`).

---

## 📖 Language Keywords & Complete Grammar Reference

KL uses a strict, deterministic syntax designed for high-speed compilation, human readability, and safe execution.

| Keyword | Category | Functional Purpose & Behavior |
| :--- | :--- | :--- |
| `SCHEMA` | Declaration | Defines an immutable, tag-numbered data structure (e.g. `@1 id: String`). |
| `ACTION` | Execution | Defines a sandboxed function executing sequential `GUARD`, `LET`, and `RETURN` logic. |
| `GUARD` | Verification | Pre-execution boundary check evaluated before action logic. |
| `ELSE FAIL` | Exception | Aborts execution with a machine-readable error code (e.g. `FAIL(UnauthorizedOrigin, "Msg")`). |
| `LET` | Binding | Binds an immutable local variable within an action execution scope. |
| `RETURN` | Output | Evaluates and returns a schema object, scalar value, or boolean result. |

### Built-in Native Types
* `String`: UTF-8 dynamic text with 32-bit unsigned length prefix (`<I`).
* `Int`: 64-bit signed little-endian integer (`<q`).
* `Float`: 64-bit IEEE-754 double-precision float (`<d`).
* `Bool`: 8-bit single-byte boolean flag (`0x01` / `0x00`).
* `Decimal`: Fixed-point scalar with 64-bit mantissa (`<q`) + 8-bit scale factor (`<B`).
* `Optional<T>`: Absent values represented by zeroed offset sentinels (`0x00000000`).
* `List<T>`: Homogeneous list descriptor.
* `Map<K, V>`: Tagged key-value map descriptor.

---

## 🏗️ Architecture & Target Output Matrix

Compiling a `.kl` contract (`python kl/cli.py build contract.kl`) generates **8 production target artifacts**:

| Generated Target File | Target Audience / Use Case |
| :--- | :--- |
| **`contract_schema.py`** | Type-safe Python Dataclass with native binary packing/unpacking helpers. |
| **`contract_schema.rs`** | Serde-compatible Rust `struct` definition for high-performance systems. |
| **`contract_schema.ts`** | TypeScript Interface definition with field tag documentation. |
| **`contract_schema.go`** | Go `struct` definition with field tags (`json:"..." kl:"@1"`). |
| **`contract_openai.json`** | Valid OpenAI Function Calling Tool Schema for GPT-4/GPT-3.5 tools. |
| **`contract_mcp.json`** | Valid Anthropic Model Context Protocol (MCP) tool definition for Claude agents. |
| **`contract.klb`** | 8-byte aligned tagged VTable binary frame with 32-byte SHA-256 cryptographic seal. |
| **`contract.wasm`** | W3C-compliant WebAssembly bytecode for sub-microsecond edge guard evaluation. |

---

## 📊 Industry Benchmark Comparison

| Metric / Feature | JSON-RPC (MCP) | Python (FastAPI) | Google Protobuf | **KL Protocol Engine v10.5** |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Text tool calling | Dynamic web apps | Wire serialization | **AI Agent IDL & Wire Protocol** |
| **Deserialization Paradigm**| Full text scan | Full unpack/alloc | Full unpack required | **$O(1)$ Tagged VTable Offsets** |
| **Cryptographic Schema Seal**| ❌ None | ❌ None | ❌ None | **✅ 32-Byte SHA-256 Signature Seal** |
| **Numeric Precision** | IEEE-754 floats | IEEE-754 floats | IEEE-754 floats | **✅ Fixed-point 64-bit mantissa + scale** |
| **Action Execution Runtime**| ❌ External | ❌ Dynamic | ❌ Data schema only | **✅ Anti-DoS Sandboxed Action VM** |
| **Schema Evolution** | Manual parsing | Pydantic model | Field tags | **✅ Tag-Based Out-of-Order VTable** |
| **Code Generation** | Manual JSON | Pydantic | C++, Java, Py, Go | **✅ Python, Rust, TS, Go, OpenAI, MCP, WASM** |

---

## 🔬 Empirical Verification & Fuzz Audit Results

The KL v10.5 protocol engine was subjected to 50,000 corrupted payload fuzzing packets and high-throughput execution audits:

```text
================================================================================
           KL v10.5 INDUSTRIAL ADVERSARIAL STRESS & FUZZ TEST SUITE           
================================================================================

[TIER 1] 50,000 PACKET ADVERSARIAL FUZZING (BYTE MUTATION & BIT FLIPS)
  * Packets Fuzzed: 50,044
  * Safe Traps & Interceptions: 50,044 / 50,044 (100.00% safe handling)

[TIER 2] SCHEMA EVOLUTION & COMPATIBILITY STRESS
  * Out-of-order tag resolution: PASSED
  * Forward Compatibility (v1 reader skipping tag 6): PASSED
  * Backward Compatibility (missing optional tag 5 returns None): PASSED

[TIER 3] DECIMAL FIXED-POINT PRECISION STRESS
  * IEEE-754 Precision Fix (0.1d + 0.2d == 0.3d): PASSED
  * Complex Billing Calculation ($12,685.00 exact): PASSED

[TIER 4] HIGH-THROUGHPUT LOAD & HEAP ALLOCATION TEST (100,000 ITERATIONS)
  * Serialized & Executed 100,000 frames in 4.908 seconds
  * Throughput Rate: 20,377 frames/sec (Python runtime)
  * GC Overhead / Memory Leak Check: CLEAN (0 growth, <0.033 MB peak heap)

================================================================================
STRESS TEST AUDIT VERDICT: 100% SUCCESSFUL (0 CRASHES / 0 DRIFT / 0 LEAKS)
================================================================================

💻 Cross-Domain Code Examples & AI Tool Integration
1. 1-Line LangChain AI Agent Tool Wrapper (kl/frameworks.py)
python


from kl.frameworks import KLLangChainTool
# Wrap any KL contract into a sandboxed LangChain tool in 1 line
lc_tool = KLLangChainTool(kl_contract_source)
result = lc_tool.run(account_id="acc_100", amount="1000.00", fee_rate="0.05", authorized=True)
print(result) # {'status': 'SUCCESS', 'result': '950.00'}
2. End-to-End AI Agent Tool Execution (examples/06_ai_agent_mcp_demo.py)
python


from kl.engine import KLCompiler
from kl.agent_bridge import KLAgentBridge
from kl.gateway import KLGateway
# 1. Parse KL Contract
parsed = KLCompiler.parse_kl_source(contract_code)
# 2. Export Anthropic MCP Tool Definition
mcp_tool = KLAgentBridge.export_mcp_tool_definition(parsed)
# 3. Process LLM Tool Invocation via JSON Gateway Transcoder
raw_llm_json = {
    "account_id": "acc_100",
    "amount": "1000.00",
    "fee_rate": "0.05",
    "authorized": True
}
klb_bytes, result = KLGateway.process_json_action(parsed, raw_llm_json)
print(result) # {'status': 'SUCCESS', 'result': '950.00'}


```🚀 Getting Started & CLI Commands
Installation
bash
git clone https://github.com/Karthik8639-collab/KL-Lang.git
cd KL-Lang

CLI Toolchain Execution
bash

# 1. Run the 13-point formal specification audit suite
python kl/cli.py test
# 2. Build any .kl contract into Python, Rust, TS, Go, OpenAI, MCP, .klb, and .wasm
python kl/cli.py build examples/01_ai_guard.kl
# 3. Run the AI Agent Anthropic MCP & Gateway Transcoder demo
python examples/06_ai_agent_mcp_demo.py


📄 License
This project is open-source and licensed under the Apache License 2.0.
