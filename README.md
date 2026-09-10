<div align="center">
  <img src="assets/logo.png" alt="Tempus DDB" width="180" />

# Tempus DDB

### The B2A (Bot-to-Agent) Security Gate for Autonomous Agent Actions

**Zero-trust authorization · Single-use cryptographic permits · Tamper-evident receipts · MCP native**

<p align="center">
  <a href="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml"><img src="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml/badge.svg" alt="CI Build" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-passing-brightgreen.svg?logo=github" alt="Tests" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/releases"><img src="https://img.shields.io/github/v/release/elbuilder77/tempus-ddb?color=blue&logo=github" alt="GitHub Release" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/pypi/v/tempus-ddb.svg?logo=pypi&logoColor=white&color=blue" alt="PyPI Version" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/pypi/dm/tempus-ddb.svg?color=success" alt="PyPI Downloads" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python&logoColor=white" alt="Python 3.10+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-blue.svg?logo=shield" alt="Security Policy" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/discussions"><img src="https://img.shields.io/badge/community-discussions-orange.svg?logo=github" alt="Community Discussions" /></a>
</p>

---

### ⚡ Quick Install
```bash
pip install tempus-ddb
```

### 🚀 [Try the Live Interactive Trace Demo →](https://elbuilder77.github.io/tempus-ddb/trace.html)
*Verify real cryptographic hashes, Ed25519 signatures, and tamper detection directly in your browser.*

---
</div>

> **Status: beta (`0.5.0` milestone line).** Signed policy, identity lifecycle,
> Vault-backed signing, mediated executor runtime (GitHub, HTTP, Slack, Payment),
> hash-linked event streaming, and signed monotonic checkpoints are implemented.
> Distributed multi-container gate service is in progress (0.6).
>
> [Project site](https://elbuilder77.github.io/tempus-ddb/) ·
> [Integration guide](https://elbuilder77.github.io/tempus-ddb/docs.html) ·
> [Architecture Blueprints](docs/blueprints/README.md) ·
> [Cookbooks](cookbooks/README.md) ·
> [Interactive trace demo](https://elbuilder77.github.io/tempus-ddb/trace.html) ·
> [Roadmap](ROADMAP.md) · [Security](SECURITY.md) ·
> [Threat model](THREAT_MODEL.md) · [Contributing](CONTRIBUTING.md)

---

## 💡 ¿Qué resuelve Tempus? / What Tempus Solves

When autonomous AI agents take actions (calling external APIs, issuing database writes, creating pull requests, moving funds), **they must not approve their own requests or directly hold privileged downstream credentials**.

Tempus DDB creates an enforced **B2A (Bot-to-Agent / Bot-to-Action) Security Boundary**:

1. 🛑 **Zero-Trust Authorization Toll:** The agent cryptographically signs its *intent*. It cannot execute directly.
2. 📜 **Signed, Deterministic Policy:** Tempus evaluates tenant policy and issues an expiring, single-use signed permit (`ALLOWED` or `BLOCKED`).
3. 🔒 **Credential Isolation:** The mediated executor—not the AI agent—holds downstream secrets (e.g. `GITHUB_TOKEN`, API keys) and only executes when presented with a valid, unconsumed permit.
4. 🧾 **Tamper-Evident Receipts:** Both the executor and Tempus gate sign the outcome, generating an immutable, mathematically verifiable cryptographic trace.

> **Product Invariant:** *No Tempus permit, no effect; every effect produces a verifiable receipt.*

---

## ⚔️ Why Tempus vs Traditional RBAC / MCP Gateways?

In 2026, several MCP governance proxies (such as Bifrost, Obot, MCPX, MintMCP) manage agent access using role-based access control (RBAC). **Tempus DDB solves a completely different, deeper architectural problem:**

| Dimension | Traditional MCP Gateways (RBAC / Proxies) | Tempus DDB (B2A Toll Gate) |
|---|---|---|
| **Security Model** | **Authorize & Forward (*"Trust"*):** Checks rules, forwards requests, and trusts the agent and downstream service. | **Cryptographic Toll (*"Zero-Trust"*):** Agent signs intent; Gate issues single-use permit; Executor consumes permit atomically. |
| **Credential Boundary** | Agent or Gateway proxy holds raw API keys and database credentials. | **Strict Credential Isolation:** Agent *never* sees or handles downstream secrets (`GITHUB_TOKEN`, Slack tokens, API keys). |
| **Replay & Loop Prevention** | Advisory rate limits; repeated calls within role permissions pass through. | **Cryptographic Single Consumption:** Consumed permits are permanently invalidated. Replay attempts fail closed. |
| **Tamper Detection** | Server application logs (which can be modified, truncated, or forged). | **Dual-Signed Immutable Receipts:** Cryptographically linked (Ed25519 + SHA-256) and verifiable offline by anyone. |
| **Financial / High-Impact Actions** | Unstructured JSON payloads. | **Universal `money` Contract:** Hard limits, currency enforcement, and tenant-scoped asset ceilings. |

---

## 🔍 Interactive Trace Demo

Inspect how Tempus binds the entire lifecycle (Intent ➔ Authorization ➔ Execution ➔ Receipt) with Ed25519 signatures and SHA-256 state hashes:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TEMPUS B2A PROTOCOL FLOW                          │
├─────────────────┬─────────────────┬───────────────────┬─────────────────────┤
│  01 / INTENT    │  02 / POLICY    │  03 / EXECUTION   │  04 / VERIFICATION  │
│  Agent signs    │  Gate issues    │  Executor verifies│  End-to-end receipt │
│  exact payload  │  single-use     │  permit & acts    │  cryptographically │
│                 │  permit         │  with isolated key│  linked & immutable │
│   [ BOUND ]     │   [ ALLOWED ]   │    [ CONSUMED ]   │    [ VERIFIED ]     │
└────────┬────────┴────────┬────────┴─────────┬─────────┴──────────┬──────────┘
         │                 │                  │                    │
         ▼                 ▼                  ▼                    ▼
   Signed Intent ──► Expiring Permit ──► Execution Receipt ──► Auditable Trace
```

👉 **[Launch Interactive In-Browser Demo](https://elbuilder77.github.io/tempus-ddb/trace.html)** — *Test tamper detection, hash validation, and signature verification live.*

---

The `0.5.0` implementation establishes the local permit protocol, signed policy
bundles, rotation and revocation, unified mediated `ExecutorRuntime` (GitHub, HTTP/Webhooks, Slack, and Pluggable Payments), Vault Transit signing, single-instance replay protection, and cryptographically signed monotonic checkpoints for verifiable disaster recovery. Read
[THREAT_MODEL.md](THREAT_MODEL.md) before relying on the current security boundary.

## What is implemented

- **[Enterprise Architecture & Product Blueprints](docs/blueprints/README.md)**: Production implementation guides for
  [DevOps over MCP (OpenClaw, Hermes Agent, Cursor, Claude, Windsurf)](docs/blueprints/devops-mcp/product-blueprint.md)
  and [Financial Toll Gates for Multi-Agent Crews (CrewAI, LangGraph, AutoGen)](docs/blueprints/payments-crewai/product-blueprint.md).
- Stable machine contracts with explicit `schema_version` values (`.v1`).
- Separate Ed25519 identities for the Tempus gate, requesting agent, and executor.
- Immutable, gate-signed agent registration receipts. Registrations cannot be silently
  overwritten.
- Signed, versioned deterministic policy bundles. Each permit binds its policy digest,
  reproducible evidence digest, closed reason codes, and executor constraints.
- Tenant-scoped delegation, signed key rotation and revocation, historical key-at-time
  verification, and emergency invalidation of unconsumed permits.
- A provider-neutral signer boundary shared by the gate and executor. Local Ed25519 and
  Vault Transit use the same exact-byte contract; provider outages fail closed.
- `ALLOWED` or `BLOCKED` authorization before execution.
- Short-lived permits, deterministic action IDs, and idempotency conflict detection.
- Single-consumption execution receipts; an identical retry is idempotent and a
  conflicting second outcome is rejected.
- End-to-end verification of intent, gate authorization, executor outcome, and receipt
  linkage.
- A unified mediated `ExecutorRuntime` with conformance testing for third-party adapters.
- Signed executor observations for `STARTED`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`, with
  restart recovery that never retries an ambiguous external effect.
- Pre-packaged reference executors for GitHub (`github.create_issue`, `github.create_pull_request`), HTTP/Webhooks, Slack, and Pluggable Payments.
- Money is optional metadata in the same universal action envelope; financial and
  non-financial actions use the same protocol.
- Append-only hash-linked event streams (`tempus.event-stream-event.v1`) and signed monotonic checkpoints (`tempus.checkpoint.v1`) for tamper and rollback detection.
- Disaster recovery and offline reconciliation tooling (`tempus checkpoint create / export / verify`).
- An autonomous MCP surface that hides administrative, legacy, and destructive tools by
  default.

## B2A flow

```text
agent signs intent
        │
        ▼
Tempus request_action ── BLOCKED ──► signed denial trace
        │ ALLOWED
        ▼
single-use, expiring permit
        │
        ▼
executor performs effect and signs outcome
        │
        ▼
Tempus commit_outcome ──► final signed execution receipt
        │
        ▼
human or machine calls verify_trace
```

Tempus becomes an unavoidable toll when the executor exclusively holds the downstream
credential. The packaged GitHub adapter implements that boundary for its supported
actions in a single-instance deployment. Operators must ensure the requesting agent
cannot read the executor's environment or key material.

## Install

Python 3.10 or newer is required.

### 1. From PyPI (Standard & Verified)
Tempus DDB is published to PyPI using **Trusted Publishing (OIDC)** and **Sigstore provenance attestations** on every artifact:
```bash
python -m pip install tempus-ddb
```

### 2. From GitHub Release Wheels & SBOM
Download the pre-built native wheel matching your platform or the SPDX SBOM from [GitHub Releases v0.5.0](https://github.com/elbuilder77/tempus-ddb/releases/tag/v0.5.0):
```bash
pip install ./tempus_ddb-0.5.0-<platform>.whl
```

### 3. From Source (Development)
```bash
git clone https://github.com/elbuilder77/tempus-ddb.git
cd tempus-ddb
pip install -e ".[dev]"
```

## Bootstrap identities

`tempus init` creates the local gate key and database, then records the gate as the
signed delegation root. This is deployment-time bootstrap, not a human approval step
for each action.

```bash
tempus init
tempus keygen --output agent.keys.json
tempus keygen --output executor.keys.json

tempus register-agent --alias purchasing-agent --agent-keyfile agent.keys.json \
  --metadata '{"tenant_id":"acme"}'
tempus register-agent --alias purchasing-executor --agent-keyfile executor.keys.json \
  --metadata '{"tenant_id":"acme"}'
tempus doctor --json
tempus conformance --signer
```

The gate signer configuration is the global `--keyfile` and defaults to `keys.json`.
Production deployments should use the non-secret Vault Transit configuration described
in [docs/VAULT_TRANSIT_SIGNER.md](docs/VAULT_TRANSIT_SIGNER.md); the workload authenticates
to Vault without placing a private key in the file.

## Install a signed policy bundle

Policies define allowed tenants, agents, actions, resources, rate ceilings, minor-unit
currency limits, and authorized executors.

```bash
tempus install-policy --policy acme-github-policy.json
tempus list-policies
```

Policy evaluation is deterministic and rejects unknown constraints, floating-point input,
oversized input, tenant/resource/action mismatches, excessive TTL, disallowed executors,
and money metadata outside the configured currency or minor-unit ceiling.

## Checkpoints & Disaster Recovery

Tempus allows generating cryptographically signed monotonic checkpoints and exporting hash-linked event streams without database downtime:

```bash
# 1. Create a signed monotonic checkpoint for a tenant
tempus checkpoint create --tenant-id acme --out checkpoint-acme.json

# 2. Export the incremental event stream
tempus checkpoint export --tenant-id acme --from-seq 1 --out stream-acme.json

# 3. Cryptographically verify stream integrity and rollback absence offline
tempus checkpoint verify --checkpoint checkpoint-acme.json --stream stream-acme.json
```

See [docs/BACKUP_AND_DISASTER_RECOVERY.md](docs/BACKUP_AND_DISASTER_RECOVERY.md) for complete disaster recovery, hot backup, and reconciliation procedures.

## Python quickstart

```python
import json
import time
from tempus_ddb import TempusDDB, gen_keys

gen_keys("gate.keys.json")
gen_keys("agent.keys.json")
gen_keys("executor.keys.json")

gate = TempusDDB("tempus.db", "gate.keys.json")

with open("gate.keys.json", encoding="utf-8") as handle:
    gate_id = json.load(handle)["public_key"]
with open("agent.keys.json", encoding="utf-8") as handle:
    agent_id = json.load(handle)["public_key"]
with open("executor.keys.json", encoding="utf-8") as handle:
    executor_id = json.load(handle)["public_key"]

gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
gate.register_agent(agent_id, "purchasing-agent", "{}")
gate.register_agent(executor_id, "purchasing-executor", "{}")

intent = json.dumps({
    "schema_version": "tempus.action-intent.v1",
    "tenant_id": "acme",
    "agent_id": agent_id,
    "idempotency_key": "purchase-2026-07-16-001",
    "action_type": "purchase",
    "resource": "vendor-api/compute-credits",
    "requested_at": time.time_ns() // 1_000,
    "input": {"sku": "compute-credits"},
    "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"},
})

authorization = json.loads(gate.request_action(intent, "agent.keys.json", 60))
permit = authorization["authorization"]
assert permit["decision"] == "ALLOWED"

# The executor performs the external effect only after checking the permit.
outcome = json.dumps({
    "schema_version": "tempus.action-outcome.v1",
    "authorization_id": permit["authorization_id"],
    "action_id": permit["action_id"],
    "status": "SUCCEEDED",
    "external_reference": "vendor-tx-9182",
    "output": {"credits_added": 1000},
})

receipt = gate.commit_outcome(
    permit["authorization_id"],
    outcome,
    "executor.keys.json",
)
verification = json.loads(gate.verify_trace(permit["action_id"]))
assert verification["status"] == "VERIFIED"
assert verification["phase"] == "COMPLETED"
```

For remote transports, use `request_action_signed(...)` and
`commit_outcome_signed(...)`. The requesting agent and executor sign locally, so their
private keys and keyfiles never enter the gate process.

## 📚 Cookbooks & Framework Integrations

Explore practical integration recipes in the [cookbooks/](cookbooks/) directory:

- [🦜🔗 **LangChain & LangGraph Guard**](cookbooks/langchain_agent_guard.py) — Wrap sensitive tools (DB writes, payouts) with fail-closed cryptographic permits.
- [👥 **CrewAI Multi-Agent Financial Gate**](cookbooks/crewai_action_gate.py) — Multi-agent delegation where executors require signed gate permits before executing effects.
- [🔌 **Claude Desktop & Cursor MCP Quickstart**](cookbooks/mcp_cursor_claude_quickstart.md) — Connect Tempus DDB as an autonomous Model Context Protocol server in 2 minutes.

```bash
# Run the LangChain guard recipe
python cookbooks/langchain_agent_guard.py

# Run the CrewAI financial gate recipe
python cookbooks/crewai_action_gate.py
```

## Demos and Scenarios

The repository includes runnable end-to-end demonstrations covering security guards, B2A flow, and tamper detection:
Examples create ephemeral databases and keys and remove them when they finish.

### 1. Commercial Demo (`examples/commercial_demo.py`)
Demonstrates the Phase 2 mediated-executor foundation and bypass prevention against a
simulated downstream API.
```bash
python examples/commercial_demo.py
```
**Key checks performed:**
- **Direct Bypass Attempt:** Rejected (agent lacks downstream API secret token).
- **Authorized Execution:** Agent signs intent &rarr; Tempus Gate validates &rarr; Mediated Executor verifies permit &rarr; API executed.
- **Replay Guard:** Re-using a consumed permit is rejected by the Executor.
- **Expiry Guard:** Expired permits are rejected.
- **Tamper Guard:** Altered permit fields invalidate the signature and are rejected.
- **Cross-Tenant Guard:** Permits issued for a different tenant ID are blocked.
- **Trace Verification:** Full cryptographic audit trace verification passes end-to-end.

### 2. Decision Chain Scenario (`examples/decision_chain.py`)
Simulates an autonomous bot lifecycle (Genesis &rarr; Decision 1 &rarr; Decision 2) with chain validation and JSON export:
```bash
python examples/decision_chain.py
```

### 3. CLI Tamper Detection (`examples/tamper_detection_cli.py`)
Demonstrates tamper detection using the Rust CLI by simulating unauthorized modifications to recorded traces:
```bash
python examples/tamper_detection_cli.py
```

### 4. Code Examples (`examples/`)
Additional standalone scripts in `examples/`:
- `examples/basic_record.py`: Basic decision recording.
- `examples/full_agent_flow.py`: Complete multi-agent authorization flow.
- `examples/verify_chain.py`: Cryptographic chain verification.

```bash
python examples/full_agent_flow.py
```

## Packaged Mediated Executors

Tempus includes four official, credential-isolated executors out of the box. The requesting AI agent *never* holds downstream API keys or secrets.

### 1. GitHub Executor (`tempus-github-executor`)
Performs audited GitHub REST writes with an isolated `GITHUB_TOKEN`:
- `github.create_issue`: `owner/repository` with allowlisted `title`, `body`, `labels`.
- `github.create_pull_request`: `owner/repository` with allowlisted `title`, `head`, `base`, `body`, `draft`.

```bash
tempus-github-executor \
  --permit permit.json \
  --executor-db github-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme
```

### 2. HTTP & Webhook Executor (`tempus-http-executor`)
Executes HTTPS POST/PUT webhooks and external API mutations while isolating authorization headers:
- Supported actions: `http.post`, `http.put`, `webhook.send`.

```bash
tempus-http-executor \
  --permit permit.json \
  --executor-db http-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --auth-header "Bearer <isolated-api-secret>"
```

### 3. Slack Executor (`tempus-slack-executor`)
Dispatches channel alerts and notifications while isolating `SLACK_BOT_TOKEN`:
- Supported actions: `slack.post_message`, `slack.send_alert`.

```bash
tempus-slack-executor \
  --permit permit.json \
  --executor-db slack-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --token "xoxb-<isolated-slack-bot-token>"
```

### 4. Pluggable Financial Adapter (`tempus-payment-executor`)
Reference pluggable executor that enforces the universal `money` envelope (`amount`, `asset`, `beneficiary`) and minor-unit limits with credential isolation:
- Supported actions: `finance.disburse`, `finance.transfer`, `payment.charge`.
- **Bring Your Own Provider:** Implements a pluggable `PaymentTransport` interface. Shipped with a deterministic mock transport for verification and testing; plug in your real Stripe/Wise API client at the transport boundary without exposing payment keys to the AI agent.

```bash
tempus-payment-executor \
  --permit permit.json \
  --executor-db pay-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --secret-key "sk_live_<isolated-payment-key>"
```

## Performance Benchmarks

Tempus DDB includes a benchmarking tool to evaluate transaction throughput and validation latency:

```bash
python examples/benchmark.py --records 1000
```

To output machine-readable JSON:
```bash
python examples/benchmark.py --records 1000 --json
```

**Optimizations active in v0.2.1+:**
- SQLite Write-Ahead Logging (`WAL` mode) with `PRAGMA synchronous = NORMAL` and `busy_timeout = 5000`.
- In-memory key caching to prevent disk I/O bottlenecks during hot-path transactions.
- Max LTO release compilation (`opt-level = 3`, `lto = true`, `codegen-units = 1`).

## Stable contracts

| Contract | Schema |
|---|---|
| Agent intent | `tempus.action-intent.v1` |
| Authorization response | `tempus.authorization-result.v1` |
| Signed permit | `tempus.authorization-receipt.v1` |
| Signed deterministic policy | `tempus.policy-bundle.v1` |
| Policy evidence | `tempus.policy-evidence.v1` |
| Identity lifecycle event | `tempus.identity-lifecycle-event.v1` |
| Executor outcome | `tempus.action-outcome.v1` |
| Execution response | `tempus.execution-result.v1` |
| Signed execution receipt | `tempus.execution-receipt.v1` |
| Executor state observation | `tempus.executor-observation.v1` |
| Complete trace | `tempus.action-trace.v1` |
| Verification result | `tempus.trace-verification.v1` |

Authorization decisions are `ALLOWED` or `BLOCKED`. Execution outcomes are `SUCCEEDED`
or `FAILED`. Executor observations are `STARTED`, `SUCCEEDED`, `FAILED`, or `UNKNOWN`.
Trace verification is `VERIFIED` or `INVALID`.

Phase 3 fields are additive to the v1 authorization contracts. Executors require and
verify them, while historical Phase 2 receipts keep their original signature semantics.
See [COMPATIBILITY.md](COMPATIBILITY.md) for support/deprecation rules and
[MIGRATION_0.4.md](MIGRATION_0.4.md) for the `0.3.x` upgrade procedure.

## MCP autonomous mode

The default MCP surface exposes only machine-to-machine execution and read-only audit
operations. The agent and executor must sign their own payloads; the gate never receives
their keyfile paths:

| Tool | Purpose |
|---|---|
| `tempus_request_action_signed` | Verify a locally signed intent and obtain a signed, expiring permit |
| `tempus_commit_outcome_signed` | Consume a permit with an executor-signed result |
| `tempus_get_trace` | Read authorization and execution evidence |
| `tempus_verify_trace` | Verify the complete action trace |
| `tempus_list_agents` | Read signed agent identities |
| `tempus_list_policies` | Read active and retired signed policy bundles |
| `tempus_list_identity_events` | Read signed rotation and revocation events |

Configuration:

```json
{
  "mcpServers": {
    "tempus": {
      "command": "tempus",
      "args": ["mcp", "start"],
      "env": {
        "TEMPUS_MODE": "autonomous",
        "TEMPUS_GATE_KEYFILE": "keys.json"
      }
    }
  }
}
```

Provisioning should run separately from the agent-facing MCP process. The following
flags are deliberately off by default:

| Flag | Unlocks |
|---|---|
| `TEMPUS_ADMIN_TOOLS=1` | init, key generation, signed agent registration, whoami |
| `TEMPUS_LEGACY_TOOLS=1` | old voluntary `record`, list, export, count, validate tools |
| `TEMPUS_DESTRUCTIVE_TOOLS=1` | demo-only cleanup |
| `TEMPUS_LOCAL_KEYFILE_TOOLS=1` | development-only `tempus_request_action` and `tempus_commit_outcome` tools that accept local keyfile paths |

## Human audit

Humans are readers, not approvers:

```bash
tempus trace --action-id <action-id>
tempus verify-trace --action-id <action-id>
tempus list-agents
tempus list-policies
tempus identity-events
```

The public [trace demo](https://elbuilder77.github.io/tempus-ddb/trace.html) is a
synthetic, browser-only illustration of hashes, signatures and record binding. A future
read-only audit console must derive its views from these contracts; it is not in the
current source line.

## Legacy ledger

The original `record`, `validate`, `list`, `count`, and `export` interfaces remain for
compatibility and migration. They are a voluntary flight recorder and do not enforce
the B2A toll. New autonomous integrations should use the signed action authorization
flow; local keyfile MCP tools are development compatibility only.

## Security boundary

This implementation detects receipt, policy, evidence, and trace alteration; rejects
unregistered or revoked actors; prevents conflicting idempotent requests; and prevents
two outcomes from consuming one permit. It does not yet prevent deletion or rollback of
the entire local database, nor bypass by an agent that still possesses downstream
credentials. Read [THREAT_MODEL.md](THREAT_MODEL.md)
before using Tempus for high-impact production actions.

## Roadmap

The next release line focuses on large-ledger streaming, durable receipt events,
independent rollback detection, and operating procedures. See [ROADMAP.md](ROADMAP.md)
for milestones and explicit exit criteria.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, security reporting, and pull-request
requirements. The complete local verification set is:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
ruff check .
pytest -p no:cacheprovider
python -m maturin build
```

## License

MIT. See [LICENSE](LICENSE).
