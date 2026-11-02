# Tempus DDB reference

The complete operator and integrator reference: identities, policies, the CLI flow,
checkpoints, the Python API, executors, MCP, independent verification and upgrade notes.
The short, evidence-first introduction is the [README](../README.md); the protocol is
specified in [SPEC.md](../SPEC.md); the comparison with MCP gateways is in
[COMPARISON.md](COMPARISON.md).

## 💡 ¿Qué resuelve Tempus? / What Tempus Solves

When autonomous AI agents take actions (calling external APIs, issuing database writes, creating pull requests, moving funds), **they must not approve their own requests or directly hold privileged downstream credentials**.

Tempus DDB creates an enforced **B2A (Bot-to-Agent / Bot-to-Action) Security Boundary**:

1. 🛑 **Zero-Trust Authorization Toll:** The agent cryptographically signs its *intent*. It cannot execute directly.
2. 📜 **Signed, Deterministic Policy:** Tempus evaluates tenant policy and issues an expiring, single-use signed permit (`ALLOWED` or `BLOCKED`).
3. 🔒 **Credential Isolation:** The mediated executor—not the AI agent—holds downstream secrets (e.g. `GITHUB_TOKEN`, API keys) and only executes when presented with a valid, unconsumed permit.
4. 🧾 **Tamper-Evident Receipts:** Both the executor and Tempus gate sign the outcome, generating an immutable, mathematically verifiable cryptographic trace.

> **Product Invariant:** *No Tempus permit, no effect; every effect produces a verifiable receipt.*

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

👉 **[Launch Interactive In-Browser Demo](https://tempus-protocol.github.io/tempus-ddb/trace.html)** — *Test tamper detection, hash validation, and signature verification live.*

---

The `0.6.0` implementation establishes the local permit protocol, signed policy
bundles, rotation and revocation, unified mediated `ExecutorRuntime` (GitHub, HTTP/Webhooks, Slack, and Pluggable Payments), Vault Transit signing, single-instance replay protection, and cryptographically signed monotonic checkpoints for verifiable disaster recovery. Read
[THREAT_MODEL.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/THREAT_MODEL.md) before relying on the current security boundary.

## What is implemented

- **[Enterprise Architecture & Product Blueprints](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/blueprints/README.md)**: Production implementation guides for
  [DevOps over MCP (OpenClaw, Hermes Agent, Cursor, Claude, Windsurf)](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/blueprints/devops-mcp/product-blueprint.md)
  and [Financial Toll Gates for Multi-Agent Crews (CrewAI, LangGraph, AutoGen)](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/blueprints/payments-crewai/product-blueprint.md).
- Stable machine contracts with explicit `schema_version` values (`.v1`).
- Separate Ed25519 identities for the Tempus gate, requesting agent, and executor.
- Immutable, gate-signed agent registration receipts. Registrations cannot be silently
  overwritten.
- Signed, versioned deterministic policy bundles. Each permit binds its policy digest,
  reproducible evidence digest, closed reason codes, and executor constraints.
- Tenant-scoped delegation, signed key rotation and revocation, historical key-at-time
  verification, and emergency invalidation of unconsumed permits.
- A provider-neutral signer boundary shared by the gate and executor. Local Ed25519 and
  Vault Transit use the same exact-byte contract; a signing timeout, error, unexpected key version or signature that does not verify aborts the operation and no receipt is issued.
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
- An autonomous MCP surface that hides administrative and destructive tools by default
  and never accepts a private-key path from a client.
- A public browser verifier (the wasm32 build of the core) and a `verify_url` in every
  signed receipt and exported bundle.

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
Download the pre-built native wheel matching your platform or the SBOM files from [GitHub Releases](https://github.com/tempus-protocol/tempus-ddb/releases). Releases cut by the tag workflow attach an SPDX SBOM and CycloneDX SBOMs for Rust and Python. Verify them with the commands in [docs/RELEASING.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/RELEASING.md).
```bash
pip install ./tempus_ddb-0.6.0-<platform>.whl
```

### 3. From Source (Development)

Building from source compiles the Rust extension, so you need a **Rust toolchain**
(minimum supported version `rust-version = "1.88"`, see `Cargo.toml`; the repository
pins `1.99.1` in `rust-toolchain.toml`, which `rustup` installs for you on first build)
plus a C linker (`build-essential` / Xcode command line tools / MSVC build tools).
The PyPI and release wheels above need no Rust.

```bash
# Install Rust once (https://rustup.rs), then reopen your shell or: . "$HOME/.cargo/env"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/tempus-protocol/tempus-ddb.git
cd tempus-ddb
pip install -e ".[dev]"      # builds the extension with maturin; takes a few minutes
tempus --version
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
tempus conformance --signer
# Next: install a policy (below). Until then the gate denies every action and
# `tempus doctor --json` reports `active_policy: FAIL`.
```

The gate signer configuration is the global `--keyfile` and defaults to `keys.json`.
Production deployments should use the non-secret Vault Transit configuration described
in [docs/VAULT_TRANSIT_SIGNER.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/VAULT_TRANSIT_SIGNER.md); the workload authenticates
to Vault without placing a private key in the file.

## Install a signed policy bundle

**Default-deny.** A gate with no installed policy denies every action: the signed
receipt is `BLOCKED` with the reason code `POLICY_NOT_INSTALLED`. Nothing is seeded by
`tempus init`, by the first registration, or when the database is reopened, and a
tenant without its own policy is denied as well. Install a policy before expecting any
`ALLOWED` receipt.

Policies define allowed tenants, agents, actions, resources, rate ceilings, minor-unit
currency limits, and authorized executors.

Write a policy for your tenant, naming the executor identity you registered above (the
`public_key` field of `executor.keys.json`), then install it:

```bash
EXECUTOR_PUB=$(python -c "import json; print(json.load(open('executor.keys.json'))['public_key'])")
cat > acme-github-policy.json <<EOF
{
  "schema_version": "tempus.policy-bundle.v1",
  "policy_version": "acme-github-v1",
  "tenant_id": "acme",
  "constraints": {
    "allowed_action_types": ["github.create_issue", "github.create_pull_request"],
    "allowed_resources": ["acme/*"],
    "allowed_executors": ["$EXECUTOR_PUB"],
    "max_ttl_seconds": 60,
    "max_input_bytes": 16384,
    "allowed_currencies": ["USD"]
  }
}
EOF

tempus install-policy --policy acme-github-policy.json
tempus list-policies
```

The same template ships as `config/policy.github.example.json` in the source tree, with a
`REPLACE_WITH_EXECUTOR_ED25519_PUBLIC_KEY` placeholder that you must replace;
`install-policy` refuses a file that still contains a `REPLACE_WITH_` placeholder.

### Local development only: `--allow-all-dev`

To try the flow without writing a policy, opt in explicitly. This installs a signed
policy that **allows every action, resource and executor** for every tenant without its
own policy. It does not set `allowed_currencies`, so it does not constrain currency.
The CLI prints a warning, `tempus doctor` reports `active_policy: FAIL`
while it is active, and every receipt carries the `tempus.dev-allow-all.v1.*`
`policy_version`. Never use it in production.

```bash
tempus init --allow-all-dev            # or, on an existing gate:
tempus install-policy --allow-all-dev
```

Equivalents: `TempusDDB.install_allow_all_dev_policy()` (Python, emits a `UserWarning`),
`SqliteStorage::install_allow_all_dev_policy()` and
`tempus-ddb-core install-allow-all-dev` (Rust). It is not exposed through MCP, so an
agent cannot switch the gate to allow-all. Installing a real policy for the same
tenant `*` later replaces it; a gate whose active `*` policy is not the dev one refuses
`--allow-all-dev` (`TEMPUS_DEV_ALLOW_ALL_REFUSED`).

Upgrading: a database seeded by an older gate still contains `tempus.baseline.v1`.
It is now ignored (the gate denies). Install a real policy, or opt in with
`--allow-all-dev` for development. A dev allow-all policy stored with a non-exact
`allowed_currencies` list fails closed (`TEMPUS_POLICY_INVALID`) and the gate leaves
that signed row unchanged. Run `tempus install-policy --allow-all-dev` (or
`TempusDDB.install_allow_all_dev_policy()`) to replace it. Until then it is not allowed.

Policy evaluation is deterministic and rejects unknown constraints, floating-point input,
oversized input, tenant/resource/action mismatches, excessive TTL, disallowed executors,
and money metadata outside the configured currency or minor-unit ceiling. Currency
allowlists are exact codes (`USD`). Payment actions
(`finance.disburse`, `finance.transfer`, `payment.charge`) require a `money` object and
a non-zero amount.

## End-to-end from the CLI

The whole B2A cycle without Python, continuing from the policy installed above (tenant
`acme`, `agent.keys.json`, `executor.keys.json`). Run it in the directory where you ran
`tempus init`.

```bash
# 1. The agent's signed intent. `requested_at` is microseconds since the Unix epoch.
AGENT_PUB=$(python -c "import json; print(json.load(open('agent.keys.json'))['public_key'])")
cat > intent.json <<EOF
{
  "schema_version": "tempus.action-intent.v1",
  "tenant_id": "acme",
  "agent_id": "$AGENT_PUB",
  "idempotency_key": "issue-2026-001",
  "action_type": "github.create_issue",
  "resource": "acme/widgets",
  "requested_at": $(python -c "import time; print(time.time_ns() // 1000)"),
  "input": {"title": "Rotate the staging key", "body": "Opened through Tempus."}
}
EOF

# 2. request-action: the gate evaluates the policy and prints the permit
#    (`tempus.authorization-result.v1`, ALLOWED or a signed BLOCKED denial).
#    This file is the `permit.json` the packaged executors consume.
tempus request-action --intent intent.json --agent-keyfile agent.keys.json \
  --ttl-seconds 60 > permit.json
AUTH_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['authorization_id'])")
ACTION_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['action_id'])")
python -c "import json; print(json.load(open('permit.json'))['authorization']['decision'])"   # ALLOWED

# 3. The executor performs the effect (see "Packaged Mediated Executors"), then the
#    outcome it reports is committed to the gate, signed with the executor key.
#    Here the outcome is written by hand to keep the walkthrough offline.
cat > outcome.json <<EOF
{
  "schema_version": "tempus.action-outcome.v1",
  "authorization_id": "$AUTH_ID",
  "action_id": "$ACTION_ID",
  "status": "SUCCEEDED",
  "external_reference": "acme/widgets#17"
}
EOF
tempus commit-outcome --authorization-id "$AUTH_ID" --outcome outcome.json \
  --executor-keyfile executor.keys.json > execution.json

# 4. Verify against the gate public key you pinned out of band (no trust in the database)
GATE_PUB=$(python -c "import json; print(json.load(open('keys.json'))['public_key'])")
tempus trace --action-id "$ACTION_ID" > receipt.json
tempus verify-receipt --receipt receipt.json --gate-public-key "$GATE_PUB" \
  --require-decision ALLOWED --require-execution
tempus verify-trace --action-id "$ACTION_ID" --gate-public-key "$GATE_PUB" --strict \
  --require-decision ALLOWED --require-execution

# 5. One self-contained file for an auditor, verified with only that file and the key
tempus export-bundle --action-id "$ACTION_ID" --out evidence.json --create-checkpoint
tempus verify-bundle --bundle evidence.json --gate-public-key "$GATE_PUB" \
  --require-decision ALLOWED --require-execution --require-checkpoint
```

`request-action` signs the intent with `--agent-keyfile` before the gate sees it. A policy that does not allow the intent still produces a permit file,
with `"decision": "BLOCKED"` and reason codes; it is a signed denial and no executor will
act on it. See *Independent verification* below for what the verify commands do and do
not prove.

## Checkpoints & Disaster Recovery

Tempus allows generating cryptographically signed monotonic checkpoints and exporting hash-linked event streams without database downtime:

```bash
# 1. Create a signed monotonic checkpoint for a tenant
tempus checkpoint create --tenant-id acme --out checkpoint-acme.json

# 2. Export the incremental event stream
tempus checkpoint export --tenant-id acme --from-seq 1 --out stream-acme.json

# 3. Cryptographically verify stream integrity and rollback absence offline.
#    Pin the gate public key: without it the check is NOT independent.
tempus checkpoint verify --checkpoint checkpoint-acme.json --stream stream-acme.json \
    --gate-public-key <gate-public-key-hex|file>
```

See [docs/BACKUP_AND_DISASTER_RECOVERY.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/docs/BACKUP_AND_DISASTER_RECOVERY.md) for complete disaster recovery, hot backup, and reconciliation procedures.

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

# Default-deny: without an installed policy every request is BLOCKED
# (POLICY_NOT_INSTALLED). Install a signed policy for the tenant first.
gate.install_policy(json.dumps({
    "schema_version": "tempus.policy-bundle.v1",
    "policy_version": "acme-purchasing-v1",
    "tenant_id": "acme",
    "constraints": {
        "allowed_action_types": ["purchase"],
        "allowed_resources": ["vendor-api/*"],
        "allowed_executors": [executor_id],
        "max_ttl_seconds": 60,
        "max_input_bytes": 16384,
        "allowed_currencies": ["USD"],
        "max_money_amount_minor": 5000,
    },
}))
# Development shortcut only: gate.install_allow_all_dev_policy() allows everything.

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

Explore practical integration recipes in the [cookbooks/](https://github.com/tempus-protocol/tempus-ddb/tree/main/cookbooks) directory:

- [🦜🔗 **LangChain & LangGraph Guard**](https://github.com/tempus-protocol/tempus-ddb/blob/main/cookbooks/langchain_agent_guard.py) — Wrap sensitive tools (DB writes, payouts) so they run only with a signed, single-use permit.
- [👥 **CrewAI Multi-Agent Financial Gate**](https://github.com/tempus-protocol/tempus-ddb/blob/main/cookbooks/crewai_action_gate.py) — Multi-agent delegation where executors require signed gate permits before executing effects.
- [🔌 **Claude Desktop & Cursor MCP Quickstart**](https://github.com/tempus-protocol/tempus-ddb/blob/main/cookbooks/mcp_cursor_claude_quickstart.md) — Connect Tempus DDB as an autonomous Model Context Protocol server in 2 minutes.

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

### 2. Code Examples (`examples/`)
Additional standalone scripts in `examples/`:
- `examples/full_agent_flow.py`: Complete multi-agent authorization flow.

```bash
python examples/full_agent_flow.py
```

## Mediated Executors

The requesting AI agent *never* holds downstream API keys or secrets. Since 0.7 the wheel
ships one executor, `tempus-github-executor`, as the conformance reference for the
`ActionAdapter` protocol; the product executor for GitHub is
[Tempus Guard for GitHub](https://github.com/tempus-protocol/tempus-github-app)
(`tempus-github-app`), which adds permit-bound pushes and the "Verified by Tempus" check.
The HTTP, Slack and payment executors live in this repository under
[`contrib/executors/`](../contrib/executors/README.md) as the unpublished distribution
`tempus-executors-contrib` (`pip install -e contrib/executors`); their commands and options
are unchanged and documented below.

**Where `permit.json` comes from.** It is the output of `tempus request-action` (see
*End-to-end from the CLI*): `tempus request-action --intent intent.json --agent-keyfile
agent.keys.json > permit.json`. `--gate-id` is the gate's public key (the `public_key`
in the gate's `keys.json`, also printed by `tempus whoami`), `--tenant-id` must match the
permit's tenant, and `--executor-keyfile` must be the identity that the policy lists in
`allowed_executors`. The executor verifies the permit, consumes it once in its own
`--executor-db` (a second run of the same permit is refused), performs the action with the
credential only it holds, and prints its signed result. Reporting that outcome to the gate
(so it appears in the trace) is the separate `tempus commit-outcome` step, as the cookbooks
do. An expired permit (`--ttl-seconds`) or a `BLOCKED` one is rejected.

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

### 2. HTTP & Webhook Executor (`tempus-http-executor`, contrib)
Executes HTTPS POST/PUT webhooks and external API mutations while isolating authorization headers:
- Supported actions: `http.post`, `http.put`, `webhook.send`.

```bash
tempus-http-executor \
  --permit permit.json \
  --executor-db http-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --allowed-domains api.example.com \
  --auth-header "Bearer <isolated-api-secret>"
```

- **Credentials need an allowlist.** The `Authorization` header is added to every request,
  so the executor refuses to start with `--auth-header` (or `HTTP_EXECUTOR_AUTH_HEADER`)
  unless `--allowed-domains` / `allowed_domains` / `HTTP_EXECUTOR_ALLOWED_DOMAINS` names the
  hosts that may receive it (`*` accepts every host, explicitly). Pattern matching now
  respects component boundaries: an entry matches that host only, and `*.domain` matches
  labels under that domain but not the apex. An exact host does not include its subdomains.
  A `*` glued to text matches nothing.
- **Policy patterns match whole components.** `allowed_resources`, `allowed_action_types`,
  `allowed_executors`, `allowed_currencies` and `allowed_beneficiaries` split on `/` and `.`.
  A `*` matches only as a whole component, so a path pattern such as `https://api.example.com/*`
  or `acme/*` covers what follows that separator, and `*.domain` covers labels under that
  domain. A `*` glued to the surrounding text matches nothing.
  `tempus install-policy` prints a WARNING for `http(s)` patterns with no `/` before the `*`.
- **Ports are not restricted by the allowlist** (`:8443` on an allowed host is still allowed).
  A policy pattern matches the URL text, so a pattern without the port does not match a URL
  that includes one. Pin the port in the pattern when it matters
  (`https://api.example.com:8443/*`).
- **No `.`/`..` path segments**, plain or percent-encoded (`%2e%2e`, `%252e%252e`, `..%2f`),
  and no backslashes: the policy matches the URL *text*, so `/v1/../admin` would pass
  `https://api.example.com/v1/*` while the server serves `/admin`.
- **The SSRF filter is a guard, not complete protection.** It refuses `localhost`
  names, and any host that is or resolves to a loopback, private, link-local, CGNAT,
  unspecified, multicast or reserved address or a known cloud-metadata address, in any
  spelling (`127.1`, `2130706433`, `0x7f000001`, `[::ffff:127.0.0.1]`, ...). The name is
  resolved once, every answer is checked and the connection goes to that validated IP
  (TLS still verifies the certificate for the name), which closes DNS rebinding for direct
  connections. It does **not** cover: ports (above); an `HTTPS_PROXY`/`https_proxy` in the
  environment (the proxy resolves the target, so the name is checked but not pinned, and
  the proxy's own reachability is yours to restrict); internal names you put in the
  allowlist (they are refused too if they resolve to private space; this executor has no
  opt-out); public services that are themselves open relays; or a compromised DNS that
  answers consistently with a public attacker address. Keep network egress rules as the
  real boundary.
- **Known limits** (informational, not fixed): ports are not restricted (H4, above); the
  conversion of an adapter's output has a size/node budget but **no time limit** (D2-a: a
  hostile custom adapter whose `__repr__` sleeps or never returns blocks the executor; the
  packaged adapters are not affected); and a very large legitimate output is recorded as a
  degraded summary with **no digest of the full output** (D2-b).
- The executor sends exactly the URL the policy matched, with no whitespace, control
  characters, backslashes or credentials in it.
- An ambiguous transport outcome is recorded as `UNKNOWN` and is not retried.
  Classification uses the exception type. A validation failure is `FAILED`.

### 3. Slack Executor (`tempus-slack-executor`, contrib)
Dispatches channel alerts and notifications while isolating `SLACK_BOT_TOKEN`:
- Supported actions: `slack.post_message`, `slack.send_alert`.
- The permit `resource` is the channel and must be **exactly one**: an ID (`C`, `G` or `D` +
  uppercase letters/digits, e.g. `C0123ABCD`) or a `#channel-name` (lowercase letters, digits,
  `-`, `_`). Slack reads a comma-separated `channel` as several, so `C0123,C9999` is rejected
  (`TEMPUS_SLACK_BINDING_REJECTED`) before anything is sent. Policy patterns match whole
  components. Put the exact channel in `allowed_resources`.

```bash
tempus-slack-executor \
  --permit permit.json \
  --executor-db slack-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --token "xoxb-<isolated-slack-bot-token>"
```

### 4. Pluggable Financial Adapter (`tempus-payment-executor`, contrib)
Reference pluggable executor that enforces the universal `money` envelope (`amount` or `amount_minor`, `asset` or `currency`, `beneficiary`; fields that disagree are refused) and minor-unit limits with credential isolation:
- Supported actions: `finance.disburse`, `finance.transfer`, `payment.charge`. Each one
  requires a `money` object and a non-zero amount; a missing, null, or zero amount is
  refused (`TEMPUS_INVALID_CONTRACT`) and nothing is signed.
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

- **Minor units assume two decimals.** `amount_minor` and the `max_money_amount_minor` limit
  are read as hundredths (`"25.5"` is `2550`) for every currency. That is wrong for zero-
  decimal currencies (JPY: `"500"` means 500 yen, but the limit sees 50 000 minor units) and
  for three-decimal ones (BHD, KWD). Express limits per currency with that in mind, or keep
  such currencies out of `allowed_currencies`.
- `money.beneficiary` must be a non-empty string; it is paid exactly as written.
- An ambiguous payment-transport outcome is recorded as `UNKNOWN`. A definitive
  provider or validation error is `FAILED`. The transport must raise the real
  exception (or `AmbiguousTransportError`) when the outcome is not known.
  `allowed_currencies` accepts only exact 3-letter codes.
- **This executor is not a complete payment control.** It checks, per intent, the currency,
  the beneficiary pattern and one maximum amount, with the same component patterns as the
  policy for the beneficiary; it has no
  cumulative, daily or velocity limits, no sanctions/KYC checks, no confirmation of the
  provider's settlement, and the shipped transport is a mock. Put the real controls
  (provider-side limits, approvals, reconciliation) at the provider.

## `tempus guard`: the agent's side

`tempus guard ...` is the Tempus Guard CLI ([tempus-guard-cli](https://github.com/tempus-protocol/tempus-guard-cli),
`pip install tempus-guard-cli`) reached through the core CLI; without it installed the command says so
and exits 2. `tempus guard intent --branch agent/fix-123 --base origin/main --tenant-id acme
--agent-keyfile agent.keys.json` reads the local branch, writes the git bundle and prints the
signed `github.push_branch` intent (`intent`, `agent_id`, `agent_signature`) with the bundle
digest, the changed paths and `diff_sha256`, ready for `request_action_signed` or
`tempus guard request --signed signed.json --gate-db gate.db --gate-keyfile gate.keys.json`.
`tempus guard hook install` makes the clone refuse direct pushes. Options meant for `tempus-guard`
itself go after `--` (`tempus guard -- --version`).

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
See [COMPATIBILITY.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/COMPATIBILITY.md) for support/deprecation rules and
[MIGRATION_0.4.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/MIGRATION_0.4.md) for the `0.3.x` upgrade procedure.

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
| `TEMPUS_DESTRUCTIVE_TOOLS=1` | demo-only cleanup |

## Human audit

Humans are readers, not approvers:

```bash
tempus trace --action-id <action-id>
tempus verify-trace --action-id <action-id> --gate-public-key <hex|file>
tempus list-agents
tempus list-policies
tempus identity-events
```

The public [trace demo](https://tempus-protocol.github.io/tempus-ddb/trace.html) is a
synthetic, browser-only illustration of hashes, signatures and record binding. A future
read-only audit console must derive its views from these contracts; it is not in the
current source line.

## Independent verification (pinned gate key)

The [public browser verifier](https://tempus-protocol.github.io/tempus-ddb/verify.html) runs
the same checks as the commands below, offline, from the `verify_url` every receipt and
bundle carries. The CLI equivalents:

`verify-trace` without a key checks the database against **its own** root of trust, so a
completely forged database (attacker keys, fake payment) verifies against itself. The
output says so (`"trust": {"independent": false}` plus a warning). To verify
independently, pin the gate's public key, obtained out of band (the operator publishes
the output of `tempus whoami`), instead of trusting the database:

```bash
# Operator: publish the gate PUBLIC key (never the key file) and hand out receipts
tempus whoami                                   # prints the gate "Public Key"
tempus trace --action-id <action-id> > receipt.json

# Verifier: no database, no gate private key; the key is pinned by you
tempus verify-receipt --receipt receipt.json --gate-public-key <64-hex|file>
tempus verify-receipt --receipt receipt.json --gate-public-key <hex> \
    --executor-public-key <executor-hex>        # optionally pin the executor too
tempus verify-trace --action-id <id> --gate-public-key <hex> --strict
tempus checkpoint verify --checkpoint chk.json --stream stream.json --gate-public-key <hex>
```

`verify-receipt` takes a trace (`tempus.action-trace.v1`), a permit
(`tempus.authorization-result.v1`) or an outcome (`tempus.execution-result.v1`); `-` reads
stdin. Exit code `0` is VERIFIED, `2` is INVALID (tampered receipt, wrong key, or a
database signed by someone else) and `1` is a usage or I/O error (a missing or invalid
argument, an unreadable file, an empty key); the two never share a code. `--strict` refuses to run
without `--gate-public-key`. Python: `verify_receipt(json, gate_pub, executor_pubs=None)`,
`verify_checkpoint(chk, stream, gate_pub)` and `TempusDDB.verify_trace(id, gate_pub)`.

### Evidence bundle: one file, verified offline

```bash
# Operator: one file per action (add --create-checkpoint to sign a fresh checkpoint
# first so the bundle can show ledger inclusion)
tempus export-bundle --action-id <action-id> --out evidence.json --create-checkpoint

# Verifier: only the file and the pinned gate public key; no database, no private keys
tempus verify-bundle --bundle evidence.json --gate-public-key <64-hex|file> \
    [--executor-public-key <hex>]
```

The bundle (`tempus.evidence-bundle.v1`) holds the trace (intent, agent signature, permit,
signed policy used to reproduce the decision, outcome and signed receipts) and, if one
covers the action, the gate-signed checkpoint with the tenant's event stream. It contains no
private keys: every field is a public document or a hash. The verifier re-checks every
signature and hash against the pinned key, reproduces the decision from the signed policy,
and, with a checkpoint, checks that the permit and outcome events are in the signed ledger.
Same exit codes as above (0 VERIFIED, 2 INVALID, 1 usage). Python:
`TempusDDB.export_bundle(id)` and `verify_bundle(json, gate_pub, executor_pubs=None)`.

### What VERIFIED means, and how strict it is

- A document that repeats a JSON object key anywhere is refused with `DUPLICATE_JSON_KEY`.
  Verifiers report the document `INVALID`. The gate applies the same rule when it receives an
  intent, outcome, policy or metadata (`parse_canonical`), and the Rust executor and the
  Python executor runtime reject a permit that repeats a key before consuming it. Do not
  generate JSON with repeated keys.
- Fields outside the schema at the top level of a bundle, in its `trace` or in its
  `checkpoint` wrapper are `INVALID` (`UNKNOWN_FIELD (<path>)`): they would be unsigned
  text travelling inside a verified file.
- A key file (`--gate-public-key FILE`) is the root of trust, so it is read strictly: bare
  hex, or a JSON object whose `public_key` / `gate_public_key` (one, or both with the same
  value) is a non-empty string. Repeated keys, an empty or non-string field, or two fields
  with different keys are usage errors (exit 1).
- Numbers in signed documents must be integers in the i64/u64 range. A float, or a larger
  integer, can be spelled several ways for one stored value (`0.1` / `1e-1`, `...567890` /
  `...567891`), so the gate refuses it when it arrives (`NON_EXACT_NUMBER`) and the
  verifiers report a document containing one as `INVALID`. Send decimals and large values as
  strings (`"amount": "25.00"`). The packaged executors convert such numbers in a
  downstream answer to strings before signing the outcome.
- `output_degraded` in the result tells you when the executor runtime could not represent
  the adapter's result in full (too large, too deep, cyclic, conversion error) and recorded
  a bounded summary under `_tempus_output_degraded` with the adapter's own status. It is
  `true` / `false`, or `null` when nothing verified; the CLI prints a NOTE on stderr. The
  marker is written by the executor: anyone holding the executor key can sign one by hand,
  so it is a visible signal, not proof of how the output was produced.
- `--gate-public-key` and `--executor-public-key` must not be empty: an empty value (for
  example an unset shell variable) is a usage error (exit 1), never "unpinned".
- `VERIFIED` alone does not say that the action was allowed or executed: a `BLOCKED`
  decision, a `FAILED` outcome, or a permit with no outcome or checkpoint all verify. The
  result shows `decision` and `execution_status` (both `null` unless the result is
  `VERIFIED`), and these flags turn an unmet expectation into exit 2 (`INVALID`,
  `REQUIREMENT_NOT_MET (...)`): `--require-decision ALLOWED|BLOCKED`,
  `--require-execution` (a verified outcome with status `SUCCEEDED`) and, on
  `verify-bundle`, `--require-checkpoint`. A script that only looks at the exit code should
  pass the ones that matter to it.

What a pinned verification (receipt or bundle) does **not** show; the result lists these in
`trust.not_checked`:

- **Completeness.** A bundle that leaves out the outcome is still a valid permit-only
  bundle (the verifier reports `phase: AUTHORIZED` or `EXPIRED`, `execution: NOT_PRESENT`).
  Nothing proves that other actions, retries or outcomes are not hidden from you.
- **Single use across the system.** Whether the permit was consumed only once is gate
  state; a document cannot prove it, even with a checkpoint.
- **Agent registration at issue time** and, unless you pin it, **the executor identity**:
  the pinned gate signature attests both.
- **Ledger inclusion without a checkpoint.** Only a bundle with a checkpoint shows the
  events are in the gate's signed ledger, and only as of that checkpoint's time. A gate
  that signs two diverging ledgers is not detected from one bundle.
- **Gate key compromise.** The guarantee is only as good as the secrecy of the gate key and
  the out-of-band way you obtained its public key.
- **Privacy.** The bundle includes the intent and outcome as recorded, and the checkpoint
  stream exposes ids, types, timestamps and hashes (not contents) of every event of that
  tenant up to the checkpoint. Streams over `--max-stream-events` (default 10000) are
  omitted, not truncated.

### Common cases that now break, and how to fix them

Since signed documents may only hold integers in the i64/u64 range as numbers, code written
for earlier versions can hit `NON_EXACT_NUMBER` (the message names the path, for example
`$.requested_at`). The usual causes:

| What you send | Result | Fix |
| --- | --- | --- |
| `requested_at` from `time.time()` (a float, seconds) | `NON_EXACT_NUMBER ... $.requested_at` | An integer in microseconds: `time.time_ns() // 1000` |
| `money.amount` as a number (`25.5`) | `NON_EXACT_NUMBER ... $.money.amount`; an integer (`25`) gives `money.amount must be a decimal string` | A string with at most two decimals: `"25.50"` (or an integer `amount_minor` in minor units; if you send both, or both `currency` and `asset`, they must agree or the intent is refused with `TEMPUS_INVALID_CONTRACT`) |
| A float in `input` (`{"price": 19.99}`) | `NON_EXACT_NUMBER ... $.input.price` (it used to produce a signed `BLOCKED`) | A string (`"19.99"`) or an integer in minor units (`1999`) |
| A decimal in agent `metadata`, a policy or an outcome `output` | `NON_EXACT_NUMBER` at its path | A string (`"0.5"`); policy limits such as `max_money_amount_minor` are already integers |
| `NaN`, `Infinity`, `1e400` or `-0` from the CLI (`--intent`, `--outcome`, `--policy`, `--metadata`) | `NON_EXACT_NUMBER` (raw text given to the Python/Rust API: `1e400` is `NON_EXACT_NUMBER`; `NaN`/`Infinity` are "must be valid JSON", they are not JSON) | Send a string, or write `0` for `-0` |

Pattern matching now respects component boundaries (`.` and `/`). A `*` matches only as
a whole component. Glued stars become denials; a `*` that is already its own leading or
middle component (`*.example.com`) used to be a dead literal and now matches, so review
such entries before upgrading:

| What you had | Result | Fix |
| --- | --- | --- |
| A policy pattern whose `*` is glued to the surrounding text (a textual prefix) in `allowed_resources`, `allowed_action_types`, `allowed_executors`, or `allowed_beneficiaries` (`allowed_currencies` takes exact codes only, see below) | The pattern matches nothing, so that entry authorizes nobody | Put `*` in its own component, after `.` or `/` (`name/*`, `*.domain`), or list the exact value. `*` alone still matches everything |
| An HTTP allowlist entry that was meant to include subdomains (`example.com` used to allow labels under it) | Only that exact host matches | Add `*.domain` for the labels under it, and keep the apex as its own entry if it should still match. `*` still means every host |
| A payment allowlist entry (`allowed_beneficiaries` or `PAYMENT_ALLOWED_BENEFICIARIES`) that used `*` as a textual prefix | The entry authorizes nobody. The policy field of the same name uses the same rule | An exact beneficiary, `*`, or a `*` that is its own component |

A transport failure where the effect may already have happened is no longer a definitive
`FAILED`. The runtime classifies that by exception type, not by words in the message:

| What you had | Result | Fix |
| --- | --- | --- |
| An HTTP, payment, or Slack transport outcome that is ambiguous | Signed `UNKNOWN`. The permit is not retried. Connection refused stays `FAILED` | Reconcile the external effect before a new action. Raise `AmbiguousTransportError`, or the real exception type, when the outcome is unknown |
| A validation error or any other definitive adapter exception | Stays `FAILED`. Classification uses the exception type | Raise the original error. Raise `AmbiguousTransportError` when the outcome is unknown |
Upgrading from 0.5.3, these also break:

| What you send | Result | Fix |
| --- | --- | --- |
| A currency pattern or wildcard in `allowed_currencies` | `TEMPUS_POLICY_INVALID`: entries must be exact currency codes. A stored dev allow-all policy with a non-exact list fails the same way and the gate does not rewrite it | Exact codes (`USD`), or omit the list. Replace a stored dev allow-all policy by running `tempus install-policy --allow-all-dev` (or `TempusDDB.install_allow_all_dev_policy()`). Any other such policy is rejected until you install a valid one. |
| A lowercase currency code | Refused: `money.currency` / `money.asset` must be an exact 3-letter code, and the same rule applies to `allowed_currencies` | An uppercase exact code (`USD`) |
| A payment action (`finance.disburse`, `finance.transfer`, `payment.charge`) with no `money`, null money, or amount 0 | `TEMPUS_INVALID_CONTRACT` (a money object, or a non-zero amount). Nothing is signed | A `money` object whose amount is greater than zero |
| JSON with a repeated object key | `DUPLICATE_JSON_KEY` from the gate (`parse_canonical`), the Rust executor and the Python runtime | Emit each object key once |
| A permit whose only intent was `authorization.intent` | The runtime does not execute that field | Put the intent at the top level of the permit (the verified `intent`) |

Custom executors do not need to convert their results: the packaged runtime records floats,
huge integers, `Decimal` and `datetime` as strings, and a result it cannot represent in a
degraded form (with the adapter's own status) instead of recording `FAILED`. An exception
the adapter itself raises is still recorded as `FAILED` (or `UNKNOWN` for ambiguous
transport errors): the runtime cannot know whether the effect happened. Bundles signed by older
versions that contain a float verify as `INVALID` (`AUTHORIZATION_NON_EXACT_NUMBER` /
`EXECUTION_NON_EXACT_NUMBER`) even if untouched.

## Security boundary

This implementation detects receipt, policy, evidence, and trace alteration; rejects
unregistered or revoked actors; prevents conflicting idempotent requests; and prevents
two outcomes from consuming one permit. It does not yet prevent deletion or rollback of
the entire local database, nor bypass by an agent that still possesses downstream
credentials. Read [THREAT_MODEL.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/THREAT_MODEL.md)
before using Tempus for high-impact production actions.

## Roadmap

0.6 "Evidence" puts the verifier in front: a public browser verifier, `verify_url` in
every receipt and bundle, and the protocol specification with conformance fixtures.
Next: 0.7 Guard (Tempus Guard for GitHub), 0.8 Anchor, 0.9 Console, 1.0 GA. See
[ROADMAP.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/ROADMAP.md).

## Development

See [CONTRIBUTING.md](https://github.com/tempus-protocol/tempus-ddb/blob/main/CONTRIBUTING.md) for setup, security reporting, and pull-request
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

MIT. See [LICENSE](https://github.com/tempus-protocol/tempus-ddb/blob/main/LICENSE).
