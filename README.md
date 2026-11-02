<div align="center">
  <img src="https://raw.githubusercontent.com/tempus-protocol/tempus-ddb/main/assets/logo.png" alt="Tempus DDB" width="180" />

# Tempus DDB

**Evidence that an agent's action was authorized, and that it happened exactly as authorized.**

Every effect needs a signed, single-use permit. Every effect leaves a signed receipt.
Anyone with the gate's public key can verify it, in a browser, without trusting anyone.

<p align="center">
  <a href="https://github.com/tempus-protocol/tempus-ddb/actions/workflows/ci.yml"><img src="https://github.com/tempus-protocol/tempus-ddb/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://crates.io/crates/tempus-ddb"><img src="https://img.shields.io/crates/v/tempus-ddb.svg" alt="crates.io" /></a>
  <a href="https://docs.rs/tempus-ddb"><img src="https://img.shields.io/docsrs/tempus-ddb" alt="docs.rs" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/pypi/v/tempus-ddb.svg" alt="PyPI" /></a>
  <a href="https://github.com/tempus-protocol/tempus-ddb/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <a href="https://github.com/tempus-protocol/tempus-ddb/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/security-policy-blue.svg?logo=shield" alt="Security Policy" /></a>
</p>

[**Verify evidence now →**](https://tempus-protocol.github.io/tempus-ddb/verify.html) · [Spec](SPEC.md) · [Full reference](docs/REFERENCE.md) · [Español](README.es.md)

</div>

---

## Start here: verify a receipt

Somebody hands you a file. Open the [public verifier](https://tempus-protocol.github.io/tempus-ddb/verify.html),
load the file, paste the gate's public key you obtained separately, and read the
verdict. The page is the same verifier as the CLI, compiled to WebAssembly: it runs
offline and nothing leaves your browser. Click **Load a real sample** to see a verified
bundle, and **Load a tampered sample** to see one signed field changed after the fact.

Every receipt Tempus signs says where to do this: its `verify_url` points at the
verifier with the action's identifier, and every exported bundle carries the bundle's
digest in its link, so link and file are checked against each other.

```bash
# The same check from a terminal, with only the file and the public key:
tempus verify-bundle --bundle evidence.json --gate-public-key <64 hex>
```

## Install in three commands

```bash
python -m pip install tempus-ddb        # pre-built wheels for Python 3.10+, no Rust needed
tempus init --allow-all-dev             # local gate key + database; allow-all is a dev shortcut
tempus status                           # keys, database, identities, policy, verifier URL
```

Without `--allow-all-dev` the gate denies every action until you install a signed
policy (default-deny). To work on the source see [docs/REFERENCE.md](docs/REFERENCE.md#install).

## Your first verified action

```bash
tempus keygen --output agent.keys.json
tempus keygen --output executor.keys.json
tempus register-agent --alias demo-agent    --agent-keyfile agent.keys.json    --metadata '{"tenant_id":"acme"}'
tempus register-agent --alias demo-executor --agent-keyfile executor.keys.json --metadata '{"tenant_id":"acme"}'

# 1. The agent signs what it wants to do.
AGENT_PUB=$(python -c "import json; print(json.load(open('agent.keys.json'))['public_key'])")
cat > intent.json <<EOF
{"schema_version": "tempus.action-intent.v1", "tenant_id": "acme", "agent_id": "$AGENT_PUB",
 "idempotency_key": "issue-001", "action_type": "github.create_issue", "resource": "acme/widgets",
 "requested_at": $(python -c "import time; print(time.time_ns() // 1000)"),
 "input": {"title": "Rotate the staging key"}}
EOF

# 2. The gate evaluates the policy and signs a single-use permit (or a signed denial).
tempus request-action --intent intent.json --agent-keyfile agent.keys.json --ttl-seconds 60 > permit.json
AUTH_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['authorization_id'])")
ACTION_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['action_id'])")

# 3. The executor does the work and signs the outcome; the gate signs the receipt.
cat > outcome.json <<EOF
{"schema_version": "tempus.action-outcome.v1", "authorization_id": "$AUTH_ID",
 "action_id": "$ACTION_ID", "status": "SUCCEEDED", "external_reference": "acme/widgets#17"}
EOF
tempus commit-outcome --authorization-id "$AUTH_ID" --outcome outcome.json --executor-keyfile executor.keys.json > execution.json

# 4. One file for anyone: verified with the file and the gate PUBLIC key only.
tempus export-bundle --action-id "$ACTION_ID" --out evidence.json --create-checkpoint
GATE_PUB=$(python -c "import json; print(json.load(open('keys.json'))['public_key'])")
tempus verify-bundle --bundle evidence.json --gate-public-key "$GATE_PUB"
```

`export-bundle` prints the bundle's `verify_url`. Send `evidence.json` and the gate
public key (never the key file) to whoever needs to check; they can open the link and
load the file.

## What a receipt proves, and what it does not

A `VERIFIED` result means every signed document in the file is byte-for-byte what the
pinned gate signed, the agent's intent is the one the permit was issued for, the
executor's outcome is the one the receipt covers, and (with a checkpoint) the events sit
in the gate's hash-linked ledger with no gap or rollback.

It does not prove what no document can: that the permit was used only once, or that
nothing else happened. The verifier lists those under `trust.not_checked` instead of
staying silent. A document checked against the database it came from is reported as not
independent. The rules are in [SPEC.md](SPEC.md); the attacks considered are in
[THREAT_MODEL.md](THREAT_MODEL.md).

## How it works

```text
agent signs intent ──► gate evaluates signed policy ──► single-use permit (ALLOWED | BLOCKED)
                                                              │
                     executor holds the credential, acts, signs outcome
                                                              │
                     gate signs execution receipt, appends to hash-linked ledger, signs checkpoints
                                                              │
                     anyone verifies receipt / bundle with the gate public key (browser or CLI)
```

- **Fail-closed.** No installed policy, unknown schema, unregistered or revoked key,
  expired permit, ambiguous JSON (repeated keys, inexact numbers): the gate denies or
  refuses, and signs the denial.
- **Credential isolation.** The requesting agent never holds the downstream token; the
  mediated executor does, and it acts only on an unconsumed permit.
- **One outcome per permit.** A conflicting second outcome is refused; an executor that
  cannot tell whether an effect happened records `UNKNOWN` and never retries.
- **Evidence a third party can check.** Ed25519 signatures, SHA-256 over a canonical
  form, signed checkpoints over the event stream, and a public verifier.

## Python in twenty lines

```python
import json, time
from tempus_ddb import TempusDDB, gen_keys

for name in ("gate", "agent", "executor"):
    gen_keys(f"{name}.keys.json")
key = lambda name: json.load(open(f"{name}.keys.json"))["public_key"]

gate = TempusDDB("tempus.db", "gate.keys.json")
gate.register_agent(key("gate"), "gate", '{"can_delegate":true}')
gate.register_agent(key("agent"), "agent", "{}")
gate.register_agent(key("executor"), "executor", "{}")
gate.install_allow_all_dev_policy()          # dev only; install_policy(...) for real rules

intent = {"schema_version": "tempus.action-intent.v1", "tenant_id": "acme", "agent_id": key("agent"),
          "idempotency_key": "purchase-001", "action_type": "purchase", "resource": "vendor-api/credits",
          "requested_at": time.time_ns() // 1_000, "input": {"sku": "compute-credits"},
          "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"}}
permit = json.loads(gate.request_action(json.dumps(intent), "agent.keys.json", 60))["authorization"]
assert permit["decision"] == "ALLOWED"

outcome = {"schema_version": "tempus.action-outcome.v1", "authorization_id": permit["authorization_id"],
           "action_id": permit["action_id"], "status": "SUCCEEDED", "external_reference": "vendor-tx-1"}
gate.commit_outcome(permit["authorization_id"], json.dumps(outcome), "executor.keys.json")

bundle = gate.export_bundle(permit["action_id"], None)
print(json.loads(bundle)["verify_url"])      # open it, load the bundle, paste key("gate")
```

For remote agents and executors use `request_action_signed` / `commit_outcome_signed`
(they sign locally; the gate never sees their keys), or the MCP server (`tempus mcp start`).
Packaged executors exist for GitHub, HTTP webhooks, Slack and payments: see the
[reference](docs/REFERENCE.md#packaged-mediated-executors).

## The protocol

Fifteen `.v1` contracts, specified in [SPEC.md](SPEC.md) with conformance fixtures in
`conformance/evidence/` that the native verifier and the browser verifier are tested
against. Stable for the whole `0.x` line ([COMPATIBILITY.md](COMPATIBILITY.md)).

| Document | Schema | Signed by |
|---|---|---|
| Agent intent | `tempus.action-intent.v1` | agent |
| Permit | `tempus.authorization-receipt.v1` | gate |
| Authorization result | `tempus.authorization-result.v1` | — (wrapper) |
| Policy bundle | `tempus.policy-bundle.v1` | gate |
| Policy evidence | `tempus.policy-evidence.v1` | — (digest in the permit) |
| Agent registration | `tempus.agent-registration.v1` | registrar |
| Identity lifecycle event | `tempus.identity-lifecycle-event.v1` | gate |
| Executor outcome | `tempus.action-outcome.v1` | executor |
| Execution receipt | `tempus.execution-receipt.v1` | gate |
| Execution result | `tempus.execution-result.v1` | — (wrapper) |
| Executor observation | `tempus.executor-observation.v1` | executor |
| Action trace | `tempus.action-trace.v1` | — (wrapper) |
| Event-stream event | `tempus.event-stream-event.v1` | — (hash-linked) |
| Checkpoint | `tempus.checkpoint.v1` | gate |
| Evidence bundle | `tempus.evidence-bundle.v1` | — (carries the above) |

Verification results are `tempus.trace-verification.v1` and
`tempus.checkpoint-verification.v1`.

## Built on Tempus

- **Tempus Guard for GitHub** ([tempus-github-app](https://github.com/tempus-protocol/tempus-github-app)):
  a GitHub App executor that pushes only under a permit and will put a "Verified by
  Tempus" check on every pull request, linking to the verifier (0.7).
- **Tempus Guard CLI** ([tempus-guard-cli](https://github.com/tempus-protocol/tempus-guard-cli)):
  the client side of Guard; `tempus guard intent` signs the push intent from a local branch.
- **Tempus Advance** ([Tempus-Advance](https://github.com/tempus-protocol/Tempus-Advance)):
  a hosted, read-only console over the same contracts (0.9).

Compared with MCP gateways and RBAC: [docs/COMPARISON.md](docs/COMPARISON.md).
Milestones: [ROADMAP.md](ROADMAP.md).

## Security boundary

Tempus detects altered or forged receipts, policies, evidence and traces; rejects
unregistered or revoked actors; refuses conflicting idempotent requests; and prevents two
outcomes from consuming one permit. It does not yet prevent deletion of an entire gate
database without an external anchor (0.8), nor bypass by an agent that still holds a
downstream credential. Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on it for
high-impact actions, and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets
ruff check . && python -m pytest tests/
bash scripts/build_wasm_verifier.sh && node scripts/test_wasm_verifier.mjs && node scripts/validate_site.mjs
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Everything else, from policy authoring and the
executors to checkpoints, MCP configuration and the Vault signer, is in
[docs/REFERENCE.md](docs/REFERENCE.md).

## License

MIT. See [LICENSE](LICENSE).
