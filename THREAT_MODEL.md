# Tempus DDB B2A Threat Model

## Scope and invariant

Tempus is a security gate for autonomous business-to-agent and agent-to-agent actions.
Its target invariant is:

> No valid Tempus permit, no external effect; every external effect produces a
> cryptographically verifiable receipt.

The current release implements the local authorization and receipt protocol. The
invariant becomes operationally enforceable only when the downstream executor holds the
real credentials and rejects every request that lacks a valid, unexpired, unused Tempus
permit.

Humans are outside the per-action approval loop. They may provision the deployment trust
root and inspect history, but agents, the gate, and executors perform the runtime flow.

## Protected assets

- Agent action intents and their input digests.
- Gate authorization and denial receipts.
- Executor outcomes and external references.
- Linkage between intent, authorization, and outcome.
- Gate, agent, and executor signing keys.
- Signed agent registration and delegation records.
- Tenant action history and verification results.
- Downstream credentials held by mediated executors.

## Trust boundaries

1. **Requesting agent:** untrusted until its signature and signed registration verify.
2. **Tempus gate:** trusted to evaluate the configured policy and sign permits. Its key
   must be provisioned as the delegation root.
3. **Executor:** trusted to hold downstream credentials and report the external outcome;
   its identity and output are signed and independently verifiable.
4. **SQLite storage:** untrusted mutable storage. Signatures detect alteration, but local
   storage alone cannot prove that a complete database was not deleted or rolled back.
5. **MCP transport:** agent-controlled input. The autonomous surface exposes no direct
   record, registration, key-generation, or cleanup tools by default.
6. **Human auditor:** read-only consumer of traces. Human approval is not a security
   dependency for an action to proceed.

## Implemented controls

### Signed identity delegation

- The first agent registration must be the gate key itself.
- The gate registration becomes the signed root and receives delegation authority.
- Every subsequent registration is signed by an active delegator.
- Registrations are insert-only; an alias or metadata record cannot be replaced silently.
- Legacy unsigned `agents` rows are not trusted for B2A authorization.

### Agent intent proof

- Every action uses `tempus.action-intent.v1`.
- `agent_id` must match the Ed25519 key that signs the canonical intent.
- Unknown or untrusted agents receive a signed `BLOCKED` authorization.
- Invalid schema, mismatched identity, and malformed JSON are rejected; no permit is issued for them.

### Permit integrity and replay protection

- The gate signs an authorization receipt containing the action, actor, intent hash,
  policy version, decision, issue time, and expiry.
- `action_id` is deterministic for tenant, agent, and idempotency key.
- Repeating the same request returns the original authorization.
- Reusing an idempotency key for a different intent is rejected.
- Permit TTL is bounded to 1–86,400 seconds.
- Pattern matching now respects component boundaries (`.` and `/`) for policy pattern
  lists and the payment beneficiary allowlist. A `*` that is not a whole component
  matches nothing.

### Outcome integrity and single consumption

- Only an active registered executor can commit an outcome.
- The executor signs the canonical `tempus.action-outcome.v1` payload.
- The gate signs the final execution receipt and links it to the authorization and intent
  hash.
- An identical retry returns the existing receipt.
- A conflicting second outcome is rejected as an already-consumed permit.
- The executor stores signed `STARTED`, `SUCCEEDED`, `FAILED`, or `UNKNOWN`
  observations independently of the gate receipt.
- Restart recovery marks abandoned `STARTED` executions `UNKNOWN`; it never retries an
  external effect whose result is ambiguous.
- A transport failure after the executor may have sent the effect (timeout, reset,
  disconnect, TLS, EOF, or HTTP 5xx) is signed `UNKNOWN`. Other adapter exceptions,
  including validation errors, are signed `FAILED`. The choice is by exception type.

### GitHub credential isolation and exact binding

- `tempus-github-executor` reads `GITHUB_TOKEN` only from the executor environment.
- The permit is verified and consumed before the GitHub request is sent.
- The outbound endpoint and JSON payload are derived exclusively from the signed
  `action_type`, exact `owner/repository` resource, and allowlisted intent arguments.
- Unsupported actions, resources, or extra fields produce a signed `FAILED` outcome
  without contacting GitHub.

### MCP least privilege

The default MCP process exposes only authorization, outcome commit, trace verification,
trace reading, and registry reading. Separate environment flags are required for:

- `TEMPUS_ADMIN_TOOLS=1`: deployment-time provisioning.
- `TEMPUS_DESTRUCTIVE_TOOLS=1`: demo cleanup.

No MCP tool accepts a private-key path from the client. The former
`TEMPUS_LEGACY_TOOLS` (pre-protocol ledger) and `TEMPUS_LOCAL_KEYFILE_TOOLS` (key-file
request/commit tools) were removed in 0.6.0 and are ignored if set.

The gate key path is server-controlled through `TEMPUS_GATE_KEYFILE`; an MCP client
cannot select a different gate key per authorization request. The default B2A MCP tools
accept locally signed intent and outcome payloads, not private-key file paths.

### External anchoring

`tempus anchor` proves a signed checkpoint's hash to a public log (Rekor) and a timestamp authority
(RFC 3161). The proofs are verified offline, against roots the reader pins, so an auditor needs
neither the operator nor Tempus, and a later outage of either service does not matter.

- The gate never calls out. The operator anchors from the CLI or cron.
- Only the hash leaves the machine. The log entry is signed by a throwaway key, so a public entry
  says nothing about the tenant and cannot be linked to the gate.
- A proof with no pinned root is `NOT_CHECKED`, never `VERIFIED`. One failed proof makes the verdict
  `INVALID`.
- The date an anchor proves is an upper bound on when the checkpoint existed, and nothing more.

### Policy rules

Rules are data, in a closed typed subset of JsonLogic checked when a policy is read. A verifier
re-executes them, so a gate cannot sign an `ALLOWED` its own rule denies without a verifier finding
it. A rule's work is bounded by 32 rules, 256 nodes and 16 levels, and it reads only the fields it
names. A policy that reads a very large input field on every node is an operator's own cost, within
`max_input_bytes`.

## Threats and residual risk

| Threat | Current control | Residual risk / required production control |
|---|---|---|
| Agent bypasses Tempus | GitHub credential is held by the packaged mediated executor | Deployment is bypassable if the same token is also exposed to the requesting agent. |
| Agent forges identity | Ed25519 signature, signed registration, tenant scope, rotation, and revocation | A stolen active key can impersonate that agent until revocation reaches every executor. Production identities should use the Vault/workload signer path. |
| Client self-registers | Registration requires a delegation-capable signer in the same tenant scope; admin MCP tools are disabled | Protect the separate provisioning process and delegation root. |
| Gate forges permits | Gate receipts identify the signer URI/key version and are signed locally or through Vault Transit | The gate remains a trust root. A verifier reproduces the decision, rules included, from the signed policy, so a false decision over an honest policy is caught. A gate that signs a false policy is not. Add key transparency and replicated audit. |
| Replay or duplicate action | Gate idempotency plus atomic executor-side consumption | Multi-instance executors require shared transactional consumption state. |
| Ambiguous GitHub result | Signed `UNKNOWN` observation and no automatic retry | An operator must reconcile the external GitHub state before deciding on a new action. |
| Two conflicting outcomes | Unique authorization consumption | Distributed executors require transactional shared state or a consensus-backed permit store. |
| Receipt modification | Canonical hashes and Ed25519 signatures | Metadata confidentiality is not provided; values are stored as plaintext JSON. |
| Tail deletion or full database loss | An anchored checkpoint, retained outside the host, shows what the gate had committed to by its date | Deletion is detected, not prevented, and only up to the last anchored checkpoint. An anchor holds only a hash, so retain the checkpoint and its stream too. |
| Database rollback | Signatures preserve integrity of the restored snapshot; a retained anchored checkpoint newer than the snapshot exposes the rollback | A valid older snapshot is not distinguishable locally, and an anchor cannot show that no later checkpoint exists. Someone has to keep the newest one. |
| Backdated checkpoint | An anchor dates the checkpoint from outside, against roots the reader pins | The operator chooses when to anchor, so the date is only an upper bound. Trust moves to the log and the authority: a colluding log and authority, or a compromised root, could forge a date. Revocation of timestamp certificates is not checked offline (`TSA_REVOCATION`). |
| Malicious or altered policy | Gate-controlled policy bundles are signed and embedded by digest; evidence is reproduced by the executor | A compromised delegation root can install a malicious policy. Separate provisioning authority and monitor policy events. |
| Key file theft | Plaintext files are development-only; gate and executor accept a Vault Transit signer config with no private key | Vault workload authentication and policy remain operator responsibilities. |
| MCP path misuse | MCP tools accept only signed payloads; no tool takes a key-file path | Admin and destructive tools stay behind their flags and run in a separate process from the agent-facing server. |
| Sensitive payload disclosure | None | Store digests or encrypted evidence where raw inputs/outputs contain secrets or personal data. |
| Financial abuse | Money uses the same signed envelope | Tempus does not provide custody, KYC/AML, sanctions controls, or transaction reversal. Financial executors must supply those controls. |

## Security statuses

- Authorization: `ALLOWED` or `BLOCKED`.
- Execution: `SUCCEEDED` or `FAILED`.
- Executor observation: `STARTED`, `SUCCEEDED`, `FAILED`, or `UNKNOWN`.
- Trace verification: `VERIFIED` or `INVALID`.
- Trace phase: `AUTHORIZED`, `COMPLETED`, `BLOCKED`, or `EXPIRED`.

A `FAILED` execution can still have a `VERIFIED` trace: verification means the evidence
is authentic and linked, not that the business operation succeeded.

## Production readiness gates

Tempus must not be described as an unavoidable production toll until all of the following
are true:

The source tree implements gates 1–4, 6, and 8. Their production validity still depends
on using exclusive downstream credentials, the Vault/workload signer configuration, and
a separately protected provisioning process. Gate 5 remains Phase 4 work.

1. Downstream credentials are unavailable to requesting agents.
2. Executors verify the full permit, policy version, expiry, and consumption state before
   producing an effect.
3. Gate, agent, and executor keys use workload identity or KMS/HSM-backed signing.
4. Agent revocation and key rotation are signed, tenant-scoped, and tested.
5. Action receipts are replicated, and checkpoints are anchored and retained outside the host, to
   detect truncation and rollback.
6. Policies are signed, versioned, deterministic, and controlled by the gate rather than
   by the requesting agent.
7. Concurrency, recovery, denial-of-service, and cross-process replay tests pass.
8. The agent-facing process cannot enable admin or destructive MCP tools.
9. Confidentiality and retention controls match the data carried in action evidence.

## Out of scope for the current vertical slice

- Custody or movement of funds.
- Bilateral negotiation and arbitration.
- Human approval workflows.
- Cloud synchronization.
- A read-only web audit console.
- Arbitrary policy languages beyond the deterministic tenant, resource, action, input,
  money, TTL, and executor constraints in `tempus.policy-bundle.v1` and its typed `rules`.

These are roadmap items, not current security claims.
