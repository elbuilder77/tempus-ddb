# Tempus Protocol v1

This document specifies the documents a Tempus gate, agent, executor and verifier
exchange, how they are encoded, hashed and signed, and what a conforming verifier must
report. It is the source of truth for every Tempus product: the reference
implementation in this repository (Rust core, Python package, CLI, MCP server, browser
verifier), Tempus Guard for GitHub and Tempus Advance consume these contracts and never
redefine them.

Status: the `.v1` contracts are stable for the whole `0.x` line (see
[COMPATIBILITY.md](COMPATIBILITY.md)). The conformance fixtures in
`conformance/evidence/` are generated from the reference implementation
(`scripts/generate_conformance_evidence.py`) and every verifier, including the browser
build, is tested against them (`scripts/test_wasm_verifier.mjs`,
`tests/independent_verify_tests.rs`). Where this text and the fixtures disagree, the
fixtures win until the text is corrected.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Roles

| Role | Holds | Produces |
|---|---|---|
| Gate | The gate signing key (local Ed25519 or Vault Transit), the policy, the identity registry, the ledger | Permits, execution receipts, registration and lifecycle events, policy bundles, checkpoints, evidence bundles |
| Requesting agent | Its own Ed25519 key, registered with the gate | Signed intents |
| Executor | Its own Ed25519 key, registered with the gate, and the downstream credential | Signed outcomes, signed observations |
| Verifier | Only the gate public key, obtained out of band (and optionally executor public keys) | Verification results |

Every identity is an Ed25519 public key written as 64 lowercase hexadecimal characters.
A signer is described by a *signer identity* object:

```json
{"algorithm": "Ed25519", "key_version": "1", "public_key": "<64 hex>", "signer_uri": "local-ed25519://<64 hex>"}
```

`algorithm` MUST be `Ed25519` in v1. A verifier MUST reject any other algorithm.

## 2. Encoding

### 2.1 Strict JSON

Every signed document and every document a verifier accepts is JSON with these
restrictions, enforced at parse time:

- An object MUST NOT repeat a key at any depth. A document that does is refused with
  `DUPLICATE_JSON_KEY`. (Different parsers keep different occurrences; such a document
  does not have one meaning.)
- A number MUST be an integer in the `i64` or `u64` range. Fractions, exponents,
  `-0`, and integers outside that range are refused with `NON_EXACT_NUMBER`, which names
  the path (`$.money.amount`). Decimals and large values are carried as strings.
- A document is exactly one JSON value; trailing data is a parse error.

### 2.2 Canonical form

The canonical form of a value is the UTF-8 text produced by these rules, with no
whitespace:

- `null`, `true`, `false` as those literals.
- Integers in decimal with no leading zeros, `-` for negatives.
- Strings as JSON strings with the minimal escapes: `"` as `\"`, `\` as `\\`, control
  characters U+0000..U+001F as `\b`, `\f`, `\n`, `\r`, `\t` or `\u00XX` (lowercase hex);
  every other character, including non-ASCII, written as itself in UTF-8.
- Arrays as `[` elements joined by `,` `]`, in document order.
- Objects as `{` members joined by `,` `}`, each member `"key":value`, members sorted by
  the key's UTF-8 bytes ascending.

The canonical form is what is hashed and what message signatures cover. Documents are
*stored and transmitted* in canonical form by the reference implementation, but a
verifier MUST canonicalize what it receives rather than trust the received bytes.

### 2.3 Digests and signatures

- `sha256_hex(x)` is the SHA-256 of the canonical UTF-8 bytes of `x`, written as 64
  lowercase hexadecimal characters.
- A **digest signature** is an Ed25519 signature over the 32 raw bytes of a digest
  (the hex decoded), written as 128 lowercase hexadecimal characters. The gate signs
  permits, execution receipts, registration events, lifecycle events, policy bundles and
  policy attestations this way: `signature = Ed25519(key, bytes(sha256_hex(body)))`,
  where the body is the document without its identifier and signature fields.
- A **message signature** is an Ed25519 signature over the canonical bytes themselves.
  Agents sign intents, executors sign outcomes and observations, and the gate signs
  checkpoints this way. For outcomes and observations the signature field is removed
  before canonicalizing.

A verifier MUST recompute the digest from the body and MUST verify the signature against
the pinned public key; a signature that verifies against a key named *inside* the
document but not pinned by the verifier is not evidence (`GATE_SIGNATURE_INVALID` or
`*_GATE_KEY_NOT_PINNED`).

### 2.4 Time

Timestamps are integers: microseconds since the Unix epoch, UTC. A gate refuses an
intent whose `requested_at` is more than 300 s in the past (`REQUEST_STALE`) or 60 s in
the future (`REQUEST_FROM_FUTURE`) relative to its clock, signing the denial.

## 3. Documents

Fifteen wire documents and two verification results. Every document carries
`schema_version`; a verifier MUST refuse an unknown `schema_version` rather than
guess. Fields marked *signed* are inside the hashed and signed body.

### 3.1 `tempus.action-intent.v1` — what the agent asks for

Produced and signed (message signature, `agent_signature`) by the requesting agent.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `tempus.action-intent.v1` |
| `tenant_id` | string | Scope of the policy and the registry |
| `agent_id` | string | The signing agent's public key; MUST equal the key that signed |
| `idempotency_key` | string | Unique per (tenant, agent) for one logical action |
| `action_type` | string | Matched against the policy (`github.create_issue`, `purchase`, …) |
| `resource` | string | Matched against the policy (`acme/widgets`, `vendor-api/credits`) |
| `requested_at` | integer | Microseconds since the epoch |
| `input` | object | Action parameters; counted against `max_input_bytes` |
| `money` | object or null | Optional: `{"amount": "<decimal string>", "asset": "<currency>", "beneficiary": "<id>"}`; required for payment action types |

Derived values: `intent_hash = sha256_hex(intent)`;
`action_id = sha256_hex("tempus.action.v1" NUL tenant_id NUL agent_id NUL idempotency_key)`
(the raw string, not JSON), so the same logical action always has the same identifier
and a second intent with the same key but different content is `TEMPUS_IDEMPOTENCY_CONFLICT`.

### 3.2 `tempus.authorization-receipt.v1` — the permit

Produced and signed (digest signature) by the gate. This is the document an executor
accepts and a verifier checks.

| Field | Signed | Notes |
|---|---|---|
| `schema_version` | yes | `tempus.authorization-receipt.v1` |
| `action_id`, `tenant_id`, `agent_id` | yes | From the intent |
| `intent_hash` | yes | `sha256_hex(intent)` |
| `decision` | yes | `ALLOWED` or `BLOCKED` |
| `reason_codes` | yes | Closed list, e.g. `POLICY_ALLOWED`, `POLICY_NOT_INSTALLED`, `POLICY_MONEY_DENIED`, `AGENT_NOT_REGISTERED`, `INVALID_AGENT_SIGNATURE`, `REQUEST_STALE`, `REQUEST_FROM_FUTURE` |
| `policy_version`, `policy_digest` | yes | The policy bundle evaluated (3.4) |
| `evidence_digest` | yes | `sha256_hex` of the policy evidence (3.5) |
| `executor_constraints` | yes | `{"allowed_executors": [...]}` copied from the policy |
| `issued_at`, `expires_at` | yes | Microseconds; `expires_at = issued_at + ttl` |
| `gate_id` | yes | The gate public key |
| `gate_signer` | yes | Signer identity of the gate |
| `verify_url` | yes | `<verifier>#action=<action_id>`; default verifier `https://tempus-protocol.github.io/tempus-ddb/verify.html`, overridable with `TEMPUS_VERIFY_URL` |
| `authorization_id` | no | `sha256_hex(body)` |
| `gate_signature` | no | Digest signature over `authorization_id` |

A permit is single use: the gate records at most one outcome per `authorization_id`
(an identical retry returns the stored receipt; a different one is
`TEMPUS_PERMIT_ALREADY_CONSUMED`). The agent that requested a permit MUST NOT be the
executor that consumes it (`EXECUTOR_AGENT_COLLUSION`).

### 3.3 `tempus.authorization-result.v1` — what the agent receives

```json
{"schema_version": "tempus.authorization-result.v1",
 "authorization": <authorization-receipt>,
 "intent": <action-intent>,
 "agent_signature": "<128 hex>",
 "policy_bundle": <policy-bundle, when a policy was evaluated>}
```

A `BLOCKED` result is a signed denial; no executor acts on it.

### 3.4 `tempus.policy-bundle.v1` — the rules

Produced and signed (digest signature) by the gate when a policy is installed.

| Field | Signed | Notes |
|---|---|---|
| `schema_version` | yes | `tempus.policy-bundle.v1` |
| `policy_version` | yes | Unique per gate; the dev allow-all policy is `tempus.dev-allow-all.v1.<issued_at>` |
| `tenant_id` | yes | A tenant or `*` |
| `constraints` | yes | Object with exactly these keys allowed: `allowed_action_types`, `allowed_resources`, `allowed_executors` (pattern lists), `max_ttl_seconds`, `max_input_bytes` (required integers), `allowed_currencies` (exact codes), `max_money_amount_minor`, `allowed_beneficiaries` |
| `issued_at` | yes | Microseconds |
| `signer` | yes | Gate signer identity |
| `policy_digest` | no | `sha256_hex(body)` |
| `signature` | no | Digest signature over `policy_digest` |

Patterns match whole components split on `.` and `/`: `*` matches one component,
`vendor-api/*` matches `vendor-api/credits` and not `vendor-api/a/b`. A pattern that is
not of that form matches nothing. Evaluation is deterministic: the same bundle and intent
always yield the same decision and reason codes.

### 3.5 `tempus.policy-evidence.v1` — why the decision came out that way

Not transmitted; its digest is bound into the permit as `evidence_digest`, so a verifier
holding the policy bundle and the intent can recompute it:

```json
{"schema_version": "tempus.policy-evidence.v1", "policy_digest": "<64 hex>", "intent": <action-intent>, "ttl_seconds": <integer>}
```

When no policy is installed the gate denies with `POLICY_NOT_INSTALLED` and the evidence
carries `"policy_version": "tempus.policy.none"`-style sentinel instead of a digest; the
receipt's `policy_digest` is the digest of that sentinel.

### 3.6 `tempus.agent-registration.v1` — an identity enters the registry

Produced and signed (digest signature, `signature` over `event_id = sha256_hex(event)`)
by a registrar: the gate for itself, then any identity with `can_delegate` for others.

Fields: `schema_version`, `agent_id` (= the registered public key), `alias`, `metadata`
(object; `tenant_id` inside it scopes the identity), `status` (`active`),
`can_delegate` (bool), `registered_at`, `registered_by` (registrar public key),
`identity_id` (= `agent_id`), `tenant_id`, `key_version` (1), `signer` (identity of the
registered key). Registrations are immutable: a second registration of the same key is
refused.

### 3.7 `tempus.identity-lifecycle-event.v1` — rotation and revocation

Produced and signed (digest signature by `authorized_by`) by the gate.

| Field | Notes |
|---|---|
| `event_type` | `ROTATE` or `REVOKE` |
| `identity_id`, `tenant_id` | The identity affected |
| `public_key` | The key the event is about (the new key for `ROTATE`) |
| `previous_public_key`, `previous_key_version`, `key_version` | `ROTATE` only |
| `effective_at` | Microseconds |
| `reason` | `REVOKE` only |
| `authorized_by` | Registrar public key that signed |
| `signer` | Gate signer identity |

The event travels as `{"event": <body>, "event_id": sha256_hex(body), "signature": ...}`.
A verifier that resolves identities at a point in time uses `effective_at`: a permit
issued after a revocation, or signed by a rotated-out key, is invalid.

### 3.8 `tempus.action-outcome.v1` — what the executor reports

Produced and signed (message signature, `executor_signature`, computed over the outcome
without that field) by the executor.

| Field | Notes |
|---|---|
| `schema_version` | `tempus.action-outcome.v1` |
| `authorization_id`, `action_id` | MUST match the permit |
| `status` | `SUCCEEDED` or `FAILED` |
| `external_reference` | Optional: id of the effect downstream (`acme/widgets#17`, `vendor-tx-1`) |
| `output` | Optional object; a runtime that could not represent its result in full sets `output._tempus_output_degraded: true` |
| `executor_id` | The executor's public key |
| `executor_signature` | 128 hex |

`outcome_hash = sha256_hex(outcome without executor_signature)`. An effect whose
completion the executor cannot determine (timeout, reset) is never reported as `FAILED`
and never retried; the executor records an `UNKNOWN` observation (3.11) instead.

### 3.9 `tempus.execution-receipt.v1` — the gate's receipt for the outcome

Produced and signed (digest signature) by the gate when it commits an outcome.

| Field | Signed | Notes |
|---|---|---|
| `schema_version` | yes | `tempus.execution-receipt.v1` |
| `authorization_id`, `action_id`, `intent_hash` | yes | From the permit |
| `outcome_hash` | yes | `sha256_hex` of the outcome without its signature |
| `executor_id` | yes | The executor that signed the outcome; MUST be allowed by the permit's `executor_constraints` and registered at `completed_at` |
| `status` | yes | `SUCCEEDED` or `FAILED` |
| `completed_at` | yes | Microseconds |
| `gate_id` | yes | Gate public key |
| `verify_url` | yes | `<verifier>#action=<action_id>` |
| `receipt_id` | no | `sha256_hex(body)` |
| `gate_signature` | no | Digest signature over `receipt_id` |

### 3.10 `tempus.execution-result.v1`

```json
{"schema_version": "tempus.execution-result.v1", "receipt": <execution-receipt>, "outcome": <action-outcome>}
```

### 3.11 `tempus.executor-observation.v1` — the executor's own state record

Produced and signed (message signature, `executor_signature`) by the executor runtime
for its own durable state; not part of the gate's evidence but shaped the same way.
Fields: `schema_version`, `authorization_id`, `action_id`, `executor_id`, `status`
(`STARTED`, `SUCCEEDED`, `FAILED`, `UNKNOWN`), `observed_at`, `details` (object).

### 3.12 `tempus.action-trace.v1` — one action, start to finish

```json
{"schema_version": "tempus.action-trace.v1", "action_id": "<64 hex>",
 "authorization": <authorization-result>, "execution": <execution-result> | null}
```

The wrapper is unsigned; a verifier checks that `action_id` equals the signed one
(`TRACE_ACTION_ID_MISMATCH`) and reports any field outside this list
(`UNKNOWN_FIELD (trace.<name>)`).

### 3.13 `tempus.event-stream-event.v1` — the hash-linked ledger

Every permit, receipt, registration and policy installation is appended to a per-tenant
stream by the gate.

| Field | Notes |
|---|---|
| `tenant_id` | Stream scope |
| `sequence_number` | 1, 2, 3, … with no gaps |
| `event_id` | The identifier of the document recorded (`authorization_id`, `receipt_id`, …) |
| `event_type` | `action.authorized`, `action.executed`, `action.failed`, `agent.registered`, policy events |
| `payload_hash` | `sha256_hex` of the recorded document |
| `prev_event_hash` | `event_digest` of the previous event; a fixed genesis constant for sequence 1 |
| `timestamp` | Microseconds |
| `event_digest` | `sha256_hex` of the event without this field |

### 3.14 `tempus.checkpoint.v1` — the gate commits to a prefix of the stream

Produced and signed (message signature over the canonical envelope, `signature`) by the
gate. Fields: `schema_version`, `checkpoint_id`, `tenant_id`, `checkpoint_sequence`
(monotonic per tenant), `first_sequence`, `last_sequence`, `stream_root_hash`
(cumulative hash of the covered events), `total_events`, `created_at`, `signer`.

A verifier with the checkpoint, the covered events and the pinned gate key MUST check the
signature, the contiguity of sequence numbers, every `prev_event_hash` link and digest,
every event's tenant, and that the recomputed root equals `stream_root_hash`. A deleted
tail, a gap, an edited byte or a rollback to an earlier checkpoint is `INVALID`.

### 3.15 `tempus.evidence-bundle.v1` — one file for a third party

Produced by the gate (`tempus export-bundle`). It holds no private key material.

| Field | Signed | Notes |
|---|---|---|
| `schema_version` | — | `tempus.evidence-bundle.v1` |
| `action_id` | — | MUST equal the trace's |
| `trace` | documents inside are signed | The action trace (3.12) |
| `checkpoint` | documents inside are signed | `{"checkpoint": <checkpoint>, "stream": [<events>]}` covering the action's events, or `null` when no checkpoint covers them yet or the stream exceeds the export limit |
| `verify_url` | no | `<verifier>#bundle=<bundle_digest>` |

`bundle_digest = sha256_hex(bundle without verify_url)`. A verifier MUST report the
digest it computed (`bundle_digest`), and when `verify_url` is present MUST check that it
is an `http(s)` URL whose fragment is `bundle=<that digest>` (`BUNDLE_VERIFY_URL_MISMATCH`
otherwise, `BUNDLE_VERIFY_URL_INVALID` when malformed). A bundle without `verify_url` is
valid. Any other top-level field is `UNKNOWN_FIELD (bundle.<name>)`.

## 4. Verification results

### 4.1 `tempus.trace-verification.v1`

Returned by `verify_receipt` (permit, outcome or trace), `verify_trace` and
`verify_bundle`.

| Field | Notes |
|---|---|
| `status` | `VERIFIED` or `INVALID` |
| `kind` | `authorization`, `execution`, `trace` or `bundle` |
| `action_id` | From the document |
| `phase` | `AUTHORIZED` (permit, unexpired, no outcome), `EXPIRED`, `COMPLETED`, `BLOCKED`, or `UNKNOWN` when the document could not be parsed |
| `decision`, `execution_status`, `output_degraded` | What the signed documents say; `null` unless `status` is `VERIFIED`, so a reader never takes a value from a document that failed |
| `checks.authorization`, `checks.execution` | `VERIFIED`, `FAILED` or `NOT_PRESENT`; bundles add `checks.checkpoint` |
| `errors` | Codes, possibly with a parenthesised path; empty when `VERIFIED` |
| `trust.mode` | `PINNED_GATE_KEY` (independent) or `DATABASE_SELF_ATTESTED` (not independent; the CLI warns) |
| `trust.independent` | `true` only with a pinned key |
| `trust.gate_public_key`, `trust.executor_keys_pinned` | What was pinned |
| `trust.not_checked` | What this verification does not establish, as `CODE (explanation)`: `AGENT_REGISTRATION_AT_ISSUE`, `SINGLE_USE_CONSUMPTION`, `EXECUTOR_IDENTITY` (unless pinned), `PERMIT_LINKAGE` (outcome alone), `LEDGER_INCLUSION` (bundle without checkpoint), `COMPLETENESS` (every bundle) |
| `bundle_digest`, `verify_url` | Bundles only |

Error codes a conforming verifier MUST produce for the corresponding defect include
`AUTHORIZATION_ID_MISMATCH`, `GATE_SIGNATURE_INVALID`, `AUTHORIZATION_GATE_KEY_NOT_PINNED`,
`INTENT_HASH_MISMATCH`, `AGENT_SIGNATURE_INVALID`, `EXECUTION_RECEIPT_ID_MISMATCH`,
`EXECUTION_GATE_SIGNATURE_INVALID`, `EXECUTION_GATE_KEY_NOT_PINNED`,
`OUTCOME_HASH_MISMATCH`, `EXECUTOR_SIGNATURE_INVALID`, `EXECUTOR_AGENT_COLLUSION`,
`POLICY_DIGEST_MISMATCH`, `AUTHORIZATION_NON_EXACT_NUMBER (path)`,
`EXECUTION_NON_EXACT_NUMBER (path)`, `UNKNOWN_FIELD (path)`, `TRACE_ACTION_ID_MISMATCH`,
`BUNDLE_ACTION_ID_MISMATCH`, `BUNDLE_VERIFY_URL_MISMATCH`, `BUNDLE_VERIFY_URL_INVALID`,
`CHECKPOINT_<reason>` and `CHECKPOINT_TENANT_MISMATCH`,
`CHECKPOINT_AUTHORIZATION_NOT_INCLUDED`, `CHECKPOINT_EXECUTION_NOT_INCLUDED`, and
`DUPLICATE_JSON_KEY` / `NON_EXACT_NUMBER` for refused input. A verifier MUST NOT report
`VERIFIED` with a non-empty `errors` list.

### 4.2 `tempus.checkpoint-verification.v1`

Returned by `verify_checkpoint`: `status` (`VERIFIED` or `INVALID`), `checkpoint_id`,
`events_verified`, and on failure `reason_code` (`ERR_UNTRUSTED_SIGNER`,
`ERR_SIGNATURE_INVALID`, `ERR_EMPTY_STREAM`, `ERR_SEQUENCE_GAP`, `ERR_TENANT_MISMATCH`,
hash-chain and root mismatches, `DUPLICATE_JSON_KEY`) and `message`.

## 5. What verification means

`VERIFIED` means: every signed document in the input is byte-for-byte what the pinned
gate (and, where present, the agent and executor) signed, the documents refer to each
other consistently, and nothing in the input is outside the contracts. It does not mean
the action was wise, that the permit was used only once, or that nothing else happened:
those appear in `trust.not_checked`, and a conforming verifier MUST surface them rather
than stay silent. A document verified against the database it came from
(`DATABASE_SELF_ATTESTED`) is not independent evidence and MUST say so.

## 6. Conformance

An implementation conforms to this specification when, for every file in
`conformance/evidence/` with the gate public key in `gate_public_key.txt`, it returns the
`status`, `kind`, `phase` (or one of `phase_any`), `checks` and `errors` listed for that
file in `expected.json`, and when it refuses the malformed inputs of section 2.1. The
fixtures are regenerated by `scripts/generate_conformance_evidence.py` whenever the
reference implementation's documents change; a change that alters an expected verdict is
a protocol change and needs a new schema version.
