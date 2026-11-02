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

Sixteen wire documents and three verification results. Every document carries
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
| `reason_codes` | yes | Closed list, e.g. `POLICY_ALLOWED`, `POLICY_NOT_INSTALLED`, `POLICY_MONEY_DENIED`, `POLICY_RULES_DENIED`, `POLICY_RULES_ERROR`, `AGENT_NOT_REGISTERED`, `INVALID_AGENT_SIGNATURE`, `REQUEST_STALE`, `REQUEST_FROM_FUTURE` |
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
| `constraints` | yes | Object with exactly these keys allowed: `allowed_action_types`, `allowed_resources`, `allowed_executors` (pattern lists), `max_ttl_seconds`, `max_input_bytes` (required integers), `allowed_currencies` (exact codes), `currency_exponents`, `max_money_amount_minor`, `allowed_beneficiaries` |
| `rules` | yes | Optional; see below |
| `issued_at` | yes | Microseconds |
| `signer` | yes | Gate signer identity |
| `policy_digest` | no | `sha256_hex(body)` |
| `signature` | no | Digest signature over `policy_digest` |

Patterns match whole components split on `.` and `/`: `*` matches one component,
`vendor-api/*` matches `vendor-api/credits` and not `vendor-api/a/b`. A pattern that is
not of that form matches nothing. Evaluation is deterministic: the same bundle and intent
always yield the same decision and reason codes.

**Amounts.** An amount is read in the decimals of its currency. `currency_exponents` maps an
exact code to 0..8, and any other currency has two. `amount` has at most that many fractional
digits, minor units are `amount * 10^exponent`, and `max_money_amount_minor` and rules see
those units. `amount` and `amount_minor`, when both are present, MUST agree. Before a policy is
known a gate checks only the shape of `money`: types, the decimal grammar up to 8 fractional
digits, and no zero amount on a payment action. A gate MUST refuse to install a policy whose
`allowed_currencies` names one of these currencies with no entry in `currency_exponents`,
because read in hundredths `"500"` yen would meet a limit as 50000:

- 0 decimals: BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF
- 3 decimals: BHD IQD JOD KWD LYD OMR TND
- 4 decimals: CLF UYW

That refusal is for a new install. A verifier MUST NOT apply it to a bundle it reads.

**Rules.** `rules` is a list of up to 32 `{"id", "logic"}` objects, with ids matching
`[a-z0-9._-]{1,64}` and unique, and each `logic` holding up to 256 nodes and 16 levels. A bundle
with no `rules` has exactly the bytes it had before they existed. A rule sees this and nothing
else, so anyone can rebuild it from the permit:

```json
{"intent": <the signed intent>, "ttl_seconds": <integer>,
 "money": {"amount_minor": <integer>, "currency": "<code>"}}
```

`money` is absent when the intent has none. Rules are a typed subset of JsonLogic, because
JsonLogic itself coerces like JavaScript (`"10" > 9`, `1 == "1"`) and its arithmetic is floating
point:

```
Bool := true | false | Var
      | {"and": [Bool, ...]} | {"or": [Bool, ...]} | {"if": [Bool, Bool, Bool]}
      | {"!": Test} | {"!!": Test}
      | {"===": [Term, Term]} | {"!==": [Term, Term]}
      | {"<": [Num, Num]} | {"<=": [Num, Num]} | {">": [Num, Num]} | {">=": [Num, Num]}
      | {"in": [Str, Str | [string, ...] | Var]}
Test := Bool | Var | {"missing": ["path", ...]}
Num  := integer | Var | {"+": [Num, Num]} | {"-": [Num, Num]} | {"*": [Num, Num]}
      | {"min": [Num, ...]} | {"max": [Num, ...]}
Str  := string | Var
Term := integer | string | true | false | null | Var | Num
Var  := {"var": "path"} | {"var": ["path", integer | string | true | false | null]}
```

A path is dot-separated `[A-Za-z0-9_-]+` segments under `intent`, `ttl_seconds` or `money`. An
object has exactly one operator, and `{"!": x}` is the same as `{"!": [x]}`. A list in `in` holds
literal strings only, because JsonLogic does not evaluate inside a literal list. Anything else,
including `==`, `!=`, `/`, `%`, `substr`, `cat`, `map`, `filter`, `reduce`, `all`, `some`, `none`,
`merge`, `missing_some` and `log`, is refused when the policy is read
(`TEMPUS_POLICY_RULES_INVALID`). `missing` asks whether a key is there, and a key holding null is
there.

Integer literals, every value read as a number and every result of arithmetic MUST be exact and
within +/-(2^53 - 1). A value of the wrong type, read from a branch the rule actually reaches, is
a failure; a branch not taken cannot fail. Every rule runs. A rule that is `false` adds
`POLICY_RULES_DENIED`, a rule that fails adds `POLICY_RULES_ERROR`, each at most once and in that
order, after any other policy reason. Either makes the decision `BLOCKED`, and a verifier
re-executes the rules when it reproduces the decision.

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
tail, a gap, an edited byte or a rollback to an earlier checkpoint is `INVALID`. Its
`created_at` is the gate's own claim; an anchor (3.16) dates it from outside.

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
valid. Any other top-level field is `UNKNOWN_FIELD (bundle.<name>)`, so an anchor (3.16)
travels beside the bundle, not inside it.

### 3.16 `tempus.anchor.v1` — proof from outside that a checkpoint existed by a date

Produced by the gate operator (`tempus anchor create`), never by the gate itself. The wrapper
is unsigned; each proof authenticates itself. It is a separate file because the checkpoint's
signature and the bundle's closed field list leave no room for it inside them.

| Field | Notes |
|---|---|
| `schema_version` | `tempus.anchor.v1` |
| `checkpoint_id`, `tenant_id` | MUST equal the checkpoint's |
| `checkpoint_digest` | `sha256_hex(signed checkpoint, including its signature)`: what is anchored |
| `proofs` | 1 to 8 proofs |

Only that digest leaves the operator's machine, so a public entry says nothing about the tenant.

A `rekor` proof holds `log_url` and `entry_uuid` (informational, never trusted), `body` (base64
of the logged `hashedrekord` over the digest), `integrated_time`, `log_id`, `log_index`,
`signed_entry_timestamp`, and `inclusion_proof` (`log_index`, `tree_size`, `root_hash`, `hashes`,
`checkpoint`). The entry is signed by a fresh P-256 key that is then discarded, so entries cannot
be linked to each other or to the gate. A verifier MUST check that the body is about the digest;
then, with a pinned key whose `sha256(SPKI)` equals `log_id`, MUST verify the signed entry
timestamp (ECDSA P-256 over the canonical JSON of `{body, integratedTime, logID, logIndex}`), the
RFC 6962 inclusion proof from `sha256(0x00 || body)`, and the signed note in `checkpoint` with the
same key, whose size and root MUST equal the proof's. The proof's time is `integrated_time`.

An `rfc3161` proof holds `tsa_url` (informational) and `token` (base64 of a DER TimeStampToken)
whose imprint is SHA-256 of the raw digest bytes. A verifier MUST check the imprint; then, with
pinned roots, MUST check the signed attributes (`contentType`, `messageDigest`, a signing
certificate attribute), the signature over them, the signer's critical `timeStamping` extended
key usage, and a chain built only from the token's certificates up to a pinned root: issuer and
subject bytes equal, signature valid, issuer a CA allowed to sign certificates,
`pathLenConstraint` respected, no unknown critical extension, every certificate valid *at the
token's time*, not today, so old evidence keeps verifying. The proof's time is the token's
`genTime`. Accepted algorithms are ECDSA P-256 and P-384 with SHA-256, SHA-384 or SHA-512, and
RSA PKCS#1 v1.5 with those hashes and a modulus of at least 2048 bits. Anything else is
`ANCHOR_TSA_ALGORITHM_UNSUPPORTED`.

Trust roots are the reader's: `{"rekor_public_keys": ["<PEM or base64 SPKI>"], "tsa_roots":
["<PEM or base64 certificate>"]}`. A proof with no pinned root is `NOT_CHECKED`, never `VERIFIED`.
In both kinds the time MUST NOT be more than 300 s before the checkpoint's `created_at`
(`ANCHOR_BEFORE_CHECKPOINT`). There is no upper bound: a late anchor is honest and proves less,
and the reader sets the bound (`--anchored-before`).

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
| `checks.authorization`, `checks.execution` | `VERIFIED`, `FAILED` or `NOT_PRESENT`; bundles add `checks.checkpoint` and `checks.anchor` (`VERIFIED`, `FAILED`, `NOT_CHECKED`, or `NOT_PRESENT` when no anchor was given) |
| `anchor` | With an anchor: the result of 4.3 without `schema_version`. A failed anchor makes the whole verdict `INVALID` |
| `errors` | Codes, possibly with a parenthesised path; empty when `VERIFIED` |
| `trust.mode` | `PINNED_GATE_KEY` (independent) or `DATABASE_SELF_ATTESTED` (not independent; the CLI warns) |
| `trust.independent` | `true` only with a pinned key |
| `trust.gate_public_key`, `trust.executor_keys_pinned` | What was pinned |
| `trust.not_checked` | What this verification does not establish, as `CODE (explanation)`: `AGENT_REGISTRATION_AT_ISSUE`, `SINGLE_USE_CONSUMPTION`, `EXECUTOR_IDENTITY` (unless pinned), `PERMIT_LINKAGE` (outcome alone), `LEDGER_INCLUSION` (bundle without checkpoint), `COMPLETENESS` (every bundle), `CHECKPOINT_TIME` (bundle with no verified anchor), `ANCHOR_NOT_PINNED` (each proof with no pinned root), `TSA_REVOCATION` (a timestamp proof verified: revocation cannot be checked offline) |
| `bundle_digest`, `verify_url` | Bundles only |

Error codes a conforming verifier MUST produce for the corresponding defect include
`AUTHORIZATION_ID_MISMATCH`, `GATE_SIGNATURE_INVALID`, `AUTHORIZATION_GATE_KEY_NOT_PINNED`,
`INTENT_HASH_MISMATCH`, `AGENT_SIGNATURE_INVALID`, `EXECUTION_RECEIPT_ID_MISMATCH`,
`EXECUTION_GATE_SIGNATURE_INVALID`, `EXECUTION_GATE_KEY_NOT_PINNED`,
`OUTCOME_HASH_MISMATCH`, `EXECUTOR_SIGNATURE_INVALID`, `EXECUTOR_AGENT_COLLUSION`,
`POLICY_DIGEST_MISMATCH`, `AUTHORIZATION_POLICY_DECISION_MISMATCH`,
`AUTHORIZATION_DECISION_NOT_REPRODUCIBLE`, `AUTHORIZATION_REASON_CODES_NOT_REPRODUCIBLE`,
`AUTHORIZATION_NON_EXACT_NUMBER (path)`,
`EXECUTION_NON_EXACT_NUMBER (path)`, `UNKNOWN_FIELD (path)`, `TRACE_ACTION_ID_MISMATCH`,
`BUNDLE_ACTION_ID_MISMATCH`, `BUNDLE_VERIFY_URL_MISMATCH`, `BUNDLE_VERIFY_URL_INVALID`,
`CHECKPOINT_<reason>` and `CHECKPOINT_TENANT_MISMATCH`,
`CHECKPOINT_AUTHORIZATION_NOT_INCLUDED`, `CHECKPOINT_EXECUTION_NOT_INCLUDED`,
`ANCHOR_MALFORMED (path)`, `ANCHOR_CHECKPOINT_MISMATCH`, `ANCHOR_NO_CHECKPOINT`,
`ANCHOR_BEFORE_CHECKPOINT`, `ANCHOR_REKOR_ENTRY_MISMATCH`, `ANCHOR_REKOR_LOG_UNKNOWN`,
`ANCHOR_REKOR_SET_INVALID`, `ANCHOR_REKOR_INCLUSION_INVALID`, `ANCHOR_REKOR_NOTE_INVALID`,
`ANCHOR_TSA_TOKEN_MALFORMED`, `ANCHOR_TSA_IMPRINT_MISMATCH`, `ANCHOR_TSA_ATTRIBUTES_INVALID`,
`ANCHOR_TSA_SIGNATURE_INVALID`, `ANCHOR_TSA_ALGORITHM_UNSUPPORTED`,
`ANCHOR_TSA_SIGNER_INVALID`, `ANCHOR_TSA_CHAIN_INVALID`, and
`DUPLICATE_JSON_KEY` / `NON_EXACT_NUMBER` for refused input. A verifier MUST NOT report
`VERIFIED` with a non-empty `errors` list.

### 4.2 `tempus.checkpoint-verification.v1`

Returned by `verify_checkpoint`: `status` (`VERIFIED` or `INVALID`), `checkpoint_id`,
`events_verified`, and on failure `reason_code` (`ERR_UNTRUSTED_SIGNER`,
`ERR_SIGNATURE_INVALID`, `ERR_EMPTY_STREAM`, `ERR_SEQUENCE_GAP`, `ERR_TENANT_MISMATCH`,
hash-chain and root mismatches, `DUPLICATE_JSON_KEY`) and `message`.

### 4.3 `tempus.anchor-verification.v1`

Returned by `verify_anchor`.

| Field | Notes |
|---|---|
| `status` | `VERIFIED` (at least one proof verified, none failed), `NOT_CHECKED` (none failed, nothing pinned) or `INVALID` |
| `checkpoint_id`, `checkpoint_digest` | The digest as computed from the checkpoint given |
| `anchored_at` | Microseconds: the earliest verified proof's time. `null` unless `VERIFIED` |
| `proofs` | `{backend, status, anchored_at, errors}` per proof; `status` is `VERIFIED`, `NOT_CHECKED` or `FAILED` |
| `errors` | Document and proof errors together; empty unless `INVALID` |
| `not_checked` | What this result leaves open, in the form of `trust.not_checked` |

## 5. What verification means

`VERIFIED` means: every signed document in the input is byte-for-byte what the pinned
gate (and, where present, the agent and executor) signed, the documents refer to each
other consistently, and nothing in the input is outside the contracts. It does not mean
the action was wise, that the permit was used only once, or that nothing else happened:
those appear in `trust.not_checked`, and a conforming verifier MUST surface them rather
than stay silent. A document verified against the database it came from
(`DATABASE_SELF_ATTESTED`) is not independent evidence and MUST say so.

A verified anchor adds one statement: this checkpoint existed no later than `anchored_at`,
for anyone who trusts the roots they pinned. It says nothing about what the checkpoint leaves
out, and it cannot show that no later checkpoint exists.

## 6. Conformance

An implementation conforms to this specification when, for every file in
`conformance/evidence/` with the gate public key in `gate_public_key.txt`, it returns the
`status`, `kind`, `phase` (or one of `phase_any`), `checks` and `errors` listed for that
file in `expected.json`, and when it refuses the malformed inputs of section 2.1. For each
entry of `anchor_cases` it MUST return the listed `status`, per-proof statuses and `errors`,
both for the anchor alone against the checkpoint in `anchor_bundle` and alongside that bundle
(`checks.anchor`). `anchor_roots.json` holds the roots of a throwaway log and timestamp
authority made for the fixtures. The
fixtures are regenerated by `scripts/generate_conformance_evidence.py` whenever the
reference implementation's documents change; a change that alters an expected verdict is
a protocol change and needs a new schema version.
