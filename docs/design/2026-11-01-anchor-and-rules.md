# Anchoring, rules and per-currency decimals (release 0.8 "Anchor")

Design for phase 3 of the platform plan. Exit criterion: an auditor confirms from the
verifier that a checkpoint existed on a date, without trusting the operator or Tempus.

## 1. Decisions

| Question | Decision |
|---|---|
| Browser verifier scope | The WASM build verifies anchors completely, offline. The anchor document embeds everything; trust roots are pinned by the reader, as the gate key is today. Without a pinned root a proof is `NOT_CHECKED`, never `VERIFIED`. |
| EVM/Base | Out of 0.8. Decision-Database has no reusable anchoring code, and a third backend adds nothing the first two do not. Written from scratch if a customer asks. |
| Where an anchor lives | A separate document, `tempus.anchor.v1`. `tempus.evidence-bundle.v1` stays untouched (its field list is closed, so a new field would make 0.6/0.7 verifiers answer `INVALID`). |
| Who anchors | The gate operator, from the CLI or cron. Python talks to the log and the TSA (`_http.py`); Rust builds requests and verifies, sharing that code with WASM. The gate itself stays offline, as `THREAT_MODEL.md` promises. |
| Default TSA | DigiCert (`http://timestamp.digicert.com`), overridable with `--tsa-url` or `TEMPUS_TSA_URL`. A commercial CA with a long-lived root, and a different failure domain from Sigstore. Plain HTTP is fine: the token authenticates itself and only a hash travels. |
| Public Rekor in production | Acceptable. Proofs are verified offline, so the log's later availability does not matter. Each entry reveals one hash and when it was logged, under a throwaway key. Operators who need a private log pass `--rekor-url`. Using both backends is the default because they fail independently. |
| Rules | `rules` at the top level of `tempus.policy-bundle.v1`, a strict typed subset of JsonLogic, evaluated by `jsonlogic-fast`. Anything outside the types is `BLOCKED` with its own reason code. |
| Money | Optional `currency_exponents` constraint; 2 when absent, so old permits stay reproducible. |

Rekor v1 (`rekor.sigstore.dev`) is the log used. It is in maintenance mode but remains the
public-good default, and Sigstore commits to a year's notice before it stops accepting
uploads. Rekor v2 entries carry no signed time, so they would need a TSA anyway. A
`rekor-v2` proof type can be added later without touching this document's existing proofs,
and proofs already issued keep verifying after any shutdown because they are offline.

## 2. What is anchored

```
checkpoint_digest = sha256_hex(canonical(signed checkpoint, including its signature))
```

The plan speaks of "the root hash". The digest of the signed checkpoint commits to
`stream_root_hash` and also to the tenant, the sequence, `created_at` and the gate's
signature, so one anchor cannot be reused for a second checkpoint over the same stream, and
it shows the gate's *statement* existed, not merely some hash. Nothing about the tenant can
be read from the public entry. The anchor never enters the checkpoint: a new field there
would break its signature.

## 3. `tempus.anchor.v1`

```json
{
  "schema_version": "tempus.anchor.v1",
  "checkpoint_id": "chk_tenant_7_1793000000000000",
  "tenant_id": "tenant",
  "checkpoint_digest": "<64 hex>",
  "proofs": [
    {
      "backend": "rekor",
      "log_url": "https://rekor.sigstore.dev",
      "entry_uuid": "<hex>",
      "body": "<base64 of the logged entry>",
      "integrated_time": 1793000005,
      "log_id": "<64 hex>",
      "log_index": 1700000005,
      "signed_entry_timestamp": "<base64 DER ECDSA>",
      "inclusion_proof": {
        "log_index": 1578095743,
        "tree_size": 3515399928,
        "root_hash": "<64 hex>",
        "hashes": ["<64 hex>"],
        "checkpoint": "<signed note text>"
      }
    },
    {
      "backend": "rfc3161",
      "tsa_url": "http://timestamp.digicert.com",
      "token": "<base64 DER TimeStampToken>"
    }
  ]
}
```

The wrapper is unsigned; each proof authenticates itself. `log_url`, `entry_uuid` and
`tsa_url` are informational and never trusted. Field lists are closed (`UNKNOWN_FIELD`), as
in the bundle. `proofs` holds 1 to 8 entries. JSON is parsed strictly (repeated keys and
non-exact numbers refused).

### Producing a proof

- **Rekor.** The entry is a `hashedrekord` over `checkpoint_digest`, signed by a fresh P-256
  key that is discarded immediately. The key adds no trust: only the log's signature does.
  It is ephemeral so that entries cannot be linked to each other or to the gate, and so the
  gate key, possibly held in Vault, signs nothing new.
- **RFC 3161.** A `TimeStampReq` with SHA-256, a random nonce and `certReq = true`. The
  response must be granted and echo the nonce; the token is stored.

`tempus anchor create` checks every proof it receives as far as it can with no roots: that it is
about this checkpoint, and a token's own signature. A log's signatures need its key, so only
verifying with roots settles a Rekor proof. It merges into an existing `--out` file for the same checkpoint, keeping proofs it already holds. A failed
backend leaves the others written and exits non-zero, so a cron retry fills in the gap.

## 4. Verification

Trust roots, always supplied by the verifier:

```json
{"rekor_public_keys": ["<PEM or base64 SPKI>"], "tsa_roots": ["<PEM or base64 certificate>"]}
```

Document level, always: schema, closed fields, `checkpoint_digest` equals the digest
recomputed from the checkpoint given, `checkpoint_id` and `tenant_id` equal the checkpoint's.

Rekor proof:

1. The body is a `hashedrekord` whose `spec.data.hash` is `sha256:<checkpoint_digest>`.
   (Checked even with no pinned key.)
2. With a key pinned whose `sha256(SPKI)` equals `log_id`, verify the signed entry timestamp:
   ECDSA P-256 over the canonical JSON of `{body, integratedTime, logID, logIndex}`.
3. Recompute the RFC 6962 root from `sha256(0x00 || body)`, `inclusion_proof.log_index`,
   `tree_size` and `hashes`. It must equal `root_hash`.
4. Verify the signed note in `checkpoint` with the same key, and that its size and root equal
   the proof's.

The time is `integrated_time`.

RFC 3161 proof:

1. The token is a CMS `SignedData` holding one `TSTInfo`. Its message imprint is SHA-256 of
   the raw `checkpoint_digest` bytes. (Checked even with no pinned root.)
2. The signed attributes hold `contentType` = `id-ct-TSTInfo` and `messageDigest` = digest of
   the `TSTInfo`, and a signing-certificate attribute. A `signingCertificateV2` hash is
   checked against the signer's certificate. The older SHA-1 form is accepted without being
   recomputed: the certificate used is authenticated by the chain below in any case.
3. The signature over the signed attributes verifies with the signer's certificate, which
   must carry the critical extended key usage, naming `timeStamping` and nothing else.
4. The chain, built only from the token's certificates, reaches a pinned root. Each link:
   issuer and subject bytes equal, signature verifies, issuer is a CA allowed to sign
   certificates, `pathLenConstraint` respected, no unknown critical extension, every
   certificate valid *at `genTime`*, not today, so old evidence keeps verifying.

The time is the latest the token allows: `genTime` plus its `accuracy`, rounded up to a whole
second. Certificates are judged at `genTime` itself.

Accepted algorithms: ECDSA P-256 and P-384 with SHA-256/384/512; RSA PKCS#1 v1.5 with
SHA-256/384/512, a modulus of 2048 to 8192 bits and an odd exponent above 1 of at most 8 bytes. RSA-PSS, SHA-1 signatures and anything
else are `ANCHOR_TSA_ALGORITHM_UNSUPPORTED`.

Both proofs: the time must not be more than 300 s before `created_at`
(`ANCHOR_BEFORE_CHECKPOINT`): a checkpoint cannot be anchored before it exists. There is no
upper bound by default, because a late anchor is honest. It only proves less, and the auditor
sets the bound with `--anchored-before`.

### Results

`tempus.anchor-verification.v1` (`verify_anchor`):

| Field | Notes |
|---|---|
| `status` | `VERIFIED` (at least one proof verified, none failed), `NOT_CHECKED` (none failed, nothing pinned) or `INVALID` |
| `checkpoint_id`, `checkpoint_digest` | As computed |
| `anchored_at` | Microseconds. The earliest verified proof's time; `null` unless `VERIFIED` |
| `proofs[]` | `{backend, status, anchored_at, errors}` per proof; `status` is `VERIFIED`, `NOT_CHECKED` or `FAILED` |
| `errors` | Document and proof errors together; empty unless `INVALID` |
| `not_checked` | What the result leaves open, in the form of `trust.not_checked`. Always `CHECKPOINT_SIGNATURE`: only verifying a bundle shows a gate signed these bytes |

`verify_bundle` with an anchor adds to `tempus.trace-verification.v1`:

- `checks.anchor`: `VERIFIED`, `FAILED`, `NOT_CHECKED` or `NOT_PRESENT` (the last when no
  anchor was given, on every bundle).
- `anchor`: the object above, minus `schema_version`.
- A failed anchor turns the verdict `INVALID` and adds its codes to `errors`. A bundle with
  no checkpoint and an anchor is `ANCHOR_NO_CHECKPOINT`.
- `trust.not_checked` gains `CHECKPOINT_TIME (...)` unless an anchor verified,
  `ANCHOR_NOT_PINNED (...)` for each proof with no pinned root, and `TSA_REVOCATION (...)`
  when a TSA proof verified, because revocation cannot be checked offline.

Error codes: `ANCHOR_MALFORMED`, `ANCHOR_CHECKPOINT_MISMATCH`, `ANCHOR_NO_CHECKPOINT`,
`ANCHOR_BEFORE_CHECKPOINT`, `ANCHOR_REKOR_ENTRY_MISMATCH`, `ANCHOR_REKOR_LOG_UNKNOWN`,
`ANCHOR_REKOR_SET_INVALID`, `ANCHOR_REKOR_INCLUSION_INVALID`, `ANCHOR_REKOR_NOTE_INVALID`,
`ANCHOR_TSA_TOKEN_MALFORMED`, `ANCHOR_TSA_IMPRINT_MISMATCH`, `ANCHOR_TSA_ATTRIBUTES_INVALID`,
`ANCHOR_TSA_SIGNATURE_INVALID`, `ANCHOR_TSA_ALGORITHM_UNSUPPORTED`, `ANCHOR_TSA_SIGNER_INVALID`,
`ANCHOR_TSA_CHAIN_INVALID`, `UNKNOWN_FIELD (anchor...)`.

### CLI, Python, page

```
tempus anchor create --checkpoint <file> [--backend rekor|rfc3161]... [--rekor-url U] [--tsa-url U] [--out F]
tempus anchor verify --anchor <file> --checkpoint <file> [--rekor-public-key K]... [--tsa-root R]...
tempus verify-bundle ... --anchor <file> [--rekor-public-key K]... [--tsa-root R]... [--require-anchor] [--anchored-before DATE]
```

`--checkpoint` also takes an evidence bundle and uses its checkpoint. `--require-anchor` is
`REQUIREMENT_NOT_MET` unless `checks.anchor` is `VERIFIED`; `--anchored-before` implies it and
also requires `anchored_at` at or before the date.

The page gains an anchor file input and two fields for the pinned roots, a check row, and the
sentence an auditor came for: "this checkpoint existed no later than <date>". It still sends
nothing anywhere.

### Dependency choices

- **ECDSA:** `p256` and `p384` from RustCrypto, verification through the prehash interface,
  because real tokens mix curves and digests (Sigstore signs SHA-256 with a P-384 key, FreeTSA
  SHA-512 with P-384).
- **RSA:** a small verify-only routine over `crypto-bigint`, not the `rsa` crate. That crate
  carries RUSTSEC-2023-0071, unpatched, which would fail `cargo audit` in CI and flag every
  consumer, although it only concerns private-key operations that the verifier never does.
  The routine builds the exact EMSA-PKCS1-v1_5 encoding and compares bytes, so it has no
  padding parser to get wrong.
- **DER and X.509:** a strict hand-written reader of about 100 lines, not `der`, `x509-cert`
  and `cms`. Path validation has to be written either way, signatures need the exact signed
  bytes, which a decode-and-re-encode cannot promise, `cms` is still a release candidate, and
  the page's download matters. Tests mutate real tokens to check it never panics and never
  verifies a changed token.

## 5. Rules

Optional and at the top level of the bundle, so it is inside `policy_digest`:

```json
"rules": [
  {"id": "weekend-limit",
   "logic": {"or": [{"===": [{"var": "intent.action_type"}, "report.read"]},
                    {"<=": [{"var": "money.amount_minor"}, 50000]}]}}
]
```

Up to 32 rules, ids `[a-z0-9._-]{1,64}` and unique, each `logic` up to 256 nodes and depth 16.
Absent `rules` leaves the bytes, and therefore every existing digest, unchanged. `install_policy`
copies the field, and `validate_policy_spec` checks it, including when a verifier reads a
stored bundle.

What a rule sees, nothing else, so a verifier can reproduce it:

```json
{"intent": <the signed intent>, "ttl_seconds": 300,
 "money": {"amount_minor": 2500, "currency": "USD"}}
```

`money` is absent when the intent has none, because `missing` asks whether a key is there and a
key holding null is there.

A rule must evaluate to exactly `true`. `false` adds `POLICY_RULES_DENIED`; any failure adds
`POLICY_RULES_ERROR`. Either way the decision is `BLOCKED`. Because the logic lives in
`evaluate_policy`, the gate, the verifier (native and WASM) and the executor all re-execute it.

### Grammar

JsonLogic coerces like JavaScript: `"10" > 9`, `1 == "1"`, and arithmetic is floating point. The
plan requires integers and strings with floats refused, so rules are a typed subset, checked
statically at install and at evaluation time for what `var` returns:

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
Term := integer | string | true | false | null | Var | {"+"...} | {"-"...} | {"*"...} | {"min"...} | {"max"...}
Var  := {"var": "path"} | {"var": ["path", integer | string | true | false | null]}
```

A list in `in` holds literal strings only: JsonLogic does not evaluate inside a literal list, so a
`var` there would be compared as an object and never match. A path must sit under `intent`,
`ttl_seconds` or `money`, which catches a typo at install. `==`, `!=`, `/`, `%`, `substr`, `cat`,
`map`, `filter`, `reduce`, `all`, `some`, `none`, `merge`, `missing_some` and `log` are refused at
install. Integer literals and every value read as a
number must be exact and within ±(2^53 − 1). Arithmetic is binary so that each step can be
checked: IEEE addition and multiplication round correctly, so a result inside that range is
exact, and one outside it is an error.

The checker follows the same short-circuits as the evaluator and only checks what is reached,
so `{"if": [{"!": {"missing": ["money"]}}, {"<=": [{"var": "money.amount_minor"}, 100]}, true]}`
works without money. It computes nothing itself. Every value comes from `jsonlogic-fast`, so
there remains one policy evaluator. The evaluator parses its context for every node it is asked
about, so each rule gets only the paths it names, and an input of megabytes it never reads costs
nothing. What a rule does read is charged against 64 MiB of rule and context text per evaluation,
and past that it fails, so a hostile bundle costs its reader a bounded amount. A verifier also
reaches this with a bundle it has already refused, so a rule outside the grammar never reaches the
evaluator, whoever signed it.

Dependency: `jsonlogic-fast = "0.1.7"`, the published version. Its `evaluate` is all this needs,
and 0.2.0 is not on crates.io.

## 6. Per-currency decimals

A new optional constraint:

```json
"currency_exponents": {"JPY": 0, "KWD": 3}
```

Codes are exact, exponents 0 to 8. `amount` then means "at most that many fractional digits,
minor units are `amount * 10^exponent`". A currency not listed keeps exponent 2, so every
existing policy and permit reads the same. `max_money_amount_minor` is in that currency's own
minor units.

`validate_intent` runs before any policy is known, so it now checks only the shape of `money`
(types, grammar up to 8 digits). The exponent-aware reading, including `amount` against
`amount_minor` and the non-zero rule for payments, happens in `evaluate_policy`, which every
reader already calls, and fails with the same errors as today.

To close the warning, `install_policy` refuses a policy whose `allowed_currencies` names an ISO
4217 currency without two decimals and has no exponent for it:

- 0: BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF
- 3: BHD IQD JOD KWD LYD OMR TND
- 4: CLF UYW

The check is at install only, never on stored bundles. An operator who truly wants today's
reading declares `{"JPY": 2}`. The contrib payment executor mirrors the same reading.

## 7. Compatibility

| Change | Old readers |
|---|---|
| `tempus.anchor.v1` | Not read by 0.6/0.7. Bundles are unchanged. |
| `checks.anchor`, `anchor`, new `not_checked` entries | Additive. |
| `rules` absent | Bytes and digests unchanged. |
| `rules` present, permit `ALLOWED` | 0.6/0.7 verify it, without running the rules. |
| `rules` present, permit `BLOCKED` by rules | 0.6/0.7 recompute `ALLOWED` and answer `INVALID`. Fails closed; upgrade the verifier. |
| `currency_exponents` present | 0.6/0.7 answer `TEMPUS_POLICY_CONSTRAINT_UNKNOWN`. Fails closed. |
| `allowed_currencies` with `JPY` and no exponent | New installs refused; stored bundles keep working. Documented as a stricter install. |
| 3-decimal amount under a policy without the exponent | Still an error, now raised by `evaluate_policy` rather than `validate_intent`. With no policy installed the outcome is the signed `POLICY_NOT_INSTALLED` denial instead of an error: blocked either way. |

## 8. Testing

- **Real vectors, committed:** a real `hashedrekord` entry signed with a bare key (no OIDC
  identity), read from the public log, and real tokens from DigiCert (RSA, cross-signed root) and
  Sigstore (P-384) over a constant test digest. They prove the parsers against what the services
  really return. FreeTSA is used for a manual check but not committed, since its certificates
  carry a personal e-mail address.
- **Test authority:** `scripts/anchor_test_authority.py` is a local fake log and TSA. It produces
  the conformance fixtures (`conformance/evidence/anchor*.json`) and serves the CLI's end-to-end
  tests over localhost.
- **Hostile input:** mutation of real tokens and entries (never panics, and never changes what is
  proved: bytes outside the signed content, such as the SignedData version, may flip harmlessly),
  wrong key, wrong root, wrong digest, time before the checkpoint, unknown fields, expired certificate,
  non-TSA signer, unknown critical extension, RSA with a short modulus.
- **Parity:** every conformance case runs on the native and WASM verifiers.
- **Rules:** a table of accepted and refused grammar, coercion attempts, overflow, short-circuits,
  and a `BLOCKED` permit re-verified end to end. Money: JPY, KWD, the default, the install refusal,
  and old-fixture stability.

## 9. Not done here, on purpose

- **A live write to the public Rekor log.** Entries there are public and permanent, so that stays
  the operator's call. Reading real entries covers the verification side; the signature format of
  the request is tested against a real entry's signature. The first real `tempus anchor create`
  against the public log is the remaining end-to-end check.
- Revocation checks, witness cosignatures on Rekor checkpoints, and consistency proofs between
  checkpoints: none works offline from one document.
- `tempus.evidence-bundle.v2` with embedded anchors: only if an auditor asks for one file.
- Reporting which rule denied. Reason codes are a closed list; rule ids would need a schema change.
