# Tempus DDB roadmap

Tempus is a fail-closed policy gate for autonomous agent actions: every effect needs a
signed, single-use permit, and every effect leaves a signed receipt that anyone can
verify with the gate's public key. The protocol (the `.v1` contracts in
[SPEC.md](SPEC.md)), the policy evaluator, the ledger and the verifier live in this
repository; the other Tempus products are built on them and never redefine them.

The roadmap is ordered by what each step makes possible: a public verifier before a PR
check that links to it, a PR check before anchoring, both before a hosted console, and an
independent security review before general availability. Platform work (distributed gate,
quotas, telemetry) comes last, when a paying deployment needs it.

## Shipped: 0.4 and 0.5

- Versioned intent, authorization, outcome, receipt, trace and verification contracts.
- Separate gate, requesting-agent and executor Ed25519 identities; tenant-scoped
  delegation, signed rotation and revocation, historical key resolution.
- Signed deterministic policies with reproducible evidence and closed reason codes.
- Single-use expiring permits; an executor that cannot tell whether an effect happened
  records `UNKNOWN` instead of retrying.
- Local and Vault Transit signing through one provider boundary.
- Mediated executors for GitHub, HTTP, Slack and payments, with an adapter conformance
  suite.
- Append-only hash-linked event stream, gate-signed monotonic checkpoints, offline
  rollback detection, backup and disaster-recovery procedures.
- Default-deny on `tempus init`, strict JSON (duplicate keys and inexact numbers refused),
  component-boundary pattern matching, independent verification with a pinned gate key.
- Signed releases with provenance and SBOMs; Trusted Publishing to PyPI and crates.io.

## 0.6 — Evidence (this release)

Evidence at the front: anyone who is handed a receipt or a bundle can verify it in a
browser, without installing anything and without trusting the gate that issued it.

- Public browser verifier at <https://tempus-protocol.github.io/tempus-ddb/verify.html>:
  the wasm32 build of this crate, offline, pinned gate key, plain-language account of
  what the document cannot show.
- `verify_url` in every signed permit and execution receipt (`#action=<action_id>`) and
  in every evidence bundle (`#bundle=<sha256 of the canonical bundle>`); the verifier
  checks that link and file belong together.
- [SPEC.md](SPEC.md): the fifteen contracts, canonicalization, hashing and signatures,
  with real conformance fixtures in `conformance/evidence/` that the native verifier, the
  browser verifier and third-party implementations are tested against.
- The pre-protocol decision ledger (`record`, `verify`, `export`, `list`, `count`,
  `TEMPUS_LEGACY_TOOLS`) and the key-file MCP tools (`TEMPUS_LOCAL_KEYFILE_TOOLS`) are
  removed. The gate signs permits and receipts; nothing else is evidence.

Exit criteria: the browser verifier and `tempus verify-bundle` return the same verdict for
every conformance fixture; a bundle exported by a 0.5.4 gate still verifies.

## 0.7 — Guard

Tempus Guard for GitHub: the first installable product on the protocol.

- A GitHub App check on every pull request, "Verified by Tempus", linking to the public
  verifier with the bundle for the agent's action.
- The GitHub executor (`tempus-github-app`) issues the permit-bound push with a
  short-lived token and exports the bundle the check links to.
- The Tempus Guard CLI (`tempus guard`; repository `tempus-guard-cli`, formerly Ciel) emits Tempus
  intents and consumes permits instead of keeping its own ledger and policy language.
- One policy evaluator (`jsonlogic-fast`) for the gate and the local client.
- Dogfooding: every agent push to the project's own repositories goes through Guard.

Exit criteria: an agent can open a PR only through a permit, and a reviewer can verify
the PR's evidence from the check without any Tempus install.

## 0.8 — Anchor

- `tempus anchor`: checkpoints anchored to an external, append-only medium with
  pluggable backends (the `chain` module of the archived Decision-Database becomes the
  first one), so a deleted or rolled-back gate database is detectable from outside.
- Policy rules in `jsonlogic-fast` with signed rule bundles; the dev allow-all policy
  stays an explicit opt-in.
- Mandatory money ceilings for `finance.*` policies; payment executor safe by default.

Exit criteria: a verifier holding only the gate public key and an anchor reference can
tell whether the exported stream is the one the gate committed to.

## 0.9 — Console

Tempus Advance, a hosted read-only console over the same contracts.

- Multi-tenant read API that serves traces, bundles and checkpoints and never sits in the
  authorization path.
- Views derived only from verified documents; every view links to the public verifier.
- The first tenant comes from Guard for GitHub.

Exit criteria: the console shows nothing it cannot verify, and losing the console does
not stop or weaken a single gate.

## 1.0 — General availability

- Independent security review and remediation of high-severity findings.
- Release, upgrade, key rotation, revocation, backup and incident procedures exercised in
  a clean environment.
- Stable read API; supported deployment profiles with their availability guarantees.
- Only then the platform work deferred from the old 0.6: a transport-neutral distributed
  gate, tenant quotas and rate limits, opt-in OpenTelemetry metrics. It is built when a
  console customer needs it.

## Product principles

- No permit, no effect; every effect produces a verifiable receipt.
- Humans inspect history but do not sit in the autonomous transaction loop.
- Unknown schemas, policies, identities and execution states are rejected or denied,
  never treated as allowed. With no installed policy the gate denies every action and
  signs the denial.
- Credentials belong to mediated executors, never to requesting agents.
- One protocol, one policy evaluator, one ledger, one brand across every Tempus product.
- Performance, availability and compliance statements require reproducible evidence.

Security assumptions and current limitations are maintained in
[THREAT_MODEL.md](THREAT_MODEL.md). Compatibility commitments are maintained in
[COMPATIBILITY.md](COMPATIBILITY.md).
