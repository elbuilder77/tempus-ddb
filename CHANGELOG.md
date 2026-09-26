# Changelog

## [0.5.3] - 2026-09-26

First published build of the 0.5.2 security line. The `v0.5.2` release workflow
failed before building any artifact, so **0.5.2 was never published to PyPI or
crates.io**; 0.5.3 ships the same runtime code with a repaired release pipeline.

### Fixed
- **Release pipeline**: Four action pins in `release.yml` pointed to commit SHAs that do not exist upstream (`PyO3/maturin-action`, `actions/download-artifact`, `actions/attest-build-provenance`, `actions/attest-sbom`), which aborted the `v0.5.2` release at job setup. All pins now resolve to real tags (maturin-action v1.51.0, download-artifact v7.0.0, attest-build-provenance v2.4.0, attest-sbom v2.4.0).
- **Tag-exact builds**: Every release checkout now uses the release tag as `ref`, so manual re-runs build the tagged source instead of the dispatching branch.
- **Wheel test gate**: The pre-publish wheel tests imported the uncompiled `python/tempus_ddb` source (via pytest `pythonpath` and `tests/test_cli.py`) instead of the installed wheel, so they could never pass. The gate now removes the source package first and tests only the built wheel.
- **PyPI publishing**: Removed the unused `PYPI_API_TOKEN` password input; publication relies on Trusted Publishing (OIDC) only, as documented.
- **crates.io publishing**: The workflow read a `CRATES_IO_TOKEN` secret that was never configured, so the crate was silently skipped. It now uses `CARGO_API_TOKEN` in a separate job that cannot block the PyPI release.

### Changed
- Packaged sources no longer include the `launch/` marketing drafts removed after the `v0.5.2` tag.
- `python-dotenv` minimum raised to `>=1.2.3` (Dependabot #29).

## [0.5.2] - 2026-09-12 (not published)

### Security
- **Delegation Chain & Trusted Root Verification (Finding 1)**: Added `trusted_roots` table with single-root constraint; enforce recursive delegation chain checks ensuring all registered identities trace to an established root.
- **Signed Policy Activation & Strict Fallback (Finding 2)**: Added `active_policy_attestations` table storing cryptographic attestations over active policies; retired tenant policies fail closed instead of falling back to unconstrained wildcards; SSRF protection and destination domain allowlisting in `http_executor`.
- **Segregation of Duties & Role Enforcement (Finding 3)**: Prohibit proposing agents from executing their own permits (`executor_id != agent_id`); reject proposer roles from executor duty; enforce executor tenant scope matching.
- **Durability & Replay Defense Across Gate/Executor (Findings 4 & 6)**: Upgraded SQLite persistence to `PRAGMA synchronous = FULL;` across gate and executors; executors cross-verify revocation and consumption state against Gate DB before effectuating actions.
- **Financial Policy Beneficiary Validation (Finding 5)**: Enforce `allowed_beneficiaries` pattern matching in both policy evaluation and payment execution.
- **Untrusted Signer Rejection in Checkpoint Verification (Finding 7)**: Checkpoint stream verifier requires trusted public key and rejects checkpoints signed by arbitrary keys (`ERR_UNTRUSTED_SIGNER`).
- **Atomic State and Stream Mutations (Finding 8)**: Wrapped policy installations, authorizations, and outcome commits in immediate atomic SQLite transactions to eliminate race conditions between mutation and audit event logging.
- **Workflow Hardening (Finding 9)**: Pinned all GitHub Actions to immutable commit SHAs; added automated wheel testing and `cargo test` gates prior to release publication.
- **Windows CP1252 Compatibility**: Replaced all console and comment non-ASCII symbols with clean ASCII characters to prevent encoding crashes on Windows consoles.

## [0.5.0] - 2026-09-05

### Added
- **Append-Only Event Stream (`tempus.event-stream-event.v1`)**: Monotonically sequenced, hash-linked (`prev_event_hash` ➔ `event_digest`) event recording for all authorizations, outcomes, agent registrations, and policy installations.
- **Signed Monotonic Checkpoints (`tempus.checkpoint.v1`)**: Gate-signed external checkpoints binding cumulative SHA-256 stream root hashes and sequence windows (`first_sequence`..`last_sequence`).
- **Cryptographic Stream Verifier (`tempus.checkpoint-verification.v1`)**: Offline mathematical verification engine detecting rollback attacks (`ERR_ROLLBACK_DETECTED`), sequence gaps (`ERR_SEQUENCE_GAP`), broken chain linkage (`ERR_CHAIN_LINKAGE_BROKEN`), and single-byte tampering (`ERR_EVENT_TAMPERED`).
- **Unified Mediated Executor Runtime (`ExecutorRuntime`)**: Standardized base runtime with protocol `ActionAdapter` and conformance testing harness (`AdapterConformanceHarness` in `tempus_ddb.testing`).
- **CLI Checkpoint & DR Commands**: Added `tempus checkpoint create`, `tempus checkpoint export`, and `tempus checkpoint verify`.
- **Disaster Recovery Guide**: Published comprehensive procedures in `docs/BACKUP_AND_DISASTER_RECOVERY.md`.

## [0.4.2] - 2026-08-31

### Changed
- **Pluggable Financial Transport**: Clarified `tempus-payment-executor` and `PaymentExecutorAdapter` architecture as a pluggable reference adapter with `MockPaymentTransport` for CI/testing and `PaymentTransport` protocol for custom production payment gateways (Stripe, Wise, banking APIs).
- **Security Policy Badge**: Replaced unverified audit badge with `security-policy` badge linking to `SECURITY.md`.
- **Documentation & Install Synchronization**: Synchronized install guidance across README, PyPI metadata, and GitHub Pages emphasizing Sigstore provenance attestations and OIDC Trusted Publishing.

## [0.4.1] - 2026-08-31

### Added
- **Packaged Mediated Executors**: Added `tempus-http-executor` (generic HTTPS POST/PUT webhooks with isolated headers), `tempus-slack-executor` (isolated `SLACK_BOT_TOKEN`), and `tempus-payment-executor` (binding the universal `money` contract envelope and isolating payout secrets).
- **Cookbooks & Framework Integrations**: Added copy-paste recipes for **LangChain/LangGraph** tool guarding, **CrewAI** multi-agent financial delegation, and **Claude Desktop & Cursor MCP** autonomous setup.
- **Architectural Differentiation**: Added explicit technical comparison between Tempus DDB B2A zero-trust cryptographic toll and traditional RBAC/MCP proxies (Bifrost, Obot, MCPX, MintMCP).
- Exported `HttpExecutorAdapter`, `SlackExecutorAdapter`, and `PaymentExecutorAdapter` in the Python package root.

## [0.4.0] - 2026-08-27

### Fixed

- Kept the Rust quality gate compatible with current stable Clippy.
- Validate GitHub executor endpoints as absolute HTTPS URLs before an outbound request;
  malformed, credential-bearing, query-bearing, and plaintext endpoints fail closed.
- Restored standards-compliant Python package metadata by keeping `keywords` in the
  project metadata rather than treating it as an install extra.

### Changed

- Reused a bounded, configurable SQLite connection pool in the mediated executor instead
  of opening a new connection for every state transition.
- Added a recovery index and concurrent replay regression coverage proving that only one
  contender can consume a permit.
- Moved runnable demonstrations and the benchmark into `examples/` so the repository
  root contains only project configuration and public documentation.
- Updated repository, security, discussion, ownership, and SBOM links for
  `elbuilder77/tempus-ddb`.

### Phase 3

- A provider-neutral Rust signer boundary and verification-key resolver with compatible
  local Ed25519 and Vault Transit CLI backends. Signer URI, key version, and algorithm are
  bound into signed artifacts; unknown providers, algorithms, versions, and malformed
  responses fail closed.
- Signed deterministic policy bundles covering tenant, action type, resource, input size,
  optional money constraints, TTL, and allowed executors. Permits now bind the policy
  digest, reproducible evidence digest, executor constraints, and complete reason codes.
- Tenant-scoped identity delegation plus signed rotation and revocation events. Historical
  receipts resolve the key valid at signing time, while emergency revocation invalidates
  unconsumed permits.
- `tempus doctor`, policy and identity lifecycle commands, signer conformance checks, and
  a machine-readable adapter conformance fixture.
- SPDX 2.3 SBOM generation and GitHub artifact provenance/SBOM attestations in the release
  workflow, plus a compatibility policy and Vault Transit operating guide.
- Package maturity advances to design-partner beta (`0.4.0`). Existing v1 schema names
  remain compatible; the Phase 3 binding fields are additive and enforced by executors.

Live credentialed Vault and GitHub checks remain explicit opt-in tests; an integration
that was not run is never reported as passing.

### Added

- First complete local B2A authorization flow: signed action intent, gate permit,
  executor outcome, final receipt, trace reading, and end-to-end verification.
- Stable versioned JSON contracts and closed machine statuses for autonomous consumers.
- Signed, immutable agent registration events with a gate delegation root.
- Deterministic action idempotency, expiring permits, and single-consumption outcomes.
- Rust, Python, CLI, and MCP B2A surfaces plus replay/tamper/authorization tests.
- Public protocol boundary and production-oriented threat-model documentation.
- Signed MCP authorization and outcome tools for clients that keep agent and executor
  private keys outside the gate process.
- Signed executor observations for `STARTED`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`, plus
  restart recovery that never replays an ambiguous external effect.
- Packaged `tempus-github-executor` for exactly bound GitHub issue and pull-request
  creation with an executor-only credential.
- A public product roadmap with ordered Phase 3 trust and adoption milestones.
- Dependabot coverage for Cargo, Python, and GitHub Actions dependencies.

### Changed

- MCP defaults to the autonomous execution-gate surface. Administrative, legacy, and
  destructive tools now require explicit environment flags.
- Product positioning now treats money as optional action metadata and humans as
  read-only auditors rather than transaction approvers.
- Default MCP mode now exposes only signed B2A write tools. The compatibility tools
  that receive local keyfile paths require `TEMPUS_LOCAL_KEYFILE_TOOLS=1`.
- Phase 2 is complete for the single-instance GitHub adapter, including policy-version
  checks, exact argument binding, credential isolation, and crash recovery.
- Package metadata now reflects the actual Python 3.10+ MCP dependency and alpha status.
- The Python package exports its installed version and the GitHub executor derives its
  user-agent version from package metadata.
- Tests and runnable examples use self-cleaning temporary workspaces instead of leaving
  databases and generated keys in the repository root.

### Security

- Agent registrations can no longer be silently replaced.
- The gate signing key is server-controlled for MCP authorization requests.
- Unregistered agents are blocked before execution and conflicting permit reuse is
  rejected.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-26

### Changed
- Updated examples to the current free core API.
- Added smoke-test coverage for runnable example scripts.
- Stabilized release readiness for the free/open-core packaging and CI path.

## [0.2.0] - 2026-06-26

### Added
- Comprehensive CLI improvements: `tempus record`, `tempus status`, `tempus --version`
- Expanded test coverage with Python API tests and CLI integration tests
- Multiple end-to-end examples in `examples/`
- GitHub Actions CI workflow for multi-OS/Python testing
- Module docstrings and improved Python API documentation

### Changed
- Removed license gate entirely from Rust core and Python bindings for true free/open nature
- Simplified `TempusDDB` constructor to `TempusDDB(db_path, keyfile)`
- Updated positioning to emphasize "free, local-first, tamper-evident"
- Improved error handling and UX across CLI

### Fixed
- License generation to properly support direct CLI usage
- Constructor calls in tests and examples

## [0.1.0] - Previous

Initial public version with core Rust engine, MCP integration, and basic CLI.
