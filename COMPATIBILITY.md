# Compatibility and deprecation policy

Tempus DDB `0.6.x` is a design-partner beta. The project keeps wire contracts stricter
than its convenience APIs because authorization receipts may outlive a deployment. The
contracts themselves are specified in [SPEC.md](SPEC.md).

## Wire schemas

- A schema name ending in `.v1` remains verifiable throughout the `0.x` series.
- New optional fields may be added to an existing schema when old readers can ignore
  them safely. Required-field removal, semantic reinterpretation, or an algorithm change
  requires a new schema version.
- Unknown schemas, signature algorithms, signer identities, policy versions, and reason
  codes are rejected at an execution boundary; they are never treated as allowed.
- Ed25519 remains the only algorithm for v1 receipts. A provider that cannot produce
  compatible Ed25519 signatures requires v2 contracts.

## CLI, Python, and MCP

- Patch releases preserve documented command names, Python methods, MCP tool names, and
  their required arguments.
- A deprecated interface remains available for at least one minor release and is listed
  in `CHANGELOG.md` with its replacement. The pre-protocol decision ledger (`record`,
  `verify`, `export`, `list`, `count`, `TEMPUS_LEGACY_TOOLS`) and the key-file MCP tools
  (`TEMPUS_LOCAL_KEYFILE_TOOLS`) were documented as non-evidence and development-only
  through the 0.5 line and are removed in 0.6.0; the signed flow (`request-action`,
  `commit-outcome`, `export-bundle`, `verify-bundle`) is the replacement.
- The HTTP, Slack and payment executors (`tempus-http-executor`, `tempus-slack-executor`,
  `tempus-payment-executor` and the `HttpExecutorAdapter`, `SlackExecutorAdapter`,
  `PaymentExecutorAdapter` classes) leave the `tempus-ddb` wheel in 0.7.0 and live in the
  repository as `contrib/executors/` (`tempus-executors-contrib`, installed from source,
  never published). They are deprecated from 0.7.0 and are removed from the repository in
  0.9.0. The GitHub executor stays as the `ActionAdapter` conformance reference; the GitHub
  product executor is `tempus-github-app` (Tempus Guard for GitHub). Writing your own
  adapter against `ExecutorRuntime` and the conformance harness is the replacement.
- `verify_url` (0.6.0) is additive: it sits inside the signed receipt bodies, which
  verifiers hash whole, and as an unsigned top-level bundle field that 0.6 verifiers
  check against the bundle digest. 0.5.x receipts and bundles verify unchanged.
- Security-sensitive behavior may become stricter in a patch release. Such changes are
  called out explicitly and never turn a blocked action into an allowed action.
- Pattern matching now respects component boundaries (`.` and `/`). A `*` that is not
  a whole component matches nothing. A `*` that is its own leading or middle component
  (`*.example.com`) used to be a dead literal and now matches that component; this is
  the one documented exception to the rule above, so review such entries before
  upgrading. That applies to every policy pattern list and to the payment beneficiary
  allowlist. The HTTP domain allowlist is an exact host, `*`,
  or `*.domain` (an exact host does not include its subdomains). See `CHANGELOG.md`
  and the README section "Common cases that now break, and how to fix them".
- A transport failure where the effect may already have happened (timeout, reset,
  disconnect, TLS, EOF, or HTTP 5xx) is recorded as `UNKNOWN` and is not retried.
  Classification is by exception type. A validation error stays `FAILED`. The same
  README section has the migration notes.

## Stored data

Database migrations are forward-only. Operators must back up the SQLite database before
upgrading. Historical identity keys, signed policy bundles, and receipts are retained so
that rotation or revocation does not erase earlier verification evidence.

Compatibility guarantees become stable at `1.0`; until then, every minor upgrade should
be rehearsed against a copy of production data and the adapter conformance fixture.
