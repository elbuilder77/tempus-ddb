# Compatibility and deprecation policy

Tempus DDB `0.5.x` is a design-partner beta. The project keeps wire contracts stricter
than its convenience APIs because authorization receipts may outlive a deployment.

## Wire schemas

- A schema name ending in `.v1` remains verifiable throughout the `0.x` series.
- New optional fields may be added to an existing schema when old readers can ignore
  them safely. Required-field removal, semantic reinterpretation, or an algorithm change
  requires a new schema version.
- Unknown schemas, signature algorithms, signer identities, policy versions, and reason
  codes fail closed at an execution boundary.
- Ed25519 remains the only algorithm for v1 receipts. A provider that cannot produce
  compatible Ed25519 signatures requires v2 contracts.

## CLI, Python, and MCP

- Patch releases preserve documented command names, Python methods, MCP tool names, and
  their required arguments.
- A deprecated interface remains available for at least one minor release and is listed
  in `CHANGELOG.md` with its replacement.
- Security-sensitive behavior may become stricter in a patch release. Such changes are
  called out explicitly and never turn a blocked action into an allowed action.

## Stored data

Database migrations are forward-only. Operators must back up the SQLite database before
upgrading. Historical identity keys, signed policy bundles, and receipts are retained so
that rotation or revocation does not erase earlier verification evidence.

Compatibility guarantees become stable at `1.0`; until then, every minor upgrade should
be rehearsed against a copy of production data and the adapter conformance fixture.
