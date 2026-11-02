# Contributing to Tempus DDB

Tempus DDB is a security boundary for autonomous actions. Contributions are welcome, but
changes to signed contracts, authorization decisions, identity lifecycle, or executor
state require stronger evidence than ordinary feature work.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening a change

- Use an issue or [GitHub Discussion](https://github.com/tempus-protocol/tempus-ddb/discussions)
  for changes that alter a public contract or trust boundary.
- Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Keep pull requests focused. Large protocol changes should be split into reviewable,
  independently testable steps.

## Development setup

Python 3.10 or newer and a stable Rust toolchain are required.

```bash
git clone https://github.com/tempus-protocol/tempus-ddb.git
cd tempus-ddb
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Branches

- `main` holds released code. Every change reaches it through a pull request; the
  repository accepts squash merges only.
- `desarrollo` is the integration branch for the next release. Open feature and fix
  pull requests against it. A release is one pull request from `desarrollo` to `main`,
  after which `desarrollo` is reset to `main` so the two branches do not diverge.

## Required validation

Run the same local gate used by CI:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo audit
ruff check .
pytest -p no:cacheprovider
python -m maturin build
```

Tests and examples must use temporary workspaces. Never commit databases, generated keys,
credentials, logs, caches, wheels, or build output.

## Security and compatibility expectations

- Keep unknown schema, policy, identity, signer, and execution states rejected or
  denied (never allowed), and keep the gate default-deny.
- Add an adversarial regression test for changes to replay prevention, signature
  verification, policy evaluation, credential isolation, or recovery.
- Treat signed JSON fields and machine status values as public contracts. Follow
  [COMPATIBILITY.md](COMPATIBILITY.md) before changing them.
- Do not add network telemetry or credential-bearing payloads by default.
- Update [THREAT_MODEL.md](THREAT_MODEL.md) when a trust boundary changes.
- Update [CHANGELOG.md](CHANGELOG.md) for user-visible behavior.

## Releases

Tagged releases are built by `.github/workflows/release.yml`. The procedure, the
manual approval gate, and the `gh attestation verify` commands are in
[docs/RELEASING.md](docs/RELEASING.md).

## Pull requests

Describe the problem, the chosen approach, security and compatibility impact, and exact
validation performed. Link the relevant issue with `Fixes #<number>` when applicable.

Use clear commit subjects such as `feat:`, `fix:`, `docs:`, `test:`, or `chore:`. Pull
requests are squash-merged, so the title and description become the commit on the base
branch.
