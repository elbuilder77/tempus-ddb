# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| `0.5.x` | Current beta source line |
| `0.4.x` | Critical fixes only |
| `< 0.4` | Security fixes are not guaranteed |

No stable release has been published yet. Security fixes are developed on `main` and
will be included in the next tagged beta.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

- Open a private security advisory on GitHub: https://github.com/tempus-protocol/tempus-ddb/security/advisories/new

Please do **not** open a public issue for security vulnerabilities.

We aim to acknowledge a report within 48 hours and will coordinate disclosure and a fix
privately.

## Verifying a release

Release wheels, the source distribution, and the SPDX and CycloneDX SBOMs are
signed with GitHub artifact attestations. Those attestations are Sigstore
signatures stored in the repository. The verification commands and the manual
approval gate are documented in [docs/RELEASING.md](docs/RELEASING.md).

## Current Security Boundary

- The project is local-first. The SQLite databases are tamper-evident, not encrypted, and
  not independently protected against full deletion or rollback.
- Plaintext keyfiles are supported for local evaluation only. Production gate and executor
  processes should use the Vault Transit signer configuration and short-lived workload
  authentication. Signed rotation and revocation are implemented, but operators must
  distribute revocation state before relying on multiple executor instances.
- The in-tree GitHub executor (`tempus-github-executor`) is a single-instance adapter for
  issue and pull-request creation. It reads a personal access token from `GITHUB_TOKEN` in
  the executor environment only; an agent that also holds that token can bypass Tempus. The
  customer path is [`tempus-github-app`](https://github.com/tempus-protocol/tempus-github-app),
  which mints short-lived installation tokens and is the executor installed for a
  design-partner pilot.
- An executor result of `UNKNOWN` requires manual reconciliation and must never be retried
  automatically.
- Host permissions, backups, credential isolation, network policy, and downstream service
  controls remain operator responsibilities.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before using Tempus for any high-impact action.
