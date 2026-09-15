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

- Open a private security advisory on GitHub: https://github.com/elbuilder77/tempus-ddb/security/advisories/new

Please do **not** open a public issue for security vulnerabilities.

We aim to acknowledge a report within 48 hours and will coordinate disclosure and a fix
privately.

## Current Security Boundary

- The project is local-first. The SQLite databases are tamper-evident, not encrypted, and
  not independently protected against full deletion or rollback.
- Plaintext keyfiles are supported for local evaluation only. Production gate and executor
  processes should use the Vault Transit signer configuration and short-lived workload
  authentication. Signed rotation and revocation are implemented, but operators must
  distribute revocation state before relying on multiple executor instances.
- The GitHub executor is a single-instance adapter for issue and pull-request creation.
  Its token must exist only in the executor environment; an agent with the same token can
  bypass Tempus.
- An executor result of `UNKNOWN` requires manual reconciliation and must never be retried
  automatically.
- Host permissions, backups, credential isolation, network policy, and downstream service
  controls remain operator responsibilities.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before using Tempus for any high-impact action.
