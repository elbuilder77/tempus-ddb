# Tempus contrib executors (HTTP, Slack, payments)

Reference mediated executors for Tempus permits that are **not part of the `tempus-ddb`
wheel**. They run on the core `ExecutorRuntime`, pass the same `AdapterConformanceHarness`
as the GitHub executor, and hold the downstream credential in their own process so the
requesting AI agent never sees it.

| Console script | Adapter | Supported actions |
| --- | --- | --- |
| `tempus-http-executor` | `tempus_executors.http.HttpExecutorAdapter` | `http.post`, `http.put`, `webhook.send` |
| `tempus-slack-executor` | `tempus_executors.slack.SlackExecutorAdapter` | `slack.post_message`, `slack.send_alert` |
| `tempus-payment-executor` | `tempus_executors.payment.PaymentExecutorAdapter` | `finance.disburse`, `finance.transfer`, `payment.charge` |

## Why they are not in the wheel

The `tempus-ddb` package is the protocol: the gate, the permit verifier, the
`ExecutorRuntime`, the conformance harness and one reference executor (GitHub,
`tempus_ddb.github_executor`). Everything an integrator needs to write and certify an
adapter is there. The HTTP, Slack and payment adapters are *integrations* on top of that
protocol: useful as working examples and as drop-in executors, but each one carries
product decisions (an SSRF filter, a channel grammar, a mock payment transport) that do
not belong in the core surface and would otherwise be versioned and released with it.
Tempus Guard for GitHub (`tempus-github-app`) is the GitHub executor for production use.

This distribution (`tempus-executors-contrib`) is therefore **not published to PyPI**
(its metadata carries the `Private :: Do Not Upload` classifier). It is installed from
the repository and versioned with it.

> **Deprecated since 0.7.0, removed in 0.9.0.** These executors are kept here through the
> 0.8 line as working examples and will be deleted from the repository in 0.9.0, as
> [`COMPATIBILITY.md`](../../COMPATIBILITY.md) records. Build production integrations as
> your own `ActionAdapter` on `ExecutorRuntime`, certified with the conformance harness,
> and use Tempus Guard for GitHub for GitHub writes.

## Install

From a checkout of `tempus-ddb`, with the core installed (`pip install tempus-ddb` or
`maturin develop` / `pip install -e .`):

```bash
pip install -e contrib/executors
```

That provides the `tempus_executors` package and the three console scripts. `--no-deps`
is fine when the core is already installed in develop mode (CI does that so pip does not
replace the local build).

```python
from tempus_executors import HttpExecutorAdapter, SlackExecutorAdapter, PaymentExecutorAdapter
```

Tests: `python -m pytest contrib/executors/tests`. They use the repository root
`pyproject.toml` for pytest and ruff settings; contrib has none of its own.

## Usage

**Where `permit.json` comes from.** It is the output of `tempus request-action` (see
*End-to-end from the CLI* in [`docs/REFERENCE.md`](../../docs/REFERENCE.md)):
`tempus request-action --intent intent.json --agent-keyfile agent.keys.json > permit.json`.
`--gate-id` is the gate's public key (the `public_key` in the gate's `keys.json`, also
printed by `tempus whoami`), `--tenant-id` must match the permit's tenant, and
`--executor-keyfile` must be the identity that the policy lists in `allowed_executors`.
The executor verifies the permit, consumes it once in its own `--executor-db` (a second
run of the same permit is refused), performs the action with the credential only it
holds, and prints its signed result. Reporting that outcome to the gate (so it appears in
the trace) is the separate `tempus commit-outcome` step, as the cookbooks do. An expired
permit (`--ttl-seconds`) or a `BLOCKED` one is rejected.

### HTTP & Webhook Executor (`tempus-http-executor`)
Executes HTTPS POST/PUT webhooks and external API mutations while isolating authorization headers:
- Supported actions: `http.post`, `http.put`, `webhook.send`.

```bash
tempus-http-executor \
  --permit permit.json \
  --executor-db http-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --allowed-domains api.example.com \
  --auth-header "Bearer <isolated-api-secret>"
```

- **Credentials need an allowlist.** The `Authorization` header is added to every request,
  so the executor refuses to start with `--auth-header` (or `HTTP_EXECUTOR_AUTH_HEADER`)
  unless `--allowed-domains` / `allowed_domains` / `HTTP_EXECUTOR_ALLOWED_DOMAINS` names the
  hosts that may receive it (`*` accepts every host, explicitly). Pattern matching now
  respects component boundaries: an entry matches that host only, and `*.domain` matches
  labels under that domain but not the apex. An exact host does not include its subdomains.
  A `*` glued to text matches nothing.
- **Policy patterns match whole components.** `allowed_resources`, `allowed_action_types`,
  `allowed_executors`, `allowed_currencies` and `allowed_beneficiaries` split on `/` and `.`.
  A `*` matches only as a whole component, so a path pattern such as `https://api.example.com/*`
  or `acme/*` covers what follows that separator, and `*.domain` covers labels under that
  domain. A `*` glued to the surrounding text matches nothing.
  `tempus install-policy` prints a WARNING for `http(s)` patterns with no `/` before the `*`.
- **Ports are not restricted by the allowlist** (`:8443` on an allowed host is still allowed).
  A policy pattern matches the URL text, so a pattern without the port does not match a URL
  that includes one. Pin the port in the pattern when it matters
  (`https://api.example.com:8443/*`).
- **No `.`/`..` path segments**, plain or percent-encoded (`%2e%2e`, `%252e%252e`, `..%2f`),
  and no backslashes: the policy matches the URL *text*, so `/v1/../admin` would pass
  `https://api.example.com/v1/*` while the server serves `/admin`.
- **The SSRF filter is a guard, not complete protection.** It refuses `localhost`
  names, and any host that is or resolves to a loopback, private, link-local, CGNAT,
  unspecified, multicast or reserved address or a known cloud-metadata address, in any
  spelling (`127.1`, `2130706433`, `0x7f000001`, `[::ffff:127.0.0.1]`, ...). The name is
  resolved once, every answer is checked and the connection goes to that validated IP
  (TLS still verifies the certificate for the name), which closes DNS rebinding for direct
  connections. It does **not** cover: ports (above); an `HTTPS_PROXY`/`https_proxy` in the
  environment (the proxy resolves the target, so the name is checked but not pinned, and
  the proxy's own reachability is yours to restrict); internal names you put in the
  allowlist (they are refused too if they resolve to private space; this executor has no
  opt-out); public services that are themselves open relays; or a compromised DNS that
  answers consistently with a public attacker address. Keep network egress rules as the
  real boundary.
- **Known limits** (informational, not fixed): ports are not restricted (H4, above); the
  conversion of an adapter's output has a size/node budget but **no time limit** (D2-a: a
  hostile custom adapter whose `__repr__` sleeps or never returns blocks the executor; the
  packaged adapters are not affected); and a very large legitimate output is recorded as a
  degraded summary with **no digest of the full output** (D2-b).
- The executor sends exactly the URL the policy matched, with no whitespace, control
  characters, backslashes or credentials in it.
- An ambiguous transport outcome is recorded as `UNKNOWN` and is not retried.
  Classification uses the exception type. A validation failure is `FAILED`.

### Slack Executor (`tempus-slack-executor`)
Dispatches channel alerts and notifications while isolating `SLACK_BOT_TOKEN`:
- Supported actions: `slack.post_message`, `slack.send_alert`.
- The permit `resource` is the channel and must be **exactly one**: an ID (`C`, `G` or `D` +
  uppercase letters/digits, e.g. `C0123ABCD`) or a `#channel-name` (lowercase letters, digits,
  `-`, `_`). Slack reads a comma-separated `channel` as several, so `C0123,C9999` is rejected
  (`TEMPUS_SLACK_BINDING_REJECTED`) before anything is sent. Policy patterns match whole
  components. Put the exact channel in `allowed_resources`.

```bash
tempus-slack-executor \
  --permit permit.json \
  --executor-db slack-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --token "xoxb-<isolated-slack-bot-token>"
```

### Pluggable Financial Adapter (`tempus-payment-executor`)
Reference pluggable executor that enforces the universal `money` envelope (`amount` or `amount_minor`, `asset` or `currency`, `beneficiary`; fields that disagree are refused) and minor-unit limits with credential isolation:
- Supported actions: `finance.disburse`, `finance.transfer`, `payment.charge`. Each one
  requires a `money` object and a non-zero amount; a missing, null, or zero amount is
  refused (`TEMPUS_INVALID_CONTRACT`) and nothing is signed.
- **Bring Your Own Provider:** Implements a pluggable `PaymentTransport` interface. Shipped with a deterministic mock transport for verification and testing; plug in your real Stripe/Wise API client at the transport boundary without exposing payment keys to the AI agent.

```bash
tempus-payment-executor \
  --permit permit.json \
  --executor-db pay-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --secret-key "sk_live_<isolated-payment-key>"
```

- **Minor units assume two decimals.** `amount_minor` and the `max_money_amount_minor` limit
  are read as hundredths (`"25.5"` is `2550`) for every currency. That is wrong for zero-
  decimal currencies (JPY: `"500"` means 500 yen, but the limit sees 50 000 minor units) and
  for three-decimal ones (BHD, KWD). Express limits per currency with that in mind, or keep
  such currencies out of `allowed_currencies`.
- `money.beneficiary` must be a non-empty string; it is paid exactly as written.
- An ambiguous payment-transport outcome is recorded as `UNKNOWN`. A definitive
  provider or validation error is `FAILED`. The transport must raise the real
  exception (or `AmbiguousTransportError`) when the outcome is not known.
  `allowed_currencies` accepts only exact 3-letter codes.
- **This executor is not a complete payment control.** It checks, per intent, the currency,
  the beneficiary pattern and one maximum amount, with the same component patterns as the
  policy for the beneficiary; it has no
  cumulative, daily or velocity limits, no sanctions/KYC checks, no confirmation of the
  provider's settlement, and the shipped transport is a mock. Put the real controls
  (provider-side limits, approvals, reconciliation) at the provider.

## Writing your own adapter

These three modules are also the worked examples for the `ActionAdapter` protocol: each
one validates the intent against its own allowlist, calls a transport that can be
replaced in tests, maps transport failures to `FAILED` or `UNKNOWN`, and wraps itself in
`ExecutorRuntime`. Run `tempus_ddb.testing.AdapterConformanceHarness` against a new
adapter the way `tests/test_conformance.py` does here.
