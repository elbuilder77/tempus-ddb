# Tempus compared with MCP gateways and RBAC

Several products govern what an agent may call: MCP gateways and proxies with role-based
access control (RBAC), tool allowlists, rate limits and audit logs. Tempus solves a
different problem, and the two are often used together.

A gateway answers *"may this agent call this tool?"* and then forwards the call. Tempus
answers *"did this exact effect happen under a permit that a policy issued, and can a
third party check that later without trusting anyone involved?"*

## The difference in one table

| Dimension | MCP gateway / RBAC | Tempus |
|---|---|---|
| Decision | Role or allowlist check, then forward. The agent and the downstream service are trusted after the check. | The agent signs an exact intent. The gate evaluates a signed, deterministic policy and issues a single-use, expiring, signed permit (`ALLOWED`) or a signed denial (`BLOCKED`). |
| Credentials | The agent or the gateway holds the downstream API keys and tokens. | The mediated executor holds them. The requesting agent never sees a downstream credential and cannot act without a permit. |
| Replay | Advisory rate limits; a repeated call within the role passes. | One permit, one outcome. A second, different outcome for the same permit is refused by the gate; the executor runtime refuses a reused permit. |
| Evidence | Application logs, editable by whoever runs the server. | Receipts signed by the gate and by the executor, hash-linked into an event stream with gate-signed checkpoints. Anyone with the gate public key verifies them offline. A public log and a timestamp authority can date a checkpoint from outside. |
| Who can check | The operator, by reading their own logs. | Anyone handed a receipt or an evidence bundle, in a browser (`verify.html`) or with the CLI, with no account and no network. The `verify_url` inside every receipt says where. |
| Money | Free-form JSON. | A `money` envelope (`amount`, `asset`, `beneficiary`) evaluated by the policy with exact decimal strings, each currency's own decimals, currency allowlists and ceilings. |
| MCP surface | Sits in front of other tools and forwards their traffic. | A voluntary MCP server: the agent calls Tempus tools to obtain permits and commit outcomes. Tempus does not intercept other tools' traffic. |

## What a gateway does that Tempus does not

- Intercept and forward arbitrary tool calls. Tempus is a toll the executor enforces,
  not a proxy in the data path.
- Manage human users, roles and sessions.
- Rate-limit or shape traffic.

## What Tempus does that a gateway does not

- Produce evidence a third party can verify without trusting the operator: a reviewer,
  an auditor, a customer, a counterparty.
- Bind the effect to the exact intent the agent signed, with a policy digest and
  reproducible policy evidence inside the signed permit.
- Detect omission, rollback and gaps in the record through hash-linked events and signed
  checkpoints, from outside the system.
- Prove from outside that a checkpoint existed by a date, with an entry in a public log and a
  timestamp token, with no trust in the operator or in Tempus.
- Run a policy's rules again in the verifier, in the browser too, so a gate cannot sign an
  `ALLOWED` its own rule denies without a reader finding it.
- Refuse ambiguous documents (repeated JSON keys, inexact numbers) so that "verified"
  means the same bytes everywhere.

## Using both

Keep the gateway for access control and traffic management. Put Tempus where an action
has an external effect that someone will later have to prove or dispute: pushes to
production repositories, payments, messages sent on a company's behalf, writes to a
system of record. The executor for that effect holds the credential and consumes the
permit; the gateway never needs to.

See the [README](../README.md) for the flow and [SPEC.md](../SPEC.md) for the contracts.
