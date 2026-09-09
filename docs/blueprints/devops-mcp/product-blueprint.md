# B2A Gate for DevOps Agents over MCP — Product Blueprint

*Based on the B2A (Bot-to-Agent / Bot-to-Action) toll gate pattern from [tempus-ddb](https://github.com/elbuilder77/tempus-ddb), adapted for custom and standard Model Context Protocol (MCP) servers controlling GitHub PRs, repository changes, and Slack/Discord alerts.*

---

## Tagline
**Ensure opening a Pull Request or dispatching a production alert always requires an unforgeable cryptographic permit, never an ambient tool with direct API access.**

---

## The Problem
Modern autonomous agent runtimes—including **OpenClaw**, **Hermes Agent (Nous Research)**, **Cursor**, **Claude Desktop**, **Windsurf**, **OpenHands**, and **Aider**—interact with external environments through the Model Context Protocol (MCP) or custom function calling.

Today, teams commonly expose MCP tools that directly open GitHub Pull Requests, merge code, or post alerts to Slack. If those MCP tools hold `GITHUB_TOKEN`, GitHub App private keys, or `SLACK_BOT_TOKEN` in the same memory space or process handling the agent:
1. **Prompt Injection & Indirect Poisoning:** An agent reading an untrusted GitHub issue, pull request diff, or dependency manifest containing malicious hidden instructions can be tricked into exfiltrating data, opening backdoored PRs, or pinging unauthorized webhooks.
2. **Hallucination & Infinite Loops:** A malfunctioning loop in an autonomous agent (e.g. OpenClaw or OpenHands running overnight) can spam dozens of duplicate PRs or flood internal Slack channels.
3. **Ambient Authority:** The agent holds *ambient privilege*. Any tool call it generates is executed immediately by the MCP server without cryptographic verification of intent or policy compliance.

---

## The Solution: The B2A Toll Gate
Introduce a cryptographic toll gate between the agent runtime and destructive/state-changing external tools:

```text
┌──────────────┐         Signed Intent         ┌──────────────┐
│  AI Agent    │ ────────────────────────────► │  Tempus Gate │
│ (OpenClaw /  │                               │ (Policy &    │
│  Hermes /    │ ◄──────────────────────────── │  Permits)    │
│  Cursor)     │      Single-Use Permit        └──────────────┘
└──────┬───────┘                                       ▲
       │                                               │
       │ Consume Permit                                │ Dual-Signed
       ▼                                               │ Receipt
┌──────────────┐      External Side Effect     ┌───────┴──────┐
│ MCP Executor │ ────────────────────────────► │ GitHub/Slack │
│ (Isolated    │   (Create PR / Send Alert)    │ (External    │
│  Token)      │                               │  Service)    │
└──────────────┘                               └──────────────┘
```

1. **Intent Signing:** The agent signs its exact intended action (`github.create_pull_request`, target repo `acme/infrastructure`, branch, title, diff hash) using its local Ed25519 workload key.
2. **Policy Evaluation & Single-Use Permit:** The Gate validates the intent against a deterministic, signed policy bundle (permitted repos, allowed branches, rate ceilings, approved executors). If valid, it mints an expiring, single-use signed permit.
3. **Isolated MCP Execution:** An isolated executor process—which exclusively holds `GITHUB_TOKEN` or GitHub App credentials—validates and atomically consumes the permit. It executes the real write against GitHub.
4. **Tamper-Evident Receipts:** Gate and Executor dual-sign an immutable cryptographic receipt, stored in an append-only event stream verified offline.

---

## Target Audience
* **Platform & DevOps Engineering Teams:** Equipping developer agents (Cursor, Windsurf, Aider, OpenHands) with write access to repositories while guaranteeing branch protection and PR boundaries.
* **Autonomous Operations Teams:** Running autonomous runtimes like **OpenClaw** or **Hermes Agent** on infrastructure tasks, requiring cryptographic proof that every commit or alert conformed to policy.
* **Security & Compliance Officers (CISOs):** Requiring mathematical audit trails that prove who requested an action, what policy authorized it, and what external artifact was created.

---

## Why Tempus B2A Gate vs Traditional MCP Inline Checks?

| Dimension | Inline MCP Tool Checks / MCP Proxies | Tempus B2A Gate Architecture |
|---|---|---|
| **Trust Domain** | The same process inspects input, checks rules, and executes. | **Decoupled:** The Gate authorizes; a distinct isolated process executes. |
| **Credential Storage** | `GITHUB_TOKEN` lives in memory accessible to the tool host. | **Strictly Isolated:** Tokens live only in the executor process; never visible to the agent or chat prompt. |
| **Replay & Loop Resistance** | Repeated tool calls within quota limits succeed repeatedly. | **Cryptographic Single-Consumption:** Once consumed, the permit is permanently spent. Retries fail closed. |
| **Tamper Evidence** | Server log lines (easily forged, truncated, or lost). | **Dual-Signed Receipt:** Mathematically verifiable offline without trusting server logs. |
| **Prompt Injection Defense** | System prompts ("Do not touch repo X") can be bypassed by jailbreaks. | **Mathematical Constraint:** The Gate rejects any intent outside signed policy, regardless of model conviction. |

---

## Supported Ecosystems & Runtime Integrations

### 1. OpenClaw
OpenClaw agents run autonomous tool-execution loops. By configuring OpenClaw to call the Tempus autonomous MCP server (`tempus_list_agents`, `tempus_request_action`), OpenClaw can request permits without holding repository secrets.

### 2. Hermes Agent (Nous Research)
Hermes 2 and Hermes 3 function-calling models execute structured JSON schemas. Hermes generates the signed intent envelope; the isolated executor handles the downstream GitHub/Slack interaction.

### 3. Cursor, Windsurf & Claude Desktop
Using the standardized `mcpServers` configuration (`cookbooks/mcp_cursor_claude_quickstart.md`), developer agents operate in autonomous mode with zero credential exposure in developer terminals.

### 4. OpenHands & Aider
Software engineering agents generating pull requests can route their output through `tempus-github-executor`, preventing unauthorized push actions on sensitive repositories.

---

## Build vs. Use Tempus DDB Out-of-the-Box

Tempus DDB already ships the necessary components out-of-the-box:
* **Packaged Reference Executors:**
  * `tempus-github-executor`: Native support for Personal Access Tokens and installation-scoped **GitHub Apps** (`issues: write`, `pull_requests: write`) with automatic token rotation, HTTP redirect blocking (`_RejectRedirects`), and error sanitization.
  * `tempus-slack-executor`: Scoped Slack message and alert dispatch.
* **Autonomous MCP Server:** Exposed via `tempus mcp start` with workspace boundary lockdown (`TEMPUS_WORKSPACE`) and ambient tool suppression.
* **Quickstart Verification:** Run `tempus quickstart` to test end-to-end local permit issuance in seconds.
