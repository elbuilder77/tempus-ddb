# Connect Tempus over MCP

Install a package containing `tempus quickstart` (until released, install this
checkout with `python -m pip install -e .`). MCP uses the same database as the CLI,
inside an explicitly configured directory. Connecting it does not configure an
external executor or a requesting-agent signer.

## 1. Check a connection with no action history

Create a new directory, enter it and run `tempus init`. This initializes the Gate
and database. Configure your MCP client's server JSON with absolute paths:

```json
{
  "mcpServers": {
    "tempus": {
      "command": "C:/path/to/venv/Scripts/python.exe",
      "args": ["-m", "tempus_ddb.cli", "mcp", "start"],
      "env": {
        "TEMPUS_WORKSPACE": "C:/path/to/your/initialized-directory",
        "TEMPUS_DB_PATH": "tempus.db",
        "TEMPUS_GATE_KEYFILE": "keys.json",
        "TEMPUS_MODE": "autonomous"
      }
    }
  }
}
```

Use your installed Python executable (`/absolute/path/.venv/bin/python` on Unix).
`TEMPUS_WORKSPACE` fixes the server's path boundary independently of the client's
working directory. Database and Gate key paths resolve inside that directory;
paths escaping it are rejected. `TEMPUS_DB_PATH` is the default for autonomous
tools; `db` is optional. No agent/executor private key belongs in the MCP
configuration or chat.

After adding the server entry and reconnecting, ask: **“Call tempus_list_agents
with no arguments and show the registered Gate.”** Expected: `status: success`
and the Gate in `agents`. This works before any action exists. A missing database
returns an initialization error instead of silently creating a different one.

## 2. Produce and inspect a known action

In an operator terminal, run:

```bash
tempus quickstart --directory tempus-first-action
```

This creates a separate trial, registers agent and executor, installs an explicit
policy, signs a request, consumes the permit, writes a local issue file and
commits the signed outcome. It prints an action ID and verification command and
persists the evidence. No GitHub call is made.

Import the generated `tempus-first-action/mcp.json` server entry into your client.
It contains your Python executable, workspace and matching Gate key filename.
Reconnect, then ask:

> Call tempus_verify_trace with action_id set to the ID printed by quickstart
> (also saved in result.json). Explain recorded authorization, execution and
> evidence integrity separately.

Expected: `VERIFIED`, phase `COMPLETED`. Do not ask for “the latest action” without
an ID; discover IDs with `tempus actions` against the trial database.

## 3. Connect signing and execution

Follow the complete [GitHub issue recipe](../docs/FIRST_ACTION.md). The operator
command connects the local agent signer to the Gate, passes its permit to the
credential-holding executor and commits its signed outcome. This is a guided
development environment with separate key files on one machine; production
requires isolated service accounts/processes for these roles.

For a production agent, its host signs the exact intent locally and sends
`intent`, `agent_id` and `agent_signature` to `tempus_request_action_signed`.
The executor verifies/consumes the permit and sends its signed outcome through
`tempus_commit_outcome_signed`. The model receives public identities, permits and
results, never private keys or `GITHUB_TOKEN`. Installing the MCP entry alone
does not implement this host/executor connection.

Autonomous tools include signed request/commit, trace lookup/verification, agent
registry, policies and identity events. Administrative, destructive and local-key
signing tools remain disabled by default.

If connection fails, check the Python executable, workspace, database and Gate
key; run `tempus list-agents` with those same paths. A `doctor` failure about
workload policy is a setup issue, not a failed MCP transport connection. See
[recovery](../docs/FIRST_ACTION.md#recover-without-repeating-an-effect).
