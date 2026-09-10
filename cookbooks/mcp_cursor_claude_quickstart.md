# 🔌 Tempus DDB MCP Quickstart: Claude Desktop, Cursor & Windsurf

Tempus DDB exposes a native **Model Context Protocol (MCP)** server. In **Autonomous Mode**, it enforces the B2A toll so LLMs can only request signed permits and verify execution receipts without exposing admin or destructive tools.

---

## 1. Quick Setup for Claude Desktop

Add Tempus to your `claude_desktop_config.json`:

* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tempus": {
      "command": "tempus",
      "args": ["mcp", "start"],
      "env": {
        "TEMPUS_MODE": "autonomous",
        "TEMPUS_GATE_KEYFILE": "/path/to/keys.json",
        "TEMPUS_DB_PATH": "/path/to/tempus.db"
      }
    }
  }
}
```

---

## 2. Quick Setup for Cursor IDE

In Cursor:
1. Open **Cursor Settings** ➔ **Features** ➔ **MCP**.
2. Click **+ Add New MCP Server**.
3. Fill in:
   * **Name:** `tempus-ddb`
   * **Type:** `command`
   * **Command:** `tempus mcp start`

---

## 3. Autonomous MCP Tools Exposed to the LLM

When connected in autonomous mode (`TEMPUS_MODE=autonomous`), Claude or Cursor will only have access to safe, audited machine tools:

| Tool Name | Action & Guard |
|---|---|
| `tempus_request_action_signed` | Verify signed intent and obtain a short-lived permit (`ALLOWED` / `BLOCKED`) |
| `tempus_commit_outcome_signed` | Consume permit with an executor-signed outcome |
| `tempus_get_trace` | Inspect action evidence & authorization decisions |
| `tempus_verify_trace` | Cryptographically verify SHA-256 hashes and Ed25519 signatures |
| `tempus_list_agents` | Read registered identities (read-only) |
| `tempus_list_policies` | Read active and retired policy bundles (read-only) |

---

## 4. Testing the MCP Connection

In Claude Desktop or Cursor Chat, try asking:
> *"Inspect the Tempus DDB audit trace for the latest action ID and verify its cryptographic integrity."*
