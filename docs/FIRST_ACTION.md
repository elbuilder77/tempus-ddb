# From installation to one verified action

Use Python 3.10+ and a package containing `quickstart`. These commands are in
the current source revision, not yet a published release. From this checkout,
run `python -m pip install -e .`. Once packaged, the same commands work without
the repository or its `examples/` directory.

## Start locally

```bash
tempus quickstart --directory tempus-first-action
```

The command creates a new trial directory and separate Gate, agent and executor
keys; registers identities; installs a policy limited to one action, resource
and executor; then runs `doctor`. It requests a signed permit, consumes it through
the executor, writes a real local `issue.json`, commits a signed outcome and
verifies its trace. No GitHub call or network credential is involved.

Expected: `Authorization: ALLOWED`, `Execution: SUCCEEDED`, `Evidence integrity:
VERIFIED`. `result.json` contains the action ID, these separate states and the
output path. Keys stay on disk and are not printed. All evidence persists:
`permit.json`, `outcome.json`, `receipt.json`, `trace.json`, `verification.json`.
`policy.json` shows the rule. `mcp.json` contains a client server entry without
private keys.

## Create a real GitHub issue

Prerequisites: a test repository where you can create issues and a GitHub
credential with **Issues: write** for that repository. Configure `GITHUB_TOKEN`
in the terminal/service running the executor through your credential manager;
never paste it into chat, policy files or agent input.

```bash
tempus quickstart --directory github-trial --github-repository YOUR_OWNER/YOUR_TEST_REPO
```

This prepares identities and the exact repository policy. It creates no permit
and makes no GitHub call. Inspect `github-trial/policy.json`, then explicitly run:

```bash
tempus first-action --directory github-trial --execute-github
```

This creates **one real issue** titled “My first Tempus-controlled issue”. The
agent signs its request; the executor consumes the permit, sends the bound issue
payload and signs the result; the Gate commits the outcome. On success, the
command prints the issue URL, action ID, result file and exact verification
command. No manually assembled JSON or copying keys is needed.

This walkthrough is an operator-run development environment. Separate key files
in one process are not production credential isolation: production must separate
the agent, Gate and executor environments/service accounts. See the
[MCP recipe](../cookbooks/mcp_cursor_claude_quickstart.md) for connection and signing
responsibilities.

## Find and verify a result

Enter the trial directory, then run:

```bash
tempus --keyfile gate.keys.json actions
tempus --keyfile gate.keys.json actions --resource YOUR_OWNER/YOUR_TEST_REPO --json
tempus --keyfile gate.keys.json actions --since 2026-09-08
tempus --keyfile gate.keys.json verify-trace --action-id ACTION_ID_FROM_RESULT
tempus --keyfile gate.keys.json trace --action-id ACTION_ID_FROM_RESULT
```

Use `--agent PUBLIC_KEY` to filter by identity. `actions` finds IDs in newest-first
order, verifies each returned trace and labels recorded states separately from
integrity. `trace` and `verify-trace` retain their JSON contract. Verified
authorization without a committed outcome is not a completed action.

## Recover without repeating an effect

| State | Meaning | Next step |
|---|---|---|
| Configuration pending | Files exist; workload setup is incomplete | Register identities, `install-policy`, then `doctor`. The built-in baseline alone is insufficient. |
| Local checks passed | Local configuration was inspected | Run a bounded first action. `doctor --github` checks only token presence. |
| BLOCKED | Authorization was denied; the guided executor was not called | Read `permit.json` reason codes and policy. Correct the request or operator policy, preserving the denial. |
| Expired permit | Authorization no longer permits starting execution | Check executor state. If no effect started, request a new permit; never edit or extend the old one. |
| FAILED | An execution failure was recorded | Read `outcome.json`, correct the input/configuration and verify evidence before a new request. |
| UNKNOWN, STARTED, missing result or NO_RECEIPT | An effect may have occurred; the Gate may lack its outcome | Preserve state. Reconcile the executor and GitHub using repository, title, timestamps and external references. Do not automatically retry. |
| INVALID evidence | Recorded values cannot be trusted | Preserve originals and investigate against trusted state. ALLOWED/SUCCEEDED inside invalid evidence is not proof. |

To inspect executor state without sending another action, run this Python from
the trial directory:

```python
import json
from pathlib import Path
from tempus_ddb import ExecutorRuntime

permit = json.loads(Path("permit.json").read_text(encoding="utf-8"))
gate_id = json.loads(Path("gate.keys.json").read_text(encoding="utf-8"))["public_key"]
runtime = ExecutorRuntime("executor.db", "executor.keys.json", gate_id, "first-action")
print(runtime.raw_executor.get_execution_state(permit["authorization"]["authorization_id"]))
```

A completed signed outcome missing from the Gate can be submitted through
`tempus_commit_outcome_signed` without executing again. UNKNOWN requires
reconciliation and must not be turned into a claimed success.

Repeating `first-action` with an existing permit performs no additional effect.
Repeating `quickstart` against an existing directory refuses to overwrite it.
Choose a new trial directory only after resolving the previous action's state.

For disaster recovery, restore both the Gate and executor consumption database.
Export fresh events from the restored Gate before comparing them with the latest
independent checkpoint. Passing a checkpoint check does not establish freshness
of the executor state. Follow the [coordinated backup and recovery procedure](BACKUP_AND_DISASTER_RECOVERY.md)
before re-enabling dispatch; a missing consumed row is not proof a permit is unused.
