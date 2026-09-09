"""Persistent first-action walkthrough, shipped in the installed Python package."""

import json
import os
import sys
import time
from argparse import Namespace
from pathlib import Path

from ._tempus_ddb import TempusDDB, gen_keys
from .executor_runtime import ExecutionResult, ExecutorRuntime, UnknownExecutionError
from .github_executor import RESOURCE_PATTERN, GitHubActionAdapter


def _write(path, value):
    # Exclusive creation protects prior evidence and makes concurrent runs stop.
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class LocalIssueAdapter:
    """A real local file effect; no GitHub request or simulated external success."""

    supported_actions = {"local.create_issue"}

    def __init__(self, directory):
        self.path = directory / "issue.json"

    def execute_action(self, intent):
        if intent["resource"] != "local/issues":
            return ExecutionResult("FAILED", {"error_code": "LOCAL_RESOURCE_REJECTED"})
        _write(
            self.path,
            {"title": intent["input"]["title"], "kind": "local-example-issue"},
        )
        return ExecutionResult(
            "SUCCEEDED", {"file": str(self.path), "effect": "local file only"}
        )


def run_quickstart(args):
    directory = Path(args.directory).resolve()
    repository = args.github_repository
    if repository and not RESOURCE_PATTERN.fullmatch(repository):
        raise ValueError("--github-repository must be an exact owner/repository")
    if directory.exists():
        raise ValueError(
            "Trial directory already exists; existing evidence is preserved. "
            "Use first-action for a prepared trial, or choose a new --directory."
        )
    directory.mkdir(parents=True)
    keys = {}
    for name in ("gate", "agent", "executor"):
        path = directory / f"{name}.keys.json"
        gen_keys(str(path))
        keys[name] = _read(path)["public_key"]
    gate = TempusDDB(str(directory / "tempus.db"), str(directory / "gate.keys.json"))
    gate.register_agent(keys["gate"], "trial-gate", json.dumps({"can_delegate": True}))
    for name in ("agent", "executor"):
        gate.register_agent(
            keys[name], f"trial-{name}", json.dumps({"tenant_id": "first-action"})
        )
    action_type = "github.create_issue" if repository else "local.create_issue"
    resource = repository or "local/issues"
    policy = {
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "first-action-v1",
        "tenant_id": "first-action",
        "constraints": {
            "allowed_action_types": [action_type],
            "allowed_resources": [resource],
            "allowed_executors": [keys["executor"]],
            "max_ttl_seconds": 60,
            "max_input_bytes": 16384,
        },
    }
    _write(directory / "policy.json", policy)
    gate.install_policy(json.dumps(policy))
    _write(directory / "trial.json", {"resource": resource, "action_type": action_type})
    # MCP only receives the gate identity. The agent/executor keys stay outside
    # the model's tool arguments. A production deployment must isolate processes.
    _write(
        directory / "mcp.json",
        {
            "mcpServers": {
                "tempus": {
                    "command": sys.executable,
                    "args": ["-m", "tempus_ddb.cli", "mcp", "start"],
                    "env": {
                        "TEMPUS_WORKSPACE": str(directory),
                        "TEMPUS_DB_PATH": "tempus.db",
                        "TEMPUS_GATE_KEYFILE": "gate.keys.json",
                        "TEMPUS_MODE": "autonomous",
                    },
                }
            }
        },
    )
    print(f"Initialized trial: {directory}")
    print(f"Policy configured: {action_type} on {resource} with one executor.")
    from .cli import run_doctor

    run_doctor(
        Namespace(
            db=str(directory / "tempus.db"),
            keyfile=str(directory / "gate.keys.json"),
            github=False,
            json=False,
        )
    )
    if repository:
        print("Prepared only. No GitHub action has been requested or executed.")
        print("Set GITHUB_TOKEN in the executor environment, then explicitly run:")
        print(f'tempus first-action --directory "{directory}" --execute-github')
    else:
        run_first_action(Namespace(directory=str(directory), execute_github=False))


def run_first_action(args):
    directory = Path(args.directory).resolve()
    config = _read(directory / "trial.json")
    is_github = config["action_type"] == "github.create_issue"
    if is_github and not args.execute_github:
        raise ValueError(
            "This trial creates a real GitHub issue; use --execute-github to request it explicitly."
        )
    if not is_github and args.execute_github:
        raise ValueError(
            "This is a local trial; prepare a separate --github-repository trial first."
        )
    # Never re-request or replay an existing trial, even after a crash.
    if (directory / "permit.json").exists():
        permit = _read(directory / "permit.json")
        print(f"Existing action: {permit['authorization']['action_id']}")
        print(
            "No action repeated. Inspect result.json or use tempus actions and verify-trace."
        )
        print(
            "If the result is missing or UNKNOWN, reconcile executor state before any new request."
        )
        return
    adapter = (
        GitHubActionAdapter(token=os.environ.get("GITHUB_TOKEN"))
        if is_github
        else LocalIssueAdapter(directory)
    )
    gate = TempusDDB(str(directory / "tempus.db"), str(directory / "gate.keys.json"))
    gate_id = _read(directory / "gate.keys.json")["public_key"]
    runtime = ExecutorRuntime(
        str(directory / "executor.db"),
        str(directory / "executor.keys.json"),
        gate_id,
        "first-action",
    )
    intent = {
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "first-action",
        "agent_id": _read(directory / "agent.keys.json")["public_key"],
        "idempotency_key": "first-issue",
        "action_type": config["action_type"],
        "resource": config["resource"],
        "requested_at": time.time_ns() // 1000,
        "input": {"title": "My first Tempus-controlled issue"},
    }
    permit = json.loads(
        gate.request_action(json.dumps(intent), str(directory / "agent.keys.json"), 60)
    )
    _write(directory / "permit.json", permit)
    authorization = permit["authorization"]
    action_id = authorization["action_id"]
    print(f"Action ID: {action_id}")
    print(f"Authorization: {authorization['decision']}")
    if authorization["decision"] != "ALLOWED":
        _write(
            directory / "result.json",
            {
                "action_id": action_id,
                "authorization": "BLOCKED",
                "execution": "NOT_STARTED",
                "reason_codes": authorization.get("reason_codes", []),
            },
        )
        print(
            "No effect executed. Inspect permit.json reason_codes and policy.json before changing policy."
        )
        raise SystemExit(1)
    try:
        outcome = json.loads(runtime.execute_permit(json.dumps(permit), adapter))
    except UnknownExecutionError as exc:
        _write(directory / "outcome.json", json.loads(exc.observation))
        _write(
            directory / "result.json",
            {
                "action_id": action_id,
                "authorization": "ALLOWED",
                "execution": "UNKNOWN",
                "integrity": "NOT_VERIFIED",
            },
        )
        print(
            "Execution UNKNOWN: an external effect may exist. Do not retry; reconcile the executor observation and GitHub first."
        )
        raise SystemExit(2) from exc
    _write(directory / "outcome.json", outcome)
    receipt = json.loads(
        gate.commit_outcome_signed(
            authorization["authorization_id"], json.dumps(outcome)
        )
    )
    _write(directory / "receipt.json", receipt)
    _write(directory / "trace.json", json.loads(gate.get_trace(action_id)))
    verification = json.loads(gate.verify_trace(action_id))
    _write(directory / "verification.json", verification)
    result = {
        "action_id": action_id,
        "authorization": "ALLOWED",
        "execution": outcome["status"],
        "integrity": verification["status"],
        "output": outcome.get("output", {}),
    }
    _write(directory / "result.json", result)
    print(f"Execution: {result['execution']}")
    print(f"Evidence integrity: {result['integrity']}")
    print(f"Result: {directory / 'result.json'}")
    if is_github and outcome.get("output", {}).get("html_url"):
        print(f"Issue: {outcome['output']['html_url']}")
    elif not is_github:
        print(f"Local issue: {directory / 'issue.json'} (no GitHub request)")
    print(
        f'tempus --db "{directory / "tempus.db"}" --keyfile "{directory / "gate.keys.json"}" verify-trace --action-id {action_id}'
    )
    if result["execution"] != "SUCCEEDED" or result["integrity"] != "VERIFIED":
        print(
            "Inspect outcome.json and verification.json before requesting another action."
        )
        raise SystemExit(1)
