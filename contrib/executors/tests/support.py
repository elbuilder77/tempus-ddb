"""Helpers shared by the contrib executor tests.

They used to be imported from `tests/test_cli.py` and `tests/test_executor_runtime.py`
in the repository root; those modules stay with the core test suite, so the contrib
suite carries its own copies.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from tempus_ddb import TempusDDB, gen_keys

_CONTRIB_ROOT = Path(__file__).resolve().parent.parent
_REPO_PYTHON = _CONTRIB_ROOT.parent.parent / "python"

# Source directories a subprocess needs on PYTHONPATH when the packages are not
# installed: the contrib package itself and, inside the tempus-ddb checkout, the core.
SOURCE_PATHS = [str(p) for p in (_CONTRIB_ROOT, _REPO_PYTHON) if p.is_dir()]


def run_cli(args, cwd=None, env=None):
    """Run the tempus CLI and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "tempus_ddb.cli"] + args
    env = {**os.environ, **(env or {})}
    source_path = os.pathsep.join(SOURCE_PATHS)
    if env.get("PYTHONPATH"):
        env["PYTHONPATH"] = env["PYTHONPATH"] + os.pathsep + source_path
    else:
        env["PYTHONPATH"] = source_path
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, env=env, encoding="utf-8"
    )
    return result.returncode, result.stdout, result.stderr


def _setup_gate_and_agents(tmpdir, tenant_id="tenant-runtime-test"):
    gate_db = os.path.join(tmpdir, "gate.db")
    exec_db = os.path.join(tmpdir, "exec.db")
    gate_key = os.path.join(tmpdir, "gate.keys.json")
    agent_key = os.path.join(tmpdir, "agent.keys.json")
    exec_key = os.path.join(tmpdir, "executor.keys.json")

    gen_keys(gate_key)
    gen_keys(agent_key)
    gen_keys(exec_key)

    gate = TempusDDB(gate_db, gate_key)

    with open(gate_key, "r", encoding="utf-8") as f:
        gate_id = json.load(f)["public_key"]
    with open(agent_key, "r", encoding="utf-8") as f:
        agent_id = json.load(f)["public_key"]
    with open(exec_key, "r", encoding="utf-8") as f:
        exec_id = json.load(f)["public_key"]

    gate.register_agent(gate_id, "gate-root", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "test-agent", "{}")
    gate.register_agent(exec_id, "test-executor", "{}")

    return gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key
