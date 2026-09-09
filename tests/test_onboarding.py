import json
from argparse import Namespace

import pytest
from tempus_ddb import cli, onboarding
from tempus_ddb import mcp_server as mcp
from tempus_ddb.action_history import list_actions
from tempus_ddb.github_executor import GitHubActionAdapter


def test_init_reports_pending_setup_with_next_step(tmp_path, capsys):
    args = Namespace(db=str(tmp_path / "gate.db"), keyfile=str(tmp_path / "keys.json"))
    cli.run_init(args)
    output = capsys.readouterr().out
    assert "initialized" in output.lower()
    assert "ready" not in output.lower()
    args.github, args.json = True, True
    with pytest.raises(SystemExit):
        cli.run_doctor(args)
    report = json.loads(capsys.readouterr().out)
    policy = next(c for c in report["checks"] if c["name"] == "workload_policy")
    assert "install-policy" in policy["next_step"]
    assert report["readiness"] == "CONFIGURATION_PENDING"


@pytest.mark.asyncio
async def test_mcp_uses_configured_database_without_action_history(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(mcp, "SANDBOX_DIR", str(tmp_path))
    monkeypatch.setattr(mcp, "TEMPUS_GATE_KEYFILE", "keys.json")
    monkeypatch.setattr(mcp, "TEMPUS_DB_PATH", "configured.db", raising=False)
    cli.run_init(
        Namespace(
            db=str(tmp_path / "configured.db"), keyfile=str(tmp_path / "keys.json")
        )
    )
    tools = {t.name: t for t in await mcp.list_tools()}
    assert "db" not in tools["tempus_list_agents"].inputSchema["required"]
    response = json.loads((await mcp.call_tool("tempus_list_agents", {}))[0].text)
    assert response["status"] == "success" and len(response["agents"]) == 1
    assert not (tmp_path / "tempus.db").exists()


def test_local_trial_persists_verified_effect_and_never_repeats(tmp_path):
    directory = tmp_path / "trial"
    onboarding.run_quickstart(
        Namespace(directory=str(directory), github_repository=None)
    )
    result = json.loads((directory / "result.json").read_text())
    assert (result["authorization"], result["execution"], result["integrity"]) == (
        "ALLOWED",
        "SUCCEEDED",
        "VERIFIED",
    )
    assert (
        json.loads((directory / "issue.json").read_text())["title"]
        == "My first Tempus-controlled issue"
    )
    original = (directory / "issue.json").read_bytes()
    onboarding.run_first_action(
        Namespace(directory=str(directory), execute_github=False)
    )
    assert (directory / "issue.json").read_bytes() == original
    with pytest.raises(ValueError, match="already exists"):
        onboarding.run_quickstart(
            Namespace(directory=str(directory), github_repository=None)
        )
    rows = list_actions(
        str(directory / "tempus.db"),
        str(directory / "gate.keys.json"),
        resource="local/issues",
    )
    assert len(rows) == 1 and rows[0]["action_id"] == result["action_id"]
    assert rows[0]["recorded_outcome"] == "SUCCEEDED"
    assert rows[0]["integrity"] == "VERIFIED"
    assert (
        list_actions(
            str(directory / "tempus.db"),
            str(directory / "gate.keys.json"),
            resource="elsewhere",
        )
        == []
    )


@pytest.mark.parametrize("ambiguous", [False, True], ids=["completed", "unknown"])
def test_github_trial_requires_explicit_execution_and_preserves_outcome(
    tmp_path, monkeypatch, ambiguous
):
    directory = tmp_path / "trial"
    onboarding.run_quickstart(
        Namespace(directory=str(directory), github_repository="acme/test")
    )
    assert not (directory / "permit.json").exists()
    with pytest.raises(ValueError, match="explicitly"):
        onboarding.run_first_action(
            Namespace(directory=str(directory), execute_github=False)
        )
    calls = []

    class Transport:
        def request(self, method, url, headers, payload):
            calls.append((method, url, payload))
            if ambiguous:
                raise TimeoutError("ambiguous")
            return {"number": 1, "html_url": "https://github.test/acme/test/issues/1"}

    monkeypatch.setattr(
        onboarding,
        "GitHubActionAdapter",
        lambda **kwargs: GitHubActionAdapter(token="test-only", transport=Transport()),
    )
    args = Namespace(directory=str(directory), execute_github=True)
    if ambiguous:
        with pytest.raises(SystemExit) as exc:
            onboarding.run_first_action(args)
        assert exc.value.code == 2
    else:
        onboarding.run_first_action(args)
    result = json.loads((directory / "result.json").read_text())
    assert result["execution"] == ("UNKNOWN" if ambiguous else "SUCCEEDED")
    assert (
        len(calls) == 1
        and calls[0][1] == "https://api.github.com/repos/acme/test/issues"
    )
    onboarding.run_first_action(args)
    assert len(calls) == 1


def test_changed_resource_is_blocked_before_any_effect(tmp_path):
    directory = tmp_path / "trial"
    onboarding.run_quickstart(
        Namespace(directory=str(directory), github_repository="acme/test")
    )
    (directory / "trial.json").write_text(
        json.dumps({"action_type": "local.create_issue", "resource": "local/issues"})
    )
    with pytest.raises(SystemExit):
        onboarding.run_first_action(
            Namespace(directory=str(directory), execute_github=False)
        )
    assert not (directory / "issue.json").exists()
    assert (
        json.loads((directory / "result.json").read_text())["authorization"]
        == "BLOCKED"
    )


@pytest.mark.asyncio
async def test_generated_mcp_configuration_connects_over_stdio(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    directory = tmp_path / "trial"
    onboarding.run_quickstart(
        Namespace(directory=str(directory), github_repository=None)
    )
    config = json.loads((directory / "mcp.json").read_text())["mcpServers"]["tempus"]
    action_id = json.loads((directory / "result.json").read_text())["action_id"]
    async with stdio_client(StdioServerParameters(**config)) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            agents = await session.call_tool("tempus_list_agents", {})
            assert len(json.loads(agents.content[0].text)["agents"]) == 3
            result = await session.call_tool(
                "tempus_verify_trace", {"action_id": action_id}
            )
            assert json.loads(result.content[0].text)["status"] == "VERIFIED"
