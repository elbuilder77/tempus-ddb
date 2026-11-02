"""The HTTP executor holds credentials and connects where an intent says: it fails closed.

An Authorization header without a domain allowlist refuses to start. Allowlist entries
are an exact host, `*`, or `*.domain`, not a textual prefix.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from support import SOURCE_PATHS, run_cli
from tempus_ddb import gen_keys
from tempus_executors.http import HttpActionAdapter, HttpExecutorError


class Recorder:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers, payload):
        self.calls.append((method, url, dict(headers)))
        return {"ok": True}


def test_credentials_without_an_allowlist_refuse_to_start(monkeypatch):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    monkeypatch.delenv("HTTP_EXECUTOR_AUTH_HEADER", raising=False)
    with pytest.raises(HttpExecutorError, match="allowed.domains"):
        HttpActionAdapter(auth_header="Bearer SECRET", transport=Recorder())


def test_credentials_from_the_environment_also_need_an_allowlist(monkeypatch):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    monkeypatch.setenv("HTTP_EXECUTOR_AUTH_HEADER", "Bearer SECRET")
    with pytest.raises(HttpExecutorError, match="allowed.domains"):
        HttpActionAdapter(transport=Recorder())


def test_an_empty_allowlist_does_not_count(monkeypatch):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    with pytest.raises(HttpExecutorError):
        HttpActionAdapter(auth_header="Bearer SECRET", allowed_domains=set())


def test_credentials_with_an_allowlist_work_and_the_lookalike_host_is_refused(
    monkeypatch,
):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    recorder = Recorder()
    adapter = HttpActionAdapter(
        auth_header="Bearer SECRET",
        transport=recorder,
        allowed_domains={"api.example.com"},
    )
    ok = adapter.execute_action(
        {
            "action_type": "http.post",
            "resource": "https://api.example.com/v1/x",
            "input": {},
        }
    )
    assert ok.status == "SUCCEEDED"
    with pytest.raises(HttpExecutorError):
        adapter.execute_action(
            {
                "action_type": "http.post",
                "resource": "https://api.example.com.evil.net/x",
                "input": {},
            }
        )
    assert len(recorder.calls) == 1


def test_a_star_allowlist_is_an_explicit_choice_and_still_starts(monkeypatch):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    HttpActionAdapter(
        auth_header="Bearer SECRET", transport=Recorder(), allowed_domains={"*"}
    )


def test_no_credentials_no_allowlist_still_starts(monkeypatch):
    monkeypatch.delenv("HTTP_EXECUTOR_ALLOWED_DOMAINS", raising=False)
    monkeypatch.delenv("HTTP_EXECUTOR_AUTH_HEADER", raising=False)
    HttpActionAdapter(transport=Recorder())


def test_cli_refuses_to_start_with_credentials_and_no_allowlist_without_a_traceback():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        key = os.path.join(tmpdir, "executor.keys.json")
        gen_keys(key)
        permit = Path(tmpdir, "permit.json")
        permit.write_text("{}")
        env = dict(os.environ)
        env.pop("HTTP_EXECUTOR_ALLOWED_DOMAINS", None)
        env["PYTHONPATH"] = os.pathsep.join(SOURCE_PATHS)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tempus_executors.http",
                "--permit",
                str(permit),
                "--executor-db",
                os.path.join(tmpdir, "e.db"),
                "--executor-keyfile",
                key,
                "--gate-id",
                json.loads(Path(key).read_text())["public_key"],
                "--tenant-id",
                "t",
                "--auth-header",
                "Bearer SECRET",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "allowed-domains" in result.stderr
        assert "Traceback" not in result.stderr and "SECRET" not in result.stderr


def _policy(resources):
    return {
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "p-prefix",
        "tenant_id": "acme",
        "constraints": {
            "allowed_action_types": ["http.post"],
            "allowed_resources": resources,
            "allowed_executors": ["*"],
            "max_ttl_seconds": 60,
            "max_input_bytes": 1024,
        },
    }


@pytest.mark.parametrize(
    "pattern,warns",
    [
        ("https://api.example.com*", True),
        ("http://api.example.com:8080*", True),
        ("https://*", True),
        ("https://api.example.com/*", False),
        ("https://api.example.com/v1/*", False),
        ("https://api.example.com/hook", False),
        ("acme/*", False),
        ("*", False),
    ],
)
def test_install_policy_warns_about_url_prefixes_without_a_slash_after_the_host(
    pattern, warns
):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        code, out, err = run_cli(["init", "--allow-all-dev"], cwd=tmpdir)
        assert code == 0, out + err
        policy = Path(tmpdir, "policy.json")
        policy.write_text(json.dumps(_policy([pattern])))
        code, out, err = run_cli(
            ["install-policy", "--policy", str(policy)], cwd=tmpdir
        )
        assert code == 0, out + err  # a warning, not a refusal
        assert ("WARNING" in err and pattern in err) is warns, err
