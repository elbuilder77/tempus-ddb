import json
import time
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tempus_ddb import GitHubExecutorAdapter, TempusDDB, gen_keys
from tempus_ddb.github_app import GitHubAppCredentials
from tempus_ddb.github_executor import (
    GitHubActionAdapter,
    GitHubExecutorError,
    _RejectRedirects,
)


@pytest.fixture
def app_key(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "app.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, key


class AppTransport:
    def __init__(self, now):
        self.now = now
        self.calls = []
        self.failure = None
        self.token = "installation-test-credential"

    def request(self, method, url, headers, payload):
        self.calls.append((method, url, headers, payload))
        if self.failure:
            raise self.failure
        return {
            "token": self.token,
            "expires_at": datetime.fromtimestamp(
                self.now[0] + 3600, timezone.utc
            ).isoformat(),
        }


def provider(app_key, transport, now):
    return GitHubAppCredentials(
        "Iv1.test",
        str(app_key[0]),
        42,
        "acme/widget",
        transport=transport,
        clock=lambda: now[0],
    )


def test_signed_jwt_scoping_cache_and_refresh(app_key):
    now = [time.time()]
    transport = AppTransport(now)
    credentials = provider(app_key, transport, now)
    assert (
        credentials.token_for("acme/widget", "github.create_issue") == transport.token
    )
    method, url, headers, payload = transport.calls[0]
    claims = jwt.decode(
        headers["Authorization"][7:], app_key[1].public_key(), algorithms=["RS256"]
    )
    assert claims["iss"] == "Iv1.test"
    assert claims["iat"] == int(now[0]) - 60
    assert claims["exp"] == int(now[0]) + 540
    assert method == "POST"
    assert url == "https://api.github.com/app/installations/42/access_tokens"
    assert payload == {"repositories": ["widget"], "permissions": {"issues": "write"}}
    credentials.token_for("ACME/Widget", "github.create_issue")
    assert len(transport.calls) == 1
    credentials.token_for("acme/widget", "github.create_pull_request")
    assert transport.calls[-1][3]["permissions"] == {"pull_requests": "write"}
    now[0] += 3541
    credentials.token_for("acme/widget", "github.create_issue")
    assert len(transport.calls) == 3


@pytest.mark.parametrize(
    "resource,action",
    [
        ("other/widget", "github.create_issue"),
        ("acme/other", "github.create_issue"),
        ("acme/widget", "github.merge_pull_request"),
    ],
    ids=["different-owner", "different-repository", "unsupported-action"],
)
def test_binding_rejected_before_authentication(app_key, resource, action):
    now = [time.time()]
    transport = AppTransport(now)
    with pytest.raises(GitHubExecutorError, match="outside"):
        provider(app_key, transport, now).token_for(resource, action)
    assert not transport.calls


def test_auth_failure_does_not_write_or_leak_credentials(app_key):
    now = [time.time()]
    transport = AppTransport(now)
    transport.failure = RuntimeError("private-secret-value")
    credentials = provider(app_key, transport, now)
    adapter = GitHubActionAdapter(token_provider=credentials, transport=transport)
    result = adapter.execute_action(
        {
            "action_type": "github.create_issue",
            "resource": "acme/widget",
            "input": {"title": "test"},
        }
    )
    assert result.status == "FAILED"
    assert result.payload == {"error_code": "TEMPUS_GITHUB_CREDENTIAL_REJECTED"}
    assert len(transport.calls) == 1
    assert transport.calls[0][1].endswith("/access_tokens")


@pytest.mark.parametrize("token", [None, "", 123])
def test_malformed_token_fails_closed(app_key, token):
    now = [time.time()]
    transport = AppTransport(now)
    transport.token = token
    with pytest.raises(GitHubExecutorError, match="authentication failed"):
        provider(app_key, transport, now).token_for(
            "acme/widget", "github.create_issue"
        )


def test_redirects_cannot_forward_credentials():
    with pytest.raises(GitHubExecutorError, match="redirects"):
        _RejectRedirects().redirect_request(
            None, None, 307, "", {}, "https://other.test"
        )


def test_app_executes_only_after_valid_permit_and_never_replays(
    tmp_path, app_key, monkeypatch
):
    files = [tmp_path / f"{name}.keys.json" for name in ("gate", "agent", "executor")]
    for path in files:
        gen_keys(str(path))
    gate_path, agent_path, executor_path = files
    gate_id, agent_id, executor_id = [
        json.loads(p.read_text())["public_key"] for p in files
    ]
    gate = TempusDDB(str(tmp_path / "gate.db"), str(gate_path))
    gate.register_agent(gate_id, "gate", '{"can_delegate":true}')
    gate.register_agent(agent_id, "agent", "{}")
    gate.register_agent(executor_id, "executor", "{}")
    now = [time.time()]
    auth = AppTransport(now)
    credentials = provider(app_key, auth, now)

    class Writes:
        calls = []

        def request(self, method, url, headers, payload):
            assert headers["Authorization"] == "Bearer " + auth.token
            self.calls.append((url, payload))
            return {"number": 7}

    writes = Writes()
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-use-this-token")
    executor = GitHubExecutorAdapter(
        str(tmp_path / "executor.db"),
        str(executor_path),
        gate_id,
        "tenant",
        token_provider=credentials,
        transport=writes,
    )
    with pytest.raises(Exception):
        executor.execute("{}")
    assert not auth.calls and not writes.calls
    intent = {
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "tenant",
        "agent_id": agent_id,
        "idempotency_key": "app-001",
        "action_type": "github.create_issue",
        "resource": "acme/widget",
        "requested_at": time.time_ns() // 1000,
        "input": {"title": "App issue"},
    }
    permit = gate.request_action(json.dumps(intent), str(agent_path), 60)
    outcome = executor.execute(permit)
    assert json.loads(outcome)["status"] == "SUCCEEDED"
    assert auth.token not in outcome
    with pytest.raises(Exception):
        executor.execute(permit)
    assert len(auth.calls) == len(writes.calls) == 1
    assert writes.calls[0] == (
        "https://api.github.com/repos/acme/widget/issues",
        {"title": "App issue"},
    )
