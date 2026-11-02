"""The HTTP and Slack transports must not follow redirects.

Each test drives the real executor path (ActionAdapter -> real Urllib transport ->
real HTTP over loopback) against a local origin that answers with a 3xx pointing at a
second local server standing in for "another host". The second server must never be
contacted and must never receive the Authorization header.

The GitHub executor and the shared opener in `tempus_ddb._http` are covered by
`tests/test_redirect_blocking.py` in the repository root; the loopback `_Server` helper
is duplicated here on purpose so the two suites stay independent.
"""

import http.server
import json
import threading

import pytest
from tempus_executors import http as http_executor
from tempus_executors.http import HttpActionAdapter
from tempus_executors.slack import SlackActionAdapter, UrllibSlackTransport

REDIRECT_CODES = [301, 302, 303, 307, 308]
# Python 3.10's urllib does not treat 308 as a redirect, so the executors
# report that status as an HTTP error. 3.11+ raises RedirectRefused. Both
# must fail closed: the second host is never contacted and the action does
# not succeed. Tests assert that outcome, not one error sentence.


class _Server:
    """Loopback HTTP server that records requests and replies with a fixed answer."""

    def __init__(self, status=200, body=b"{}", headers=None):
        self.status, self.body, self.extra = status, body, headers or {}
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                self.send_response(outer.status)
                for key, value in outer.extra.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            do_GET = do_POST = do_PUT = _serve

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    created = []

    def make(**kwargs):
        server = _Server(**kwargs)
        created.append(server)
        return server

    yield make
    for server in created:
        server.close()


@pytest.fixture(autouse=True)
def loopback_http(monkeypatch):
    """Allow plain-HTTP loopback targets for the real transport (tests only)."""
    monkeypatch.setattr(http_executor, "_validate_https_url", lambda url, *a, **k: url)


def _redirecting_pair(servers, code, secret_in_location=False):
    other = servers(body=b'{"leaked": true}')
    location = other.url + "/stolen"
    if secret_in_location:
        location += "?token=LOCATION-SECRET-123"
    origin = servers(status=code, headers={"Location": location})
    return origin, other


# ---------------------------------------------------------------- HTTP executor


def _http_intent(url):
    return {"action_type": "http.post", "resource": url, "input": {"a": 1}}


def _http_adapter():
    return HttpActionAdapter(
        auth_header="Bearer HTTP-SECRET-TOKEN", allowed_domains={"127.0.0.1"}
    )


@pytest.mark.parametrize("code", REDIRECT_CODES)
def test_http_executor_refuses_redirects(servers, code):
    origin, other = _redirecting_pair(servers, code, secret_in_location=True)
    result = _http_adapter().execute_action(_http_intent(origin.url + "/hook"))
    assert other.requests == [], "redirect was followed to the second host"
    assert result.status == "FAILED"
    assert result.payload["http_status"] == code
    text = json.dumps(result.payload)
    assert "HTTP-SECRET-TOKEN" not in text and "LOCATION-SECRET-123" not in text
    assert origin.requests[0]["authorization"] == "Bearer HTTP-SECRET-TOKEN"
    assert other.requests == []


def test_http_executor_normal_flow_still_works(servers):
    origin = servers(body=b'{"ok": true}')
    result = _http_adapter().execute_action(_http_intent(origin.url + "/hook"))
    assert result.status == "SUCCEEDED"
    assert result.payload == {"ok": True}
    assert origin.requests[0]["authorization"] == "Bearer HTTP-SECRET-TOKEN"


# --------------------------------------------------------------- Slack executor


def _slack_intent():
    return {
        "action_type": "slack.post_message",
        "resource": "C123",
        "input": {"text": "hello"},
    }


def _slack_adapter(monkeypatch, origin):
    monkeypatch.setattr(UrllibSlackTransport, "API_BASE", origin.url + "/api/")
    return SlackActionAdapter(token="xoxb-SLACK-SECRET-TOKEN")


@pytest.mark.parametrize("code", REDIRECT_CODES)
def test_slack_executor_refuses_redirects(servers, monkeypatch, code):
    origin, other = _redirecting_pair(servers, code, secret_in_location=True)
    result = _slack_adapter(monkeypatch, origin).execute_action(_slack_intent())
    assert other.requests == [], "redirect was followed to the second host"
    assert result.status == "FAILED"
    text = json.dumps(result.payload)
    assert str(code) in text
    assert "SLACK-SECRET-TOKEN" not in text and "LOCATION-SECRET-123" not in text
    assert origin.requests[0]["authorization"] == "Bearer xoxb-SLACK-SECRET-TOKEN"
    assert other.requests == []


def test_slack_executor_normal_flow_still_works(servers, monkeypatch):
    reply = {"ok": True, "ts": "1.2", "message": {"ts": "1.2"}}
    origin = servers(body=json.dumps(reply).encode())
    result = _slack_adapter(monkeypatch, origin).execute_action(_slack_intent())
    assert result.status == "SUCCEEDED"
    assert result.payload["ts"] == "1.2"
    assert origin.requests[0]["path"] == "/api/chat.postMessage"
