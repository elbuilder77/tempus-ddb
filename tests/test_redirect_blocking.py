"""The GitHub transport and the shared opener must not follow redirects.

Each test drives the real executor path (ActionAdapter -> real Urllib transport ->
real HTTP over loopback) against a local origin that answers with a 3xx pointing at a
second local server standing in for "another host". The second server must never be
contacted and must never receive the Authorization header. The HTTP and Slack
executors are covered by `contrib/executors/tests/test_redirect_blocking.py`, which
carries its own copy of the `_Server` helper.
"""

import http.server
import json
import threading

import pytest
from tempus_ddb import github_executor
from tempus_ddb.github_executor import GitHubActionAdapter

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
    monkeypatch.setattr(
        github_executor, "_validate_github_api_url", lambda url: url.strip().rstrip("/")
    )


def _redirecting_pair(servers, code, secret_in_location=False):
    other = servers(body=b'{"leaked": true}')
    location = other.url + "/stolen"
    if secret_in_location:
        location += "?token=LOCATION-SECRET-123"
    origin = servers(status=code, headers={"Location": location})
    return origin, other


# -------------------------------------------------------------- GitHub executor


def _github_intent():
    return {
        "action_type": "github.create_issue",
        "resource": "acme/widget",
        "input": {"title": "t", "body": "b"},
    }


@pytest.mark.parametrize("code", REDIRECT_CODES)
def test_github_executor_refuses_redirects(servers, code):
    origin, other = _redirecting_pair(servers, code, secret_in_location=True)
    adapter = GitHubActionAdapter(token="GH-SECRET-TOKEN", api_url=origin.url)
    result = adapter.execute_action(_github_intent())
    assert other.requests == [], "redirect was followed to the second host"
    assert result.status == "FAILED"
    assert result.payload["error_code"] == f"GITHUB_HTTP_{code}"
    text = json.dumps(result.payload)
    assert "GH-SECRET-TOKEN" not in text and "LOCATION-SECRET-123" not in text
    assert origin.requests[0]["authorization"] == "Bearer GH-SECRET-TOKEN"
    assert other.requests == []


def test_github_executor_normal_flow_still_works(servers):
    issue = {
        "id": 7,
        "number": 3,
        "html_url": "https://github.test/i/3",
        "state": "open",
    }
    origin = servers(status=201, body=json.dumps(issue).encode())
    adapter = GitHubActionAdapter(token="GH-SECRET-TOKEN", api_url=origin.url)
    result = adapter.execute_action(_github_intent())
    assert result.status == "SUCCEEDED"
    assert result.payload["number"] == 3
    assert origin.requests[0]["path"] == "/repos/acme/widget/issues"
    assert origin.requests[0]["authorization"] == "Bearer GH-SECRET-TOKEN"


# ----------------------------------------------------------------- shared opener


def test_redirect_error_carries_only_a_sanitized_host(servers):
    from urllib import request

    from tempus_ddb._http import RedirectRefused, open_request

    origin = servers(
        status=302,
        headers={"Location": "https://user:pw@evil.example:8443/p?secret=1#frag"},
    )
    with pytest.raises(RedirectRefused) as caught:
        open_request(request.Request(origin.url + "/x"), timeout=5)
    message = str(caught.value)
    assert caught.value.target_host == "evil.example"
    assert "secret" not in message and "pw" not in message and "/p" not in message
