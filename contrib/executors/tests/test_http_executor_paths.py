"""H3: `.`/`..` path segments (plain or percent-encoded) never reach the HTTP executor.

Policy `https://api.example.com/v1/*` matches the *text* `/v1/../admin`; the server then
serves `/admin`. The executor refuses those paths, as the GitHub executor already did.
"""

import pytest
from tempus_executors.http import (
    HttpActionAdapter,
    HttpExecutorError,
    _validate_https_url,
)

BASE = "https://api.example.com"

ESCAPING_PATHS = [
    "/v1/../admin",
    "/v1/./x",
    "/v1/..",
    "/v1/.",
    "/v1/%2e%2e/admin",
    "/v1/%2E%2E/admin",
    "/v1/%2e%2E/admin",
    "/v1/.%2e/admin",
    "/v1/%2e./admin",
    "/v1/%2E%2E%2Fadmin",
    "/v1/%2e%2e%2fadmin",
    "/v1/..%2fadmin",
    "/v1/%252e%252e/admin",
    "/v1/%25252e%25252e/admin",
    "/v1/..;/admin",
    "/v1/%2e%2e;x=1/admin",
    "/v1/a%2f..%2f..%2fadmin",
    "/v1/x/%2e%2e/%2e%2e/admin",
]

BACKSLASH_PATHS = ["/v1/x%5cy", "/v1/x%255cy", "/v1/%2e%2e%5cadmin"]

FINE_PATHS = [
    "/v1/x",
    "/v1/hooks/T000/B000/XXXX",
    "/v1/file.name.json",
    "/v1/...",
    "/v1/..x",
    "/v1/x..",
    "/v1/.well-known/x",
    "/v1/x%20y",
    "/v1/%C3%A9",
    "/v1/100%25",
    "/v1/x?next=/../admin",
    "/v1/x?p=%2e%2e",
    "/v1//x",
    "",
    "/",
]


@pytest.mark.parametrize("path", ESCAPING_PATHS)
def test_dot_segments_are_refused_in_any_spelling(path):
    with pytest.raises(HttpExecutorError, match="'\\.' or '\\.\\.'"):
        _validate_https_url(BASE + path)


@pytest.mark.parametrize("path", BACKSLASH_PATHS)
def test_encoded_backslashes_are_refused(path):
    with pytest.raises(HttpExecutorError, match="backslash"):
        _validate_https_url(BASE + path)


def test_excessive_percent_nesting_is_refused():
    with pytest.raises(HttpExecutorError, match="encoded too many times"):
        _validate_https_url(BASE + "/v1/%" + "25" * 8 + "2e")


@pytest.mark.parametrize("path", FINE_PATHS)
def test_ordinary_paths_still_pass(path):
    assert _validate_https_url(BASE + path) == BASE + path


def test_the_adapter_sends_nothing_for_a_dot_segment_url():
    sent = []

    class Transport:
        def request(self, *args):
            sent.append(args)
            return {}

    adapter = HttpActionAdapter(
        auth_header="Bearer SECRET",
        allowed_domains={"api.example.com"},
        transport=Transport(),
    )
    with pytest.raises(HttpExecutorError):
        adapter.execute_action(
            {
                "action_type": "http.post",
                "resource": BASE + "/v1/%2e%2e/admin",
                "input": {},
            }
        )
    assert sent == []
