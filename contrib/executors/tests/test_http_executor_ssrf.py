"""H2: the HTTP executor must not reach local/private/metadata addresses.

The attacks come from the forge-5 audit (`audit_http2.py`): alternative IPv4 spellings,
IPv6 and IPv4-mapped forms, and names that resolve to blocked addresses. No test connects
anywhere: `socket.getaddrinfo` and `socket.create_connection` are replaced by recorders.
"""

import socket
import ssl
from urllib import request

import pytest
from tempus_ddb import _http
from tempus_executors.http import (
    HttpActionAdapter,
    HttpExecutorError,
    _validate_https_url,
)

ALT_NOTATION_HOSTS = [
    "127.0.0.1",
    "127.1",
    "2130706433",
    "0x7f000001",
    "0x7f.1",
    "0177.0.0.1",
    "017700000001",
    "0.0.0.0",
    "0",
    "10.0.0.1",
    "10.1",
    "167772161",
    "192.168.1.1",
    "192.168.1",
    "172.16.0.1",
    "169.254.169.254",
    "2852039166",
    "0xa9fea9fe",
    "0xa9.0xfe.0xa9.0xfe",
    "100.64.0.1",
    "100.100.100.200",
    "168.63.129.16",
    "224.0.0.1",
    "255.255.255.255",
    "[::1]",
    "[::]",
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[0:0:0:0:0:ffff:7f00:1]",
    "[::ffff:169.254.169.254]",
    "[::127.0.0.1]",
    "[64:ff9b::7f00:1]",
    "[64:ff9b::a9fe:a9fe]",
    "[fe80::1]",
    "[fd00:ec2::254]",
    "[fc00::1]",
    "[ff02::1]",
    "[2002:7f00:1::]",
    "localhost",
    "localhost.",
    "LOCALHOST",
    "foo.localhost",
    "metadata.google.internal",
    "metadata.google.internal.",
]


@pytest.mark.parametrize("host", ALT_NOTATION_HOSTS)
def test_blocked_hosts_are_refused_without_any_lookup(host, monkeypatch):
    def no_dns(*args, **kwargs):
        raise AssertionError("validation must not need DNS")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    with pytest.raises(HttpExecutorError, match="refused"):
        _validate_https_url(f"https://{host}/hook")


@pytest.mark.parametrize("host", ["127.1", "[::ffff:127.0.0.1]", "2852039166"])
def test_a_wildcard_allowlist_does_not_open_blocked_addresses(host):
    with pytest.raises(HttpExecutorError, match="refused"):
        _validate_https_url(f"https://{host}/", {"*"})


@pytest.mark.parametrize(
    "host", ["api.example.com", "93.184.216.34", "[2606:4700:4700::1111]", "1.1.1.1"]
)
def test_public_hosts_pass_validation(host):
    assert _validate_https_url(f"https://{host}/x") == f"https://{host}/x"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com%2eevil.net/",
        "https://api.example.com%252eevil.net/",
        "https://evil.net%2f.api.example.com/",
        "https://[fe80::1%25eth0]/",
        "https://api.example.com:notaport/",
    ],
)
def test_escapes_in_the_host_and_bad_ports_are_refused(url):
    with pytest.raises(HttpExecutorError):
        _validate_https_url(url)


class Net:
    """Records DNS lookups and connection attempts; never touches the network."""

    def __init__(self, monkeypatch, answers):
        self.answers = answers  # host -> list of answer lists (one per lookup)
        self.lookups, self.connections = [], []
        # These tests cover the direct (pinned) path. The module opener captured any
        # HTTPS_PROXY present at import (developer machine, sandboxed runner), which
        # would send the connection to the proxy, so use one with no proxy.
        monkeypatch.setattr(
            _http,
            "_PINNED_OPENER",
            request.build_opener(
                request.ProxyHandler({}),
                _http._RejectRedirects,
                _http._PinnedHTTPSHandler,
            ),
        )
        monkeypatch.setattr(socket, "getaddrinfo", self.getaddrinfo)
        monkeypatch.setattr(socket, "create_connection", self.create_connection)

    def getaddrinfo(self, host, port, *args, **kwargs):
        self.lookups.append((host, port))
        queue = self.answers[host]
        ips = queue.pop(0) if len(queue) > 1 else queue[0]
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, port, 0, 0) if ":" in ip else (ip, port),
            )
            for ip in ips
        ]

    def create_connection(self, address, *args, **kwargs):
        self.connections.append(address)
        raise OSError("harness: no network")


def _post(url, **kwargs):
    adapter = HttpActionAdapter(
        auth_header="Bearer SECRET", allowed_domains={"*"}, **kwargs
    )
    return adapter.execute_action(
        {"action_type": "http.post", "resource": url, "input": {}}
    )


@pytest.mark.parametrize(
    "answer",
    [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.5",
        "192.168.0.10",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "fe80::1",
    ],
)
def test_a_name_that_resolves_to_a_blocked_address_is_never_connected(
    monkeypatch, answer
):
    net = Net(monkeypatch, {"rebind.example.com": [[answer]]})
    result = _post("https://rebind.example.com/hook")
    assert result.status == "FAILED"
    assert "destination refused" in result.payload["error"]
    assert net.connections == []
    assert "SECRET" not in str(result.payload)


def test_one_blocked_answer_refuses_the_whole_name(monkeypatch):
    net = Net(monkeypatch, {"mixed.example.com": [["93.184.216.34", "10.0.0.5"]]})
    result = _post("https://mixed.example.com/")
    assert "destination refused" in result.payload["error"]
    assert net.connections == []


def test_the_connection_goes_to_the_validated_ip_not_to_the_name(monkeypatch):
    net = Net(monkeypatch, {"api.example.com": [["93.184.216.34"]]})
    _post("https://api.example.com:8443/hook")
    assert net.lookups == [("api.example.com", 8443)]
    assert net.connections == [("93.184.216.34", 8443)]


def test_rebinding_between_check_and_connect_cannot_redirect_the_connection(
    monkeypatch,
):
    # First answer public, any later answer private: the executor resolves once and
    # connects to the IP it validated, so the second answer is never consulted.
    net = Net(
        monkeypatch,
        {"rebind.example.com": [["93.184.216.34"], ["169.254.169.254"]]},
    )
    _post("https://rebind.example.com/hook")
    assert net.connections == [("93.184.216.34", 443)]
    assert len(net.lookups) == 1


def test_tls_still_verifies_the_name_not_the_ip(monkeypatch):
    seen = {}

    class FakeContext:
        # http.client before 3.12 reads these on every supplied context.
        # They stay in verifying mode: CERT_NONE would be rejected, and a
        # missing attribute aborts before the handshake is observed.
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(self, sock, server_hostname=None):
            seen["server_hostname"] = server_hostname
            raise OSError("harness: stop after the handshake call")

    class Sock:
        def close(self):
            pass

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda h, p, *a, **k: [(2, 1, 6, "", ("93.184.216.34", p))],
    )
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Sock())
    connection = _http._PinnedHTTPSConnection(
        "api.example.com", 443, context=FakeContext()
    )
    with pytest.raises(OSError, match="harness"):
        connection.connect()
    assert seen["server_hostname"] == "api.example.com"


def test_other_executors_keep_the_plain_opener():
    # Slack/GitHub/payments talk to fixed API hosts through open_request(pinned=False).
    assert _http._OPENER is not _http._PINNED_OPENER
