"""Ambiguous transport outcomes are UNKNOWN.

Classification uses the exception type. A validation error stays FAILED. The
end-to-end checks through the HTTP, Slack and payment executors are in
`contrib/executors/tests/test_ambiguous_transport.py`.
"""

import errno
import http.client
import ssl
from urllib import error

from tempus_ddb.executor_runtime import is_ambiguous_transport_error

AMBIGUOUS = [
    TimeoutError("timed out"),
    ConnectionResetError(104, "Connection reset by peer"),
    ssl.SSLError("tls handshake failed"),
    EOFError("unexpected eof"),
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    http.client.IncompleteRead(b"partial"),
    http.client.BadStatusLine(""),
    error.URLError(TimeoutError("timed out")),
    error.URLError(ConnectionResetError(104, "reset")),
    error.URLError(ssl.SSLError("eof in violation of protocol")),
]


def test_classifier_uses_exception_type_not_message_text():
    for exc in AMBIGUOUS:
        assert is_ambiguous_transport_error(exc), type(exc)
    assert is_ambiguous_transport_error(
        error.HTTPError("https://example.com/x", 500, "err", None, None)
    )
    # OSError(errno.ECONNRESET, ...) is promoted to ConnectionResetError by CPython and
    # would only exercise the type branch; set errno on a plain OSError instead.
    reset = OSError("Connection reset by peer")
    reset.errno = errno.ECONNRESET
    assert is_ambiguous_transport_error(reset)
    for exc in (
        ValueError("amount 500.00 exceeds the limit"),
        RuntimeError("HTTP 500 Internal Server Error: Gateway timeout"),
        RuntimeError("socket timeout while checking the amount 500.00"),
        ConnectionRefusedError(111, "Connection refused"),
        error.HTTPError("https://example.com/x", 404, "missing", None, None),
        error.URLError("timed out"),
    ):
        assert not is_ambiguous_transport_error(exc), type(exc)
