"""Credential-isolated HTTP/Webhook executor for Tempus permits."""

import json
import os
from typing import Any, Dict, Optional, Protocol, Set
from urllib import error, parse, request

from tempus_ddb._http import (
    DestinationRefused,
    RedirectRefused,
    check_host_literal,
    open_request,
)
from tempus_ddb.executor_runtime import (
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
    is_ambiguous_transport_error,
)

from . import __version__


class HttpExecutorError(RuntimeError):
    """Base error for HTTP executor failures."""


class HttpAPIError(HttpExecutorError):
    """A non-2xx HTTP response from the target endpoint."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _host_pattern_matches(pattern: str, hostname: str) -> bool:
    """Whether an allowlist entry matches ``hostname``.

    An entry is an exact host, ``*`` (every host), or ``*.domain`` (one or more
    labels under that domain, not the apex). An exact entry does not include
    other labels. A ``*`` that is not its own component matches nothing.
    """
    pattern = pattern.lower()
    hostname = hostname.lower()
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == hostname
    if pattern.count("*") == 1 and pattern.startswith("*."):
        suffix = pattern[2:]
        if suffix and not suffix.startswith(".") and not suffix.endswith("."):
            dotted = "." + suffix
            return hostname.endswith(dotted) and len(hostname) > len(dotted)
    return False


def _reject_dot_segments(path: str) -> None:
    """Refuse `.` and `..` path segments, however they are spelled.

    The policy matches the text (`https://api.example.com/v1/*`) but the server resolves
    `/v1/../admin` or `/v1/%2e%2e/admin` to another path. The path is percent-decoded
    until it stops changing (so `%252e%252e` is caught too), then split on `/`; a
    backslash (some servers treat it as `/`) or an `;param` after the dots does not hide
    a segment either.
    """
    decoded = path
    for _ in range(5):
        again = parse.unquote(decoded)
        if again == decoded:
            break
        decoded = again
    else:
        raise HttpExecutorError("Target URL path is encoded too many times")
    if "\\" in decoded:
        raise HttpExecutorError("Target URL path must not contain backslashes")
    for segment in decoded.split("/"):
        if segment.split(";", 1)[0] in {".", ".."}:
            raise HttpExecutorError("Target URL path must not contain '.' or '..' segments")


def _validate_https_url(
    target_url: str, allowed_domains: Optional[Set[str]] = None
) -> str:
    # The URL that is validated must be byte for byte the URL that is requested (and the
    # string the policy matched): urlsplit drops tabs and newlines and `.strip()` removes
    # padding, which urllib keeps, so anything they would disagree on is refused.
    if not isinstance(target_url, str) or any(
        char.isspace() or char == "\\" or ord(char) < 0x20 or ord(char) == 0x7F
        for char in target_url
    ):
        raise HttpExecutorError(
            "Target URL must not contain whitespace, control characters or backslashes"
        )
    candidate = target_url
    parsed = parse.urlsplit(candidate)
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise HttpExecutorError("Target URL must not contain credentials")
    if parsed.scheme != "https" or not parsed.netloc:
        raise HttpExecutorError("Target URL must be a valid HTTPS endpoint")

    _reject_dot_segments(parsed.path)

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HttpExecutorError("Target URL must contain a valid hostname")

    # SSRF filter (see _http.py): names/IP spellings that are refused without any lookup.
    # Resolution is checked again, and pinned, when the connection is made.
    if "%" in hostname:
        raise HttpExecutorError("Target URL host must not contain percent escapes")
    try:
        parsed.port
    except ValueError:
        raise HttpExecutorError("Target URL has an invalid port") from None
    try:
        check_host_literal(hostname)
    except DestinationRefused as exc:
        raise HttpExecutorError(f"Target URL destination refused: {exc}") from exc

    if allowed_domains is not None:
        # Exact host, `*`, or `*.domain`. A `*` that is not its own component
        # matches nothing. An exact host does not include other labels.
        if not any(_host_pattern_matches(entry, hostname) for entry in allowed_domains):
            raise HttpExecutorError(
                f"Target URL host '{hostname}' is not in allowed domains list"
            )

    return candidate


class HttpTransport(Protocol):
    """Transport protocol for mockability and real requests."""

    def request(
        self, method: str, url: str, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute one HTTP request."""


class UrllibHttpTransport:
    """Builtin HTTPS transport with zero external dependencies."""

    def __init__(self, allowed_domains: Optional[Set[str]] = None):
        self._allowed_domains = allowed_domains

    def request(
        self, method: str, url: str, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        _validate_https_url(url, self._allowed_domains)
        data = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload
            else None
        )
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with open_request(req, timeout=30, pinned=True) as response:  # nosec B310
                raw = response.read().decode("utf-8")
                try:
                    return (
                        json.loads(raw)
                        if raw
                        else {"status": "ok", "http_status": response.status}
                    )
                except json.JSONDecodeError:
                    return {"body": raw, "http_status": response.status}
        except RedirectRefused as exc:
            raise HttpAPIError(exc.status_code, str(exc)) from exc
        except DestinationRefused as exc:
            raise HttpExecutorError(f"Target URL destination refused: {exc}") from exc
        except error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise HttpAPIError(exc.code, f"HTTP {exc.code}: {err_body}") from exc
        except AmbiguousTransportError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                raise AmbiguousTransportError(
                    f"HTTP_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from exc
            raise HttpExecutorError(f"HTTP transport failed: {exc}") from exc


class HttpActionAdapter:
    """ActionAdapter implementation for HTTPS Webhooks and API endpoints."""

    SUPPORTED_ACTIONS: Set[str] = {"http.post", "http.put", "webhook.send"}

    def __init__(
        self,
        auth_header: Optional[str] = None,
        transport: Optional[HttpTransport] = None,
        allowed_domains: Optional[Set[str]] = None,
    ):
        self._auth_header = auth_header or os.environ.get("HTTP_EXECUTOR_AUTH_HEADER")
        allowed_env = os.environ.get("HTTP_EXECUTOR_ALLOWED_DOMAINS")
        if allowed_domains is not None:
            self._allowed_domains = {
                d.strip().lower() for d in allowed_domains if d.strip()
            }
        elif allowed_env:
            self._allowed_domains = {
                d.strip().lower() for d in allowed_env.split(",") if d.strip()
            }
        else:
            self._allowed_domains = None
        if self._auth_header and not self._allowed_domains:
            # Fail closed: an Authorization header requires a domain allowlist.
            raise HttpExecutorError(
                "Refusing to start: an Authorization header is configured without a "
                "domain allowlist (allowed_domains / --allowed-domains / "
                "HTTP_EXECUTOR_ALLOWED_DOMAINS). Name the hosts that may receive the "
                "secret, or pass '*' to accept every host explicitly."
            )
        self._transport = transport or UrllibHttpTransport(
            allowed_domains=self._allowed_domains
        )

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        action_type = intent.get("action_type")
        target_url = _validate_https_url(intent.get("resource"), self._allowed_domains)

        input_data = intent.get("input", {})
        method = "PUT" if action_type == "http.put" else "POST"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Tempus-Http-Executor/{__version__}",
        }
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        try:
            result = self._transport.request(method, target_url, headers, input_data)
            return ExecutionResult(status="SUCCEEDED", payload=result)
        except HttpAPIError as exc:
            if exc.status_code >= 500:
                raise AmbiguousTransportError(
                    f"HTTP_SERVER_RESPONSE_{exc.status_code}"
                ) from exc
            return ExecutionResult(
                status="FAILED",
                payload={"http_status": exc.status_code, "error": str(exc)},
            )
        except AmbiguousTransportError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                raise AmbiguousTransportError(
                    f"HTTP_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from exc
            return ExecutionResult(status="FAILED", payload={"error": str(exc)})


class HttpExecutorAdapter:
    """Mediated executor that manages credentials, validates targets, and calls ActionAdapter."""

    SUPPORTED_ACTIONS = {"http.post", "http.put", "webhook.send"}

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        auth_header: Optional[str] = None,
        transport: Optional[HttpTransport] = None,
        executor_pool_size: int = 8,
        allowed_domains: Optional[Set[str]] = None,
        gate_db: Optional[str] = None,
    ):
        self._adapter = HttpActionAdapter(
            auth_header=auth_header,
            transport=transport,
            allowed_domains=allowed_domains,
        )
        self._runtime = ExecutorRuntime(
            executor_db=executor_db,
            executor_keyfile=executor_keyfile,
            trusted_gate_id=trusted_gate_id,
            trusted_tenant_id=trusted_tenant_id,
            executor_pool_size=executor_pool_size,
            gate_db=gate_db,
        )

    def execute(self, permit_json: str) -> str:
        """Verify, consume, execute, and sign the outcome receipt."""
        return self._runtime.execute_permit(permit_json, self._adapter)

    execute_permit = execute


def main() -> None:
    def extra_args(parser):
        parser.add_argument(
            "--auth-header", help="Optional secret Authorization header"
        )
        parser.add_argument(
            "--allowed-domains",
            help="Comma-separated list of allowed HTTPS destination domains",
        )

    ExecutorRuntime.run_cli(
        description="Tempus Credential-Isolated HTTP Executor",
        adapter_factory=lambda args: HttpActionAdapter(
            auth_header=args.auth_header,
            allowed_domains=(
                set(args.allowed_domains.split(","))
                if getattr(args, "allowed_domains", None)
                else None
            ),
        ),
        extra_args_fn=extra_args,
    )


if __name__ == "__main__":
    main()
