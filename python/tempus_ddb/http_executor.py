"""Credential-isolated HTTP/Webhook executor for Tempus permits."""

import ipaddress
import json
import os
from typing import Any, Dict, Optional, Protocol, Set
from urllib import error, parse, request

from . import __version__
from .executor_runtime import (
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
)


class HttpExecutorError(RuntimeError):
    """Base error for HTTP executor failures."""


class HttpAPIError(HttpExecutorError):
    """A non-2xx HTTP response from the target endpoint."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _validate_https_url(
    target_url: str, allowed_domains: Optional[Set[str]] = None
) -> str:
    candidate = target_url.strip()
    parsed = parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HttpExecutorError("Target URL must be a valid HTTPS endpoint")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HttpExecutorError("Target URL must contain a valid hostname")

    # SSRF protection: reject localhost and private IP networks
    if hostname in {"localhost", "localhost.localdomain"}:
        raise HttpExecutorError("Target URL host cannot be localhost")

    try:
        ip = ipaddress.ip_address(hostname)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise HttpExecutorError(f"Target URL resolves to disallowed IP: {ip}")
    except ValueError:
        pass

    if allowed_domains is not None:
        matched = any(
            hostname == d
            or hostname.endswith("." + d)
            or d == "*"
            for d in allowed_domains
        )
        if not matched:
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
            with request.urlopen(req, timeout=30) as response:  # nosec B310
                raw = response.read().decode("utf-8")
                try:
                    return (
                        json.loads(raw)
                        if raw
                        else {"status": "ok", "http_status": response.status}
                    )
                except json.JSONDecodeError:
                    return {"body": raw, "http_status": response.status}
        except error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise HttpAPIError(exc.code, f"HTTP {exc.code}: {err_body}") from exc
        except Exception as exc:
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
        self._transport = transport or UrllibHttpTransport(
            allowed_domains=self._allowed_domains
        )

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        action_type = intent.get("action_type")
        target_url = intent.get("resource")
        _validate_https_url(target_url, self._allowed_domains)

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
        except Exception as exc:
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
