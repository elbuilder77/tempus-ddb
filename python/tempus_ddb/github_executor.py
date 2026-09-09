"""Credential-isolated GitHub executor for Tempus permits."""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Optional, Protocol, Set, Tuple
from urllib import error, parse, request

from . import __version__
from .executor_runtime import (
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
    UnknownExecutionError,
)

RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _validate_github_api_url(api_url: str) -> str:
    """Accept only an explicit HTTPS GitHub or GitHub Enterprise API endpoint."""
    candidate = api_url.strip().rstrip("/")
    parsed = parse.urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubExecutorError("GitHub API URL must be an absolute HTTPS endpoint")
    return candidate


class GitHubExecutorError(RuntimeError):
    """Base error for configuration and permit failures."""


class GitHubAPIError(GitHubExecutorError):
    """A definitive HTTP response returned by GitHub."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


class GitHubTransport(Protocol):
    """Transport boundary used by the real client and deterministic tests."""

    def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute one GitHub API request."""


class GitHubTokenProvider(Protocol):
    """Resolve credentials only for a validated, consumed intent."""

    def token_for(self, resource: str, action_type: str) -> str:
        """Return a credential bound to the configured installation."""


class _RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GitHubExecutorError("GitHub API redirects are not allowed")


class UrllibGitHubTransport:
    """Minimal GitHub REST transport with no dependency outside the standard library."""

    def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        _validate_github_api_url(url)
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        github_request = request.Request(
            url,
            data=encoded,
            headers=headers,
            method=method,
        )
        try:
            # The endpoint was validated above as absolute HTTPS with no credentials or query.
            opener = request.build_opener(_RejectRedirects())
            with opener.open(github_request, timeout=30) as response:  # nosec B310
                body = response.read().decode("utf-8")
                parsed = json.loads(body) if body else {}
                if not isinstance(parsed, dict):
                    raise GitHubExecutorError(
                        "GitHub returned a non-object JSON response"
                    )
                return parsed
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
                message = str(parsed.get("message", body))
            except json.JSONDecodeError:
                message = body or str(exc)
            raise GitHubAPIError(exc.code, message) from exc


class GitHubActionAdapter:
    """ActionAdapter implementation for GitHub REST API writes."""

    unsupported_error_code = "TEMPUS_GITHUB_BINDING_REJECTED"

    SUPPORTED_ACTIONS: Set[str] = {
        "github.create_issue",
        "github.create_pull_request",
    }

    def __init__(
        self,
        token: Optional[str] = None,
        api_url: str = "https://api.github.com",
        transport: Optional[GitHubTransport] = None,
        token_provider: Optional[GitHubTokenProvider] = None,
    ):
        if token and token_provider is not None:
            raise GitHubExecutorError("Configure only one GitHub credential source")
        if not token and token_provider is None:
            raise GitHubExecutorError(
                "GITHUB_TOKEN is required by the executor process"
            )
        self._token = token or ""
        self._token_provider = token_provider
        self._api_url = _validate_github_api_url(api_url)
        self._transport = transport or UrllibGitHubTransport()

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        """Validate intent shape, bind request, invoke GitHub REST API and sanitize result."""
        try:
            method, url, payload, action_type, resource = self._bind_request(intent)
        except (KeyError, TypeError, ValueError, GitHubExecutorError) as exc:
            return ExecutionResult(
                status="FAILED",
                payload={
                    "error_code": "TEMPUS_GITHUB_BINDING_REJECTED",
                    "message": str(exc),
                },
            )

        try:
            token = (
                self._token_provider.token_for(resource, action_type)
                if self._token_provider is not None
                else self._token
            )
            if not token:
                raise GitHubExecutorError("Empty credential")
        except Exception:
            # No action has been sent. Never include provider errors or secrets.
            return ExecutionResult(
                status="FAILED",
                payload={"error_code": "TEMPUS_GITHUB_CREDENTIAL_REJECTED"},
            )

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": f"tempus-ddb-github-executor/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            response = self._transport.request(method, url, headers, payload)
            result = self._sanitize_result(response, action_type, resource)
            return ExecutionResult(status="SUCCEEDED", payload=result)
        except GitHubAPIError as exc:
            if exc.status_code >= 500:
                raise AmbiguousTransportError(
                    f"GITHUB_SERVER_RESPONSE_{exc.status_code}"
                ) from exc
            return ExecutionResult(
                status="FAILED",
                payload={
                    "error_code": "GITHUB_HTTP_" + str(exc.status_code),
                    "message": str(exc),
                },
            )
        except Exception as exc:
            raise AmbiguousTransportError(
                f"GITHUB_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
            ) from exc

    def _bind_request(
        self, intent: Dict[str, Any]
    ) -> Tuple[str, str, Dict[str, Any], str, str]:
        action_type = self._required_string(intent, "action_type")
        resource = self._required_string(intent, "resource")
        if not RESOURCE_PATTERN.fullmatch(resource):
            raise GitHubExecutorError(
                "resource must be an exact 'owner/repository' value"
            )
        action_input = intent.get("input")
        if not isinstance(action_input, dict):
            raise GitHubExecutorError("intent.input must be an object")

        if action_type == "github.create_issue":
            payload = self._issue_payload(action_input)
            endpoint = "/repos/" + resource + "/issues"
        elif action_type == "github.create_pull_request":
            payload = self._pull_request_payload(action_input)
            endpoint = "/repos/" + resource + "/pulls"
        else:
            raise GitHubExecutorError("unsupported GitHub action_type: " + action_type)
        return "POST", self._api_url + endpoint, payload, action_type, resource

    @staticmethod
    def _required_string(value: Dict[str, Any], field: str) -> str:
        result = value.get(field)
        if not isinstance(result, str) or not result:
            raise GitHubExecutorError(field + " must be a non-empty string")
        return result

    def _issue_payload(self, value: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"title", "body", "labels"}
        self._reject_unknown_fields(value, allowed)
        payload: Dict[str, Any] = {"title": self._required_string(value, "title")}
        if "body" in value:
            if not isinstance(value["body"], str):
                raise GitHubExecutorError("input.body must be a string")
            payload["body"] = value["body"]
        if "labels" in value:
            labels = value["labels"]
            if not isinstance(labels, list) or not all(
                isinstance(label, str) for label in labels
            ):
                raise GitHubExecutorError("input.labels must be an array of strings")
            payload["labels"] = labels
        return payload

    def _pull_request_payload(self, value: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"title", "head", "base", "body", "draft"}
        self._reject_unknown_fields(value, allowed)
        payload: Dict[str, Any] = {
            "title": self._required_string(value, "title"),
            "head": self._required_string(value, "head"),
            "base": self._required_string(value, "base"),
        }
        if "body" in value:
            if not isinstance(value["body"], str):
                raise GitHubExecutorError("input.body must be a string")
            payload["body"] = value["body"]
        if "draft" in value:
            if not isinstance(value["draft"], bool):
                raise GitHubExecutorError("input.draft must be a boolean")
            payload["draft"] = value["draft"]
        return payload

    @staticmethod
    def _reject_unknown_fields(value: Dict[str, Any], allowed: set) -> None:
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise GitHubExecutorError("unsupported input fields: " + ", ".join(unknown))

    @staticmethod
    def _sanitize_result(
        response: Dict[str, Any], action_type: str, resource: str
    ) -> Dict[str, Any]:
        result = {"action_type": action_type, "resource": resource}
        for field in ("id", "number", "html_url", "url", "state"):
            if field in response:
                result[field] = response[field]
        return result


class GitHubExecutorAdapter:
    """Execute a narrow set of GitHub writes from a verified Tempus permit."""

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        token: Optional[str] = None,
        api_url: str = "https://api.github.com",
        transport: Optional[GitHubTransport] = None,
        executor_pool_size: int = 8,
        token_provider: Optional[GitHubTokenProvider] = None,
    ):
        if token_provider is None:
            token = token or os.environ.get("GITHUB_TOKEN", "")
        self._adapter = GitHubActionAdapter(
            token=token or "",
            api_url=api_url,
            transport=transport,
            token_provider=token_provider,
        )
        self._runtime = ExecutorRuntime(
            executor_db=executor_db,
            executor_keyfile=executor_keyfile,
            trusted_gate_id=trusted_gate_id,
            trusted_tenant_id=trusted_tenant_id,
            executor_pool_size=executor_pool_size,
        )

    def execute(self, permit_json: str) -> str:
        """Consume a permit, perform exactly its GitHub action, and sign the outcome."""
        return self._runtime.execute_permit(permit_json, self._adapter)

    execute_permit = execute

    def recover_incomplete(self, older_than_seconds: int = 0) -> str:
        """Mark stale STARTED executions UNKNOWN without replaying GitHub writes."""
        return self._runtime.raw_executor.recover_incomplete(older_than_seconds)

    def get_execution_state(self, authorization_id: str) -> str:
        """Return the executor's signed local state for an authorization."""
        return self._runtime.raw_executor.get_execution_state(authorization_id)


def _read_permit(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tempus-github-executor",
        description="Execute a GitHub write bound to a signed Tempus permit",
    )
    parser.add_argument(
        "--permit", required=True, help="Permit JSON file, or '-' for stdin"
    )
    parser.add_argument("--executor-db", required=True)
    parser.add_argument("--executor-keyfile", required=True)
    parser.add_argument("--gate-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--api-url", default="https://api.github.com")
    parser.add_argument("--app-client-id", help="GitHub App client ID (or App ID)")
    parser.add_argument("--app-private-key", help="Path to the GitHub App RSA PEM key")
    parser.add_argument("--installation-id", type=int)
    parser.add_argument("--repository", help="Exact owner/repository for this executor")
    parser.add_argument(
        "--executor-pool-size",
        type=int,
        default=8,
        help="Maximum pooled SQLite connections (default: 8)",
    )
    args = parser.parse_args()

    try:
        app_values = (
            args.app_client_id,
            args.app_private_key,
            args.installation_id,
            args.repository,
        )
        provider = None
        if any(value is not None for value in app_values):
            if not all(value is not None for value in app_values):
                parser.error(
                    "GitHub App mode requires all four App/installation/repository options"
                )
            from .github_app import GitHubAppCredentials

            provider = GitHubAppCredentials(
                args.app_client_id,
                args.app_private_key,
                args.installation_id,
                args.repository,
                api_url=args.api_url,
            )
        token = "" if provider is not None else os.environ.get(args.token_env, "")
        adapter = GitHubExecutorAdapter(
            args.executor_db,
            args.executor_keyfile,
            args.gate_id,
            args.tenant_id,
            token=token,
            api_url=args.api_url,
            executor_pool_size=args.executor_pool_size,
            token_provider=provider,
        )
        print(adapter.execute(_read_permit(args.permit)))
    except UnknownExecutionError as exc:
        print(exc.observation)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
