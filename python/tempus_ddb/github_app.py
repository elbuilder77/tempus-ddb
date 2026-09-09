"""GitHub App credentials isolated inside a single-tenant mediated executor."""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import __version__
from .github_executor import (
    RESOURCE_PATTERN,
    GitHubExecutorError,
    GitHubTransport,
    UrllibGitHubTransport,
    _validate_github_api_url,
)


class GitHubAppCredentials:
    """Mint short-lived credentials for an operator-bound installation/repository.

    Never derive installation IDs or repository bindings from agent input. Create
    a separate executor database, identity and provider for each tenant binding.
    """

    _PERMISSIONS = {
        "github.create_issue": "issues",
        "github.create_pull_request": "pull_requests",
    }

    def __init__(
        self,
        client_id: str,
        private_key_path: str,
        installation_id: int,
        repository: str,
        *,
        api_url: str = "https://api.github.com",
        transport: Optional[GitHubTransport] = None,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(client_id, str) or not client_id.strip():
            raise GitHubExecutorError("GitHub App client ID is required")
        if type(installation_id) is not int or installation_id <= 0:
            raise GitHubExecutorError(
                "GitHub installation ID must be a positive integer"
            )
        if not isinstance(repository, str) or not RESOURCE_PATTERN.fullmatch(
            repository
        ):
            raise GitHubExecutorError("GitHub App repository must be owner/repository")
        try:
            import jwt
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        except ImportError as exc:
            raise GitHubExecutorError(
                "Install tempus-ddb[github-app] for GitHub App mode"
            ) from exc
        try:
            key = serialization.load_pem_private_key(
                Path(private_key_path).read_bytes(), password=None
            )
            if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
                raise ValueError("RSA key required")
        except Exception:
            raise GitHubExecutorError(
                "Cannot load GitHub App RSA private key (2048+ bits)"
            ) from None
        self._jwt = jwt
        self._key = key
        self._client_id = client_id
        self._installation_id = installation_id
        self._repository = repository.lower()
        self._api_url = _validate_github_api_url(api_url)
        self._transport = transport or UrllibGitHubTransport()
        self._clock = clock
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def token_for(self, resource: str, action_type: str) -> str:
        if resource.lower() != self._repository or action_type not in self._PERMISSIONS:
            raise GitHubExecutorError("Intent is outside the GitHub App binding")
        permission = self._PERMISSIONS[action_type]
        with self._lock:
            now = self._clock()
            cached = self._cache.get(permission)
            if cached is not None and cached[1] > now + 60:
                return cached[0]
            self._cache.pop(permission, None)
            app_jwt = self._jwt.encode(
                {"iat": int(now) - 60, "exp": int(now) + 540, "iss": self._client_id},
                self._key,
                algorithm="RS256",
            )
            try:
                response = self._transport.request(
                    "POST",
                    f"{self._api_url}/app/installations/{self._installation_id}/access_tokens",
                    {
                        "Accept": "application/vnd.github+json",
                        "Authorization": "Bearer " + app_jwt,
                        "Content-Type": "application/json",
                        "User-Agent": f"tempus-ddb-github-app/{__version__}",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    {
                        "repositories": [self._repository.split("/", 1)[1]],
                        "permissions": {permission: "write"},
                    },
                )
                token = response["token"]
                expiry = datetime.fromisoformat(
                    response["expires_at"].replace("Z", "+00:00")
                )
                if expiry.tzinfo is None:
                    raise ValueError("Expiry must include timezone")
                expires_at = expiry.astimezone(timezone.utc).timestamp()
                if (
                    not isinstance(token, str)
                    or not token
                    or expires_at <= self._clock() + 60
                ):
                    raise ValueError("Invalid installation token")
            except Exception:
                # GitHub response bodies and transport errors may contain credentials.
                raise GitHubExecutorError(
                    "GitHub App installation authentication failed"
                ) from None
            self._cache[permission] = (token, expires_at)
            return token
