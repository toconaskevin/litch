import json
import time
import urllib.error
import urllib.request

import jwt

from litch.model import (
    GITHUB_APP_CLIENT_ID,
    GITHUB_APP_ID,
    GITHUB_APP_INSTALLATION_ID,
    GITHUB_APP_PEM,
    GITHUB_APP_SECRETS,
)
from litch.secrets import SecretError, SecretSource, _secret_error

API = "https://api.github.com"


def installation_auth(source: SecretSource) -> tuple[str, int]:
    values = {name: source.get(name) for name in GITHUB_APP_SECRETS}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SecretError(f"missing GitHub App secrets in vault: {', '.join(missing)}")
    app_id = _positive_int(values[GITHUB_APP_ID], GITHUB_APP_ID)
    installation_id = _positive_int(values[GITHUB_APP_INSTALLATION_ID], GITHUB_APP_INSTALLATION_ID)
    assertion = _app_jwt(values[GITHUB_APP_CLIENT_ID] or "", values[GITHUB_APP_PEM] or "")
    request = urllib.request.Request(
        f"{API}/app/installations/{installation_id}/access_tokens",
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {assertion}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "litch",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise _secret_error(
            f"github: installation token request failed ({exc.code}) for installation {installation_id}",
            exc,
        ) from None
    token = body.get("token")
    if not isinstance(token, str) or not token:
        raise SecretError("github: installation token response did not include a token")
    return token, app_id


def _app_jwt(client_id: str, pem: str) -> str:
    now = int(time.time())
    try:
        return jwt.encode(
            {"iat": now - 60, "exp": now + 9 * 60, "iss": client_id},
            pem,
            algorithm="RS256",
        )
    except (ValueError, jwt.exceptions.PyJWTError) as exc:
        raise SecretError(f"github: could not sign the App JWT with {GITHUB_APP_PEM}: {exc}") from None


def _positive_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise SecretError(f"{name} must be an integer") from None
    if number <= 0:
        raise SecretError(f"{name} must be an integer")
    return number
