import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from nacl import encoding, public

from litch.diff import Actual
from litch.model import Config

API = "https://api.github.com"
ROLE_FROM_GITHUB = {
    "admin": "admin",
    "maintain": "maintain",
    "push": "push",
    "write": "push",
    "triage": "triage",
    "pull": "pull",
    "read": "pull",
}


class GitHubError(RuntimeError):
    pass


class GitHub:
    def __init__(self, token: str):
        self.token = token

    def fetch(self, config: Config) -> Actual:
        repo = self._get(f"/repos/{config.repo}")
        return Actual(
            users=self._users(config),
            teams=self._teams(config),
            rulesets=self._rulesets(config),
            repo_settings={key: bool(repo.get(key)) for key in config.repo_settings},
            variables=self._variables(config),
            secret_names=self._secret_names(config),
            codeowners=self._file(config, ".github/CODEOWNERS"),
            workflows={item.path: self._file(config, item.path) for item in config.workflows},
        )

    def put_settings(self, config: Config) -> None:
        self._request("PATCH", f"/repos/{config.repo}", config.repo_settings)

    def put_user(self, config: Config, name: str, permission: str) -> None:
        self._request(
            "PUT",
            f"/repos/{config.repo}/collaborators/{urllib.parse.quote(name)}",
            {"permission": permission},
        )

    def delete_user(self, config: Config, name: str) -> None:
        self._request("DELETE", f"/repos/{config.repo}/collaborators/{urllib.parse.quote(name)}")

    def put_team(self, config: Config, name: str, permission: str) -> None:
        self._request(
            "PUT",
            f"/orgs/{config.owner}/teams/{urllib.parse.quote(name)}/repos/{config.repo}",
            {"permission": permission},
        )

    def delete_team(self, config: Config, name: str) -> None:
        self._request(
            "DELETE",
            f"/orgs/{config.owner}/teams/{urllib.parse.quote(name)}/repos/{config.repo}",
        )

    def put_ruleset(self, config: Config, name: str) -> None:
        rule = next(item for item in config.rulesets if item.name == name)
        body = _ruleset_body(rule)
        current = self._ruleset_index(config).get(name)
        if current is None:
            self._request("POST", f"/repos/{config.repo}/rulesets", body)
            return
        self._request("PUT", f"/repos/{config.repo}/rulesets/{current}", body)

    def put_variable(self, config: Config, name: str, value: str) -> None:
        existing = {item["name"] for item in self._collection(f"/repos/{config.repo}/actions/variables", "variables")}
        quoted = urllib.parse.quote(name)
        if name in existing:
            self._request(
                "PATCH",
                f"/repos/{config.repo}/actions/variables/{quoted}",
                {"name": name, "value": value},
            )
            return
        self._request("POST", f"/repos/{config.repo}/actions/variables", {"name": name, "value": value})

    def put_secret(self, config: Config, name: str, value: str) -> None:
        key = self._get(f"/repos/{config.repo}/actions/secrets/public-key")
        self._request(
            "PUT",
            f"/repos/{config.repo}/actions/secrets/{urllib.parse.quote(name)}",
            {"encrypted_value": encrypt_secret(key["key"], value), "key_id": key["key_id"]},
        )

    def put_text_file(self, config: Config, path: str, content: str, message: str) -> None:
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        body: dict[str, str] = {"message": message, "content": encoded}
        current = self._content_sha(config, path)
        if current:
            body["sha"] = current
        self._request("PUT", f"/repos/{config.repo}/contents/{path}", body)

    def _users(self, config: Config) -> dict[str, str]:
        users = {}
        for item in self._pages(f"/repos/{config.repo}/collaborators?affiliation=direct"):
            login = item.get("login")
            role = role_name(item)
            if login and role:
                users[login] = role
        return users

    def _teams(self, config: Config) -> dict[str, str]:
        teams = {}
        try:
            page = self._pages(f"/repos/{config.repo}/teams")
        except GitHubError as exc:
            if "404" in str(exc):
                return {}
            raise
        for item in page:
            slug = item.get("slug")
            role = role_name(item)
            if slug and role:
                teams[slug] = role
        return teams

    def _rulesets(self, config: Config) -> dict[str, dict]:
        found = {}
        for item in self._pages(f"/repos/{config.repo}/rulesets"):
            detail = self._get(f"/repos/{config.repo}/rulesets/{item['id']}")
            found[detail["name"]] = _ruleset_view(detail)
        return found

    def _ruleset_index(self, config: Config) -> dict[str, int]:
        return {item["name"]: item["id"] for item in self._pages(f"/repos/{config.repo}/rulesets")}

    def _variables(self, config: Config) -> dict[str, str]:
        wanted = {item.name for item in config.variables}
        values = {}
        for item in self._collection(f"/repos/{config.repo}/actions/variables", "variables"):
            if item.get("name") in wanted:
                values[item["name"]] = item.get("value", "")
        return values

    def _secret_names(self, config: Config) -> set[str]:
        names = set()
        for item in self._collection(f"/repos/{config.repo}/actions/secrets", "secrets"):
            if item.get("name"):
                names.add(item["name"])
        return names

    def _file(self, config: Config, path: str) -> str | None:
        try:
            body = self._get(f"/repos/{config.repo}/contents/{path}")
        except GitHubError as exc:
            if "404" in str(exc):
                return None
            raise
        if body.get("encoding") != "base64" or not isinstance(body.get("content"), str):
            return None
        return base64.b64decode(body["content"]).decode("utf-8")

    def _content_sha(self, config: Config, path: str) -> str | None:
        try:
            body = self._get(f"/repos/{config.repo}/contents/{path}")
        except GitHubError as exc:
            if "404" in str(exc):
                return None
            raise
        return body.get("sha")

    def _pages(self, path: str) -> list[dict]:
        items: list[dict] = []
        page = 1
        while True:
            joiner = "&" if "?" in path else "?"
            body = self._get(f"{path}{joiner}per_page=100&page={page}")
            if not isinstance(body, list):
                raise GitHubError(f"expected a list from {path}")
            items.extend(body)
            if len(body) < 100:
                return items
            page += 1

    def _collection(self, path: str, key: str) -> list[dict]:
        items: list[dict] = []
        page = 1
        while True:
            joiner = "&" if "?" in path else "?"
            body = self._get(f"{path}{joiner}per_page=100&page={page}")
            chunk = body.get(key) or []
            if not isinstance(chunk, list):
                raise GitHubError(f"expected {key} from {path}")
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1

    def _get(self, path: str):
        return self._request("GET", path)

    def _request(self, method: str, path: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            API + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "litch",
                **({"Content-Type": "application/json"} if data else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise GitHubError(f"github 404 {path}") from None
            raise GitHubError(f"github {exc.code} {path}") from None
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))


def role_name(item: dict) -> str | None:
    permissions = item.get("permissions")
    if isinstance(permissions, dict):
        for role in ("admin", "maintain", "push", "triage", "pull"):
            if permissions.get(role):
                return role
    raw = (item.get("role_name") or item.get("permission") or "").lower()
    return ROLE_FROM_GITHUB.get(raw)


def encrypt_secret(public_key: str, value: str) -> str:
    key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder)
    encrypted = public.SealedBox(key).encrypt(value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def _ruleset_body(rule) -> dict:
    rules = []
    if rule.required_reviews or rule.dismiss_stale:
        rules.append(
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": rule.required_reviews,
                    "dismiss_stale_reviews_on_push": rule.dismiss_stale,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False,
                },
            }
        )
    if rule.status_checks:
        rules.append(
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": check} for check in rule.status_checks],
                },
            }
        )
    if rule.block_force_push:
        rules.append({"type": "non_fast_forward"})
    return {
        "name": rule.name,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [rule.ref], "exclude": []}},
        "rules": rules,
    }


def _ruleset_view(detail: dict) -> dict:
    reviews = 0
    dismiss = False
    checks: list[str] = []
    block = False
    for rule in detail.get("rules") or []:
        kind = rule.get("type")
        params = rule.get("parameters") or {}
        if kind == "pull_request":
            reviews = int(params.get("required_approving_review_count") or 0)
            dismiss = bool(params.get("dismiss_stale_reviews_on_push"))
        elif kind == "required_status_checks":
            checks = [item.get("context", "") for item in params.get("required_status_checks") or []]
        elif kind == "non_fast_forward":
            block = True
    includes = ((detail.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    return {
        "ref": includes[0] if includes else "",
        "required_reviews": reviews,
        "dismiss_stale": dismiss,
        "status_checks": sorted(check for check in checks if check),
        "block_force_push": block,
    }
