import io
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from litch.cli import main
from litch.config import ConfigError, load_config, parse_config, parse_definition
from litch.github_api import GitHub, GitHubError, role_name
from litch.diff import Actual, diff_config, render_codeowners, render_workflow
from litch.model import GITHUB_TOKEN_SECRET
from litch.secrets import SecretError, open_source, vault_name

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXAMPLE = FIXTURES / "single-app-repo.yaml"
TEMPLATES = str(FIXTURES / "templates")


def repo(kind="single-app", name="octocat/demo", **spec):
    return {"apiVersion": "litch.dev/v1", "kind": kind, "repo": name, "spec": spec}


def test_example_config_loads():
    config = load_config(str(EXAMPLE), templates=TEMPLATES)
    assert config.kind == "single-app"
    assert config.base == "single-app"
    assert config.repo == "toconaskevin/single-app-repo-for-litch"
    assert config.provider == "azure"
    assert config.users[0].permission == "admin"
    assert config.rulesets[0].status_checks == ("ci",)
    assert config.workflows[0].path == ".github/workflows/ci.yml"


def test_rejects_cloud_identifiers_in_yaml():
    with pytest.raises(ConfigError, match="only accepts provider"):
        parse_config(repo(secrets={"provider": "aws", "role_arn": "arn:aws:iam::1:role/x"}))


def test_rejects_unknown_permission():
    with pytest.raises(ConfigError, match="permission"):
        parse_config(repo(secrets={"provider": "azure"}, access={"users": [{"name": "octocat", "permission": "owner"}]}))


def test_rejects_unknown_template():
    with pytest.raises(ConfigError, match="template"):
        parse_config(repo(secrets={"provider": "gcp"}, actions={"workflows": [{"name": "ci", "template": "ci-go"}]}))


def test_a_template_is_copied_from_the_given_directory(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    text = "name: ci\njobs:\n  ci:\n    name: ci\n"
    (templates / "ci.yml").write_text(text, encoding="utf-8")
    config = parse_config(
        repo(secrets={"provider": "local"}, actions={"workflows": [{"name": "ci-api", "template": "ci"}]}),
        templates=str(templates),
    )
    assert config.workflows[0].path == ".github/workflows/ci-api.yml"
    assert render_workflow(config.workflows[0].template, config.template_dir) == text


def test_single_app_rejects_apps_and_names_workflow_files_from_the_slug(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "ci-node.yml").write_text("name: ci\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown spec field: apps"):
        parse_config(repo(secrets={"provider": "local"}, apps=[{"name": "api", "path": "/services/api/"}]))
    config = parse_config(
        repo(secrets={"provider": "local"}, actions={"workflows": [{"name": "ci-api", "template": "ci-node"}]}),
        templates=str(templates),
    )
    assert config.workflows[0].path == ".github/workflows/ci-api.yml"


def test_provider_env_is_required_before_github(monkeypatch):
    for key in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_KEY_VAULT_URL"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(SecretError, match="AZURE_TENANT_ID"):
        open_source("azure")


def test_azure_vault_name_uses_hyphens():
    assert vault_name("azure", "DEPLOY_TOKEN") == "DEPLOY-TOKEN"
    assert vault_name("aws", "DEPLOY_TOKEN") == "DEPLOY_TOKEN"


def test_plan_hides_secret_values_and_is_empty_when_the_repo_matches():
    config = load_config(str(EXAMPLE), templates=TEMPLATES)
    actual = Actual(
        users={"toconaskevin": "admin"},
        teams={},
        rulesets={"main": {
            "ref": "refs/heads/main",
            "required_reviews": 0,
            "dismiss_stale": False,
            "status_checks": ["ci"],
            "block_force_push": True,
        }},
        repo_settings=dict(config.repo_settings),
        variables={"ENVIRONMENT": "dev"},
        secret_names=set(),
        codeowners=render_codeowners(config),
        workflows={".github/workflows/ci.yml": render_workflow("ci", config.template_dir)},
    )
    sentinel = "super-secret-value"
    changes = diff_config(
        config,
        actual,
        {GITHUB_TOKEN_SECRET: sentinel},
    )
    assert changes == []
    rendered = "\n".join(change.line() for change in changes)
    assert sentinel not in rendered


def test_plan_reports_access_ruleset_and_missing_secret():
    config = parse_config(
        repo(
            secrets={"provider": "local"},
            access={"users": [{"name": "toconaskevin", "permission": "admin"}]},
            rulesets=[{"name": "main", "target": "branch", "ref": "refs/heads/main"}],
            actions={"secrets": [{"name": "DEPLOY_TOKEN", "required": True}]},
        )
    )
    actual = Actual(
        users={"someone": "push"},
        teams={},
        rulesets={},
        repo_settings={"delete_branch_on_merge": False},
        variables={},
        secret_names=set(),
        codeowners=None,
        workflows={},
    )
    changes = diff_config(config, actual, {"DEPLOY_TOKEN": None, GITHUB_TOKEN_SECRET: "token"})
    lines = [change.line() for change in changes]
    assert any(line.startswith("- access.user someone") for line in lines)
    assert any(line.startswith("+ ruleset main") for line in lines)
    assert any("secret DEPLOY_TOKEN" in line and "missing in vault" in line for line in lines)
    assert "token" not in "\n".join(lines)


def test_maintain_comes_from_the_permissions_object():
    assert role_name({"permission": "push", "permissions": {"admin": False, "maintain": True, "push": True, "pull": True}}) == "maintain"


def test_plan_stops_before_github_without_a_token(tmp_path, monkeypatch, capsys):
    config = tmp_path / "repo.yaml"
    config.write_text(
        "apiVersion: litch.dev/v1\nkind: single-app\nrepo: octocat/demo\nspec:\n  secrets:\n    provider: local\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("LITCH_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("litch-github-token", raising=False)
    assert main(["plan", "--config", str(config)]) == 2
    captured = capsys.readouterr()
    assert "litch-github-token" in captured.err
    assert captured.out == ""


def test_cli_rejects_a_missing_file():
    assert main(["plan", "--config", "does-not-exist.yaml"]) == 2


def test_apply_workflow_is_the_same_for_every_provider():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "azure/login" not in action
    assert "configure-aws-credentials" not in action
    assert "google-github-actions/auth" not in action


def test_multi_app_flattens_apps_and_workflow_files():
    config = load_config(str(FIXTURES / "multi-app-repo.yaml"), templates=TEMPLATES)
    assert config.base == "multi-app"
    assert [row.path for row in config.codeowners] == ["*", "/services/api/", "/services/web/"]
    assert [item.path for item in config.workflows] == [
        ".github/workflows/ci-api.yml",
        ".github/workflows/ci-web.yml",
    ]
    rendered = render_workflow("ci-api", config.template_dir)
    assert "name: ci-api" in rendered
    assert "\n  ci-api:\n" in rendered
    actual = Actual(
        users={"toconaskevin": "admin"},
        teams={},
        rulesets={"main": {
            "ref": "refs/heads/main",
            "required_reviews": 0,
            "dismiss_stale": False,
            "status_checks": ["ci-api", "ci-web"],
            "block_force_push": True,
        }},
        repo_settings=dict(config.repo_settings),
        variables={"ENVIRONMENT": "dev"},
        secret_names=set(),
        codeowners=render_codeowners(config),
        workflows={item.path: render_workflow(item.template, config.template_dir) for item in config.workflows},
    )
    assert diff_config(config, actual, {GITHUB_TOKEN_SECRET: "token"}) == []


def test_app_variables_merge_and_duplicates_fail():
    config = parse_config(
        repo(
            "multi-app",
            secrets={"provider": "local"},
            actions={"variables": [{"name": "ENVIRONMENT", "value": "dev"}]},
            apps=[{
                "name": "api",
                "path": "/services/api/",
                "codeowners": ["@octocat/app"],
                "variables": [{"name": "SERVICE", "value": "api"}],
                "secrets": [{"name": "API_TOKEN", "required": True}],
            }],
        )
    )
    assert [item.name for item in config.variables] == ["ENVIRONMENT", "SERVICE"]
    assert config.secrets[0].name == "API_TOKEN"
    with pytest.raises(ConfigError, match="duplicate variable"):
        parse_config(
            repo(
                "multi-app",
                secrets={"provider": "local"},
                actions={"variables": [{"name": "SERVICE", "value": "dev"}]},
                apps=[{"name": "api", "path": "/services/api/", "variables": [{"name": "SERVICE", "value": "api"}]}],
            )
        )


def test_custom_kind_merges_defaults_and_keeps_instance_values():
    definition = parse_definition(
        {
            "apiVersion": "litch.dev/v1",
            "kind": "ConfigDefinition",
            "metadata": {"name": "custom01"},
            "spec": {
                "base": "single-app",
                "required": ["access", "rulesets", "codeowners"],
                "defaults": {
                    "secrets": {"provider": "azure"},
                    "repo_settings": {"delete_branch_on_merge": True, "allow_merge_commit": False},
                },
                "forbid": ["actions.workflows"],
            },
        }
    )
    config = parse_config(
        repo(
            "custom01",
            "octocat/payments",
            access={"teams": [{"name": "payments", "permission": "push"}]},
            rulesets=[{"name": "main", "target": "branch", "ref": "refs/heads/main"}],
            repo_settings={"allow_merge_commit": True, "has_wiki": False},
            codeowners=[{"path": "*", "owners": ["@octocat/payments"]}],
        ),
        {"custom01": definition},
    )
    assert config.kind == "custom01"
    assert config.base == "single-app"
    assert config.provider == "azure"
    assert config.repo_settings == {
        "delete_branch_on_merge": True,
        "allow_merge_commit": True,
        "has_wiki": False,
    }


def test_custom_kind_file_supplies_defaults():
    config = load_config(str(FIXTURES / "custom-repo.yaml"))
    assert config.kind == "custom01"
    assert config.base == "single-app"
    assert config.provider == "azure"
    assert config.repo_settings["delete_branch_on_merge"] is True
    assert config.workflows == []


def test_custom_kind_rejects_a_forbidden_block_and_a_missing_one():
    definition = parse_definition(
        {
            "apiVersion": "litch.dev/v1",
            "kind": "ConfigDefinition",
            "metadata": {"name": "custom01"},
            "spec": {
                "base": "single-app",
                "required": ["codeowners"],
                "defaults": {"secrets": {"provider": "local"}},
                "forbid": ["actions.workflows"],
            },
        }
    )
    with pytest.raises(ConfigError, match="forbids actions.workflows"):
        parse_config(
            repo(
                "custom01",
                secrets={"provider": "local"},
                codeowners=[{"path": "*", "owners": ["@octocat/app"]}],
                actions={"workflows": [{"name": "ci", "template": "ci-node"}]},
            ),
            {"custom01": definition},
        )
    with pytest.raises(ConfigError, match="requires codeowners"):
        parse_config(repo("custom01", secrets={"provider": "local"}), {"custom01": definition})


def test_unknown_kind_and_a_root_without_allow_are_rejected():
    with pytest.raises(ConfigError, match="unknown kind"):
        parse_config(repo("custom99", secrets={"provider": "local"}))
    with pytest.raises(ConfigError, match="allow is required"):
        parse_definition(
            {
                "apiVersion": "litch.dev/v1",
                "kind": "ConfigDefinition",
                "metadata": {"name": "custom02"},
                "spec": {},
            }
        )


def test_a_kind_inherits_required_blocks_from_its_base():
    definition = parse_definition(
        {
            "apiVersion": "litch.dev/v1",
            "kind": "ConfigDefinition",
            "metadata": {"name": "custom02"},
            "spec": {"base": "multi-app", "forbid": ["actions.workflows"]},
        }
    )
    with pytest.raises(ConfigError, match="requires apps"):
        parse_config(repo("custom02", secrets={"provider": "local"}), {"custom02": definition})


def test_a_local_kind_file_replaces_the_packaged_one(tmp_path):
    kinds = tmp_path / "kinds"
    kinds.mkdir()
    (kinds / "single-app.yaml").write_text(
        "apiVersion: litch.dev/v1\nkind: ConfigDefinition\nmetadata:\n  name: single-app\n"
        "spec:\n  allow: [secrets, actions]\n  forbid: [actions.workflows]\n",
        encoding="utf-8",
    )
    config = tmp_path / "repo.yaml"
    config.write_text(
        "apiVersion: litch.dev/v1\nkind: single-app\nrepo: octocat/demo\nspec:\n"
        "  secrets:\n    provider: local\n  actions:\n    workflows:\n"
        "      - name: ci\n        template: ci-node\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="forbids actions.workflows"):
        load_config(str(config))


def test_kind_cycles_are_rejected():
    def kind(name, base):
        return parse_definition(
            {
                "apiVersion": "litch.dev/v1",
                "kind": "ConfigDefinition",
                "metadata": {"name": name},
                "spec": {"base": base},
            }
        )

    with pytest.raises(ConfigError, match="kind cycle"):
        parse_config(
            repo("left", secrets={"provider": "local"}),
            {"left": kind("left", "right"), "right": kind("right", "left")},
        )


def test_cli_rejects_an_unknown_kind(tmp_path, capsys):
    config = tmp_path / "repo.yaml"
    config.write_text(
        "apiVersion: litch.dev/v1\nkind: custom01\nrepo: octocat/demo\nspec:\n  secrets:\n    provider: local\n",
        encoding="utf-8",
    )
    assert main(["plan", "--config", str(config)]) == 2
    assert "unknown kind" in capsys.readouterr().err


def test_cli_loads_a_custom_kind_from_definitions(tmp_path, monkeypatch, capsys):
    kinds = tmp_path / "defs"
    kinds.mkdir()
    (kinds / "custom01.yaml").write_text(
        "apiVersion: litch.dev/v1\nkind: ConfigDefinition\nmetadata:\n  name: custom01\n"
        "spec:\n  base: single-app\n  defaults:\n    secrets:\n      provider: local\n",
        encoding="utf-8",
    )
    config = tmp_path / "repo.yaml"
    config.write_text(
        "apiVersion: litch.dev/v1\nkind: custom01\nrepo: octocat/demo\nspec: {}\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("LITCH_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("litch-github-token", raising=False)
    assert main(["plan", "--config", str(config), "--definitions", str(kinds)]) == 2
    captured = capsys.readouterr()
    assert "litch-github-token" in captured.err
    assert "unknown kind" not in captured.err


def test_local_source_reads_env(monkeypatch):
    monkeypatch.setenv("LITCH_GITHUB_TOKEN", "abc")
    assert open_source("local").get("litch-github-token") == "abc"
    monkeypatch.delenv("LITCH_GITHUB_TOKEN")
    assert open_source("local").get("litch-github-token") is None
    os.environ.pop("LITCH_GITHUB_TOKEN", None)


class _Body:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _http_error(code: int, body: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.test", code, "error", hdrs={}, fp=io.BytesIO(body.encode()))


def _route(monkeypatch, routes):
    def urlopen(request, timeout=30):
        host = urllib.request.urlparse(request.full_url).netloc
        result = routes[host]
        if isinstance(result, Exception):
            raise result
        return _Body(result)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)


def _azure_env(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-id")
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://vault.example")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://oidc.example/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")


def test_missing_oidc_tells_the_caller_to_set_id_token_write(monkeypatch):
    _azure_env(monkeypatch)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    with pytest.raises(SecretError, match="permissions: id-token: write"):
        open_source("azure").get("litch-github-token")


def test_azure_token_exchange_includes_the_provider_error(monkeypatch):
    _azure_env(monkeypatch)
    _route(monkeypatch, {
        "oidc.example": b'{"value":"jwt"}',
        "login.microsoftonline.com": _http_error(
            401,
            '{"error":"invalid_client","error_description":"AADSTS700213: No matching federated identity record"}',
        ),
    })
    with pytest.raises(SecretError, match="AADSTS700213") as caught:
        open_source("azure").get("litch-github-token")
    message = str(caught.value)
    assert "rejected the GitHub OIDC token (401)" in message
    assert "client client-id" in message
    assert "audience api://AzureADTokenExchange" in message


def test_azure_key_vault_rejection_names_the_vault_hop(monkeypatch):
    _azure_env(monkeypatch)
    _route(monkeypatch, {
        "oidc.example": b'{"value":"jwt"}',
        "login.microsoftonline.com": b'{"access_token":"azure-token"}',
        "vault.example": _http_error(403, '{"error":{"code":"Forbidden","message":"Caller is not authorized"}}'),
    })
    with pytest.raises(SecretError, match="key vault rejected litch-github-token \\(403\\): Forbidden: Caller is not authorized"):
        open_source("azure").get("litch-github-token")


def test_aws_sts_rejection_names_the_role(monkeypatch):
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::1:role/litch")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://oidc.example/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
    _route(monkeypatch, {
        "oidc.example": b'{"value":"jwt"}',
        "sts.amazonaws.com": _http_error(
            403,
            "<Error><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error>",
        ),
    })
    with pytest.raises(SecretError, match="for role arn:aws:iam::1:role/litch") as caught:
        open_source("aws").get("DEPLOY_TOKEN")
    assert "AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity" in str(caught.value)


def test_gcp_sts_rejection_names_the_provider(monkeypatch):
    provider = "projects/1/locations/global/workloadIdentityPools/pool/providers/github"
    monkeypatch.setenv("GCP_WORKLOAD_IDENTITY_PROVIDER", provider)
    monkeypatch.setenv("GCP_SERVICE_ACCOUNT", "litch@example.iam.gserviceaccount.com")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://oidc.example/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
    _route(monkeypatch, {
        "oidc.example": b'{"value":"jwt"}',
        "sts.googleapis.com": _http_error(403, '{"error":"unauthorized","error_description":"The audience is not allowed"}'),
    })
    with pytest.raises(SecretError, match="The audience is not allowed") as caught:
        open_source("gcp").get("DEPLOY_TOKEN")
    assert f"for provider {provider}" in str(caught.value)


def test_github_api_error_includes_the_message(monkeypatch):
    def urlopen(request, timeout=30):
        raise _http_error(403, '{"message":"Resource not accessible by integration"}')

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    with pytest.raises(GitHubError, match="github 403 /repos/octocat/demo: Resource not accessible by integration"):
        GitHub("token")._get("/repos/octocat/demo")


def test_cli_prints_the_provider_error_on_one_line(tmp_path, monkeypatch, capsys):
    _azure_env(monkeypatch)
    _route(monkeypatch, {
        "oidc.example": b'{"value":"jwt"}',
        "login.microsoftonline.com": _http_error(
            401,
            '{"error":"invalid_client","error_description":"AADSTS700213: No matching federated identity record"}',
        ),
    })
    config = tmp_path / "repo.yaml"
    config.write_text(
        "apiVersion: litch.dev/v1\nkind: single-app\nrepo: octocat/demo\nspec:\n  secrets:\n    provider: azure\n",
        encoding="utf-8",
    )
    assert main(["plan", "--config", str(config)]) == 2
    error = capsys.readouterr().err.strip().splitlines()
    assert error == [
        "azure: rejected the GitHub OIDC token (401) for client client-id audience api://AzureADTokenExchange: "
        "AADSTS700213: No matching federated identity record"
    ]
