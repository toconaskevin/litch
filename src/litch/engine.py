from litch.diff import Change, diff_config, render_codeowners, render_workflow
from litch.github_api import GitHub
from litch.model import Config
from litch.secrets import SecretSource


def collect_values(config: Config, source: SecretSource) -> dict[str, str | None]:
    return {item.name: source.get(item.name) for item in config.secrets}


def plan(config: Config, github: GitHub, values: dict[str, str | None]) -> list[Change]:
    return diff_config(config, github.fetch(config), values)


def apply_changes(config: Config, github: GitHub, changes: list[Change], values: dict[str, str | None]) -> None:
    if any(change.target.startswith("repo_settings ") and change.action == "update" for change in changes):
        github.put_settings(config)
    for change in changes:
        if change.target.startswith("access.user "):
            name = change.target.removeprefix("access.user ")
            if change.action == "remove":
                github.delete_user(config, name)
            elif change.action in {"add", "update"}:
                github.put_user(config, name, _permission(config, "users", name))
        elif change.target.startswith("access.team "):
            name = change.target.removeprefix("access.team ")
            if change.action == "remove":
                github.delete_team(config, name)
            elif change.action in {"add", "update"}:
                github.put_team(config, name, _permission(config, "teams", name))
        elif change.target.startswith("ruleset ") and change.action in {"add", "update"}:
            github.put_ruleset(config, change.target.removeprefix("ruleset "))
        elif change.target.startswith("variable ") and change.action in {"add", "update"}:
            name = change.target.removeprefix("variable ")
            value = next(item.value for item in config.variables if item.name == name)
            github.put_variable(config, name, value)
        elif change.target.startswith("secret ") and change.action == "add":
            name = change.target.removeprefix("secret ")
            github.put_secret(config, name, values[name] or "")
        elif change.target == "codeowners .github/CODEOWNERS" and change.action in {"add", "update"}:
            github.put_text_file(config, ".github/CODEOWNERS", render_codeowners(config), "Apply CODEOWNERS from Litch")
        elif change.target.startswith("workflow ") and change.action in {"add", "update"}:
            path = change.target.removeprefix("workflow ")
            workflow = next(item for item in config.workflows if item.path == path)
            github.put_text_file(
                config,
                path,
                render_workflow(workflow.template, config.template_dir or None),
                f"Apply {workflow.name} workflow from Litch",
            )


def _permission(config: Config, kind: str, name: str) -> str:
    entries = config.users if kind == "users" else config.teams
    return next(item.permission for item in entries if item.name == name)
