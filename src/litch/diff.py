from dataclasses import dataclass
from pathlib import Path

from litch.model import Config, ConfigError


@dataclass(frozen=True)
class Change:
    action: str
    target: str
    detail: str = ""

    def line(self) -> str:
        mark = {"add": "+", "remove": "-", "update": "~", "missing": "!"}[self.action]
        suffix = f" {self.detail}" if self.detail else ""
        return f"{mark} {self.target}{suffix}"


@dataclass
class Actual:
    users: dict[str, str]
    teams: dict[str, str]
    rulesets: dict[str, dict]
    repo_settings: dict[str, bool]
    variables: dict[str, str]
    secret_names: set[str]
    codeowners: str | None
    workflows: dict[str, str | None]


def render_codeowners(config: Config) -> str:
    lines = [f"{row.path} {' '.join(row.owners)}" for row in config.codeowners]
    return ("\n".join(lines) + "\n") if lines else ""


def template_names(directory: str | None = None) -> set[str]:
    if not directory:
        return set()
    folder = Path(directory)
    if not folder.is_dir():
        raise ConfigError(f"templates not found: {directory}")
    return _template_stems(folder)


def render_workflow(template: str, directory: str | None) -> str:
    if not directory:
        raise ConfigError(f"unknown workflow template: {template}")
    found = _find_template(Path(directory), template)
    if found is None:
        raise ConfigError(f"unknown workflow template: {template}")
    return found.read_text(encoding="utf-8")


def _template_stems(folder: Path) -> set[str]:
    stems: set[str] = set()
    for pattern in ("*.yml", "*.yaml"):
        for file in folder.glob(pattern):
            if file.stem in stems:
                raise ConfigError(f"duplicate template: {file.stem}")
            stems.add(file.stem)
    return stems


def _find_template(folder: Path, template: str) -> Path | None:
    matches = [path for path in (folder / f"{template}.yml", folder / f"{template}.yaml") if path.is_file()]
    if len(matches) > 1:
        raise ConfigError(f"duplicate template: {template}")
    return matches[0] if matches else None


def ruleset_view(rule: object) -> dict:
    from litch.model import RuleSet

    if isinstance(rule, RuleSet):
        return {
            "ref": rule.ref,
            "required_reviews": rule.required_reviews,
            "dismiss_stale": rule.dismiss_stale,
            "status_checks": sorted(rule.status_checks),
            "block_force_push": rule.block_force_push,
        }
    return rule  # type: ignore[return-value]


def diff_config(config: Config, actual: Actual, secret_values: dict[str, str | None]) -> list[Change]:
    changes: list[Change] = []
    _access(changes, "user", {item.name: item.permission for item in config.users}, actual.users)
    _access(changes, "team", {item.name: item.permission for item in config.teams}, actual.teams)
    desired_rules = {rule.name: ruleset_view(rule) for rule in config.rulesets}
    for name, desired in desired_rules.items():
        current = actual.rulesets.get(name)
        if current is None:
            changes.append(Change("add", f"ruleset {name}"))
        elif current != desired:
            changes.append(Change("update", f"ruleset {name}"))
    for key, desired in config.repo_settings.items():
        current = actual.repo_settings.get(key)
        if current != desired:
            changes.append(Change("update", f"repo_settings {key}", f"{current} -> {desired}"))
    for variable in config.variables:
        current = actual.variables.get(variable.name)
        if current is None:
            changes.append(Change("add", f"variable {variable.name}"))
        elif current != variable.value:
            changes.append(Change("update", f"variable {variable.name}"))
    for secret in config.secrets:
        value = secret_values.get(secret.name)
        if secret.required and not value:
            changes.append(Change("missing", f"secret {secret.name}", "missing in vault"))
        elif value and secret.name not in actual.secret_names:
            changes.append(Change("add", f"secret {secret.name}"))
    desired_owners = render_codeowners(config)
    if config.codeowners and (actual.codeowners or "") != desired_owners:
        action = "add" if actual.codeowners is None else "update"
        changes.append(Change(action, "codeowners .github/CODEOWNERS"))
    for workflow in config.workflows:
        desired_workflow = render_workflow(workflow.template, config.template_dir or None)
        current = actual.workflows.get(workflow.path)
        if (current or "") != desired_workflow:
            action = "add" if current is None else "update"
            changes.append(Change(action, f"workflow {workflow.path}"))
    return changes


def _access(changes: list[Change], kind: str, desired: dict[str, str], actual: dict[str, str]) -> None:
    for name, permission in desired.items():
        current = actual.get(name)
        if current is None:
            changes.append(Change("add", f"access.{kind} {name}", permission))
        elif current != permission:
            changes.append(Change("update", f"access.{kind} {name}", f"{current} -> {permission}"))
    for name in actual:
        if name not in desired:
            changes.append(Change("remove", f"access.{kind} {name}"))
