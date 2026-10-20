import copy
import re
from pathlib import Path

import yaml

from litch.diff import template_names
from litch.model import (
    API_VERSION,
    BLOCKS,
    PERMISSIONS,
    PROVIDERS,
    SPEC_KEYS,
    AccessEntry,
    App,
    CodeOwner,
    Config,
    ConfigError,
    KindDef,
    RuleSet,
    SecretRef,
    Variable,
    WorkflowRef,
)

SETTING_KEYS = (
    "allow_squash_merge",
    "allow_merge_commit",
    "allow_rebase_merge",
    "delete_branch_on_merge",
    "has_wiki",
    "has_issues",
)
_SLUG = re.compile(r"^[a-z][a-z0-9-]*$")


def load_config(path: str, definitions: str | None = None, templates: str | None = None) -> Config:
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"config not found: {path}")
    data = _read_yaml(file)
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    return parse_config(data, _user_kinds(file, definitions), templates)


def parse_definition(data: dict) -> KindDef:
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    _version(data)
    if _text(data.get("kind"), "kind") != "ConfigDefinition":
        raise ConfigError("kind must be ConfigDefinition")
    _known(data, {"apiVersion", "kind", "metadata", "spec"}, "field")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        raise ConfigError("metadata must be a mapping")
    _known(metadata, {"name"}, "metadata field")
    name = _slug(metadata.get("name"), "metadata.name")
    spec = data.get("spec")
    if not isinstance(spec, dict):
        raise ConfigError("spec must be a mapping")
    _known(spec, {"allow", "base", "required", "defaults", "forbid"}, "spec field")
    base = _slug(spec.get("base"), "spec.base") if spec.get("base") else ""
    allow = _names(spec.get("allow") or [], "spec.allow", SPEC_KEYS)
    required = _names(spec.get("required") or [], "spec.required", BLOCKS)
    forbid = _names(spec.get("forbid") or [], "spec.forbid", BLOCKS)
    if not base and not allow:
        raise ConfigError("allow is required")
    overlap = set(required) & set(forbid)
    if overlap:
        raise ConfigError(f"a block cannot be required and forbidden: {', '.join(sorted(overlap))}")
    defaults = spec.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ConfigError("spec.defaults must be a mapping")
    return KindDef(name, tuple(allow), tuple(required), defaults, tuple(forbid), base)


def parse_config(data: dict, definitions: dict[str, KindDef] | None = None, templates: str | None = None) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    _version(data)
    _known(data, {"apiVersion", "kind", "repo", "spec"}, "field")
    kind = _text(data.get("kind"), "kind")
    if kind == "ConfigDefinition":
        raise ConfigError("ConfigDefinition declares a kind; it is not a repo config")
    repo = _text(data.get("repo"), "repo")
    owner, _, name = repo.partition("/")
    if not owner or not name or "/" in name:
        raise ConfigError("repo must be owner/name")
    spec = data.get("spec") if "spec" in data else {}
    if not isinstance(spec, dict):
        raise ConfigError("spec must be a mapping")
    catalog = _resolve_all({**_packaged_raw(), **(definitions or {})})
    if kind not in catalog:
        raise ConfigError(f"unknown kind: {kind}")
    definition = catalog[kind]
    merged = _merge(definition.defaults, spec)
    _enforce(kind, merged, definition)
    unknown = set(merged) - set(definition.allow)
    if unknown:
        raise ConfigError(f"unknown spec field: {', '.join(sorted(unknown))}")
    return _build(repo, kind, _root(definition, catalog), merged, definition.allow, template_names(templates), templates or "")


def _user_kinds(config_path: Path, directory: str | None) -> dict[str, KindDef]:
    if directory is None:
        folder = config_path.resolve().parent / "kinds"
        if not folder.is_dir():
            return {}
    else:
        folder = Path(directory)
        if not folder.is_dir():
            raise ConfigError(f"definitions not found: {directory}")
    return _read_kind_dir(folder)


def _packaged_raw() -> dict[str, KindDef]:
    folder = Path(__file__).resolve().parent / "kinds"
    if not folder.is_dir():
        raise ConfigError(f"packaged kinds not found: {folder}")
    return _read_kind_dir(folder)


def _read_kind_dir(folder: Path) -> dict[str, KindDef]:
    found: dict[str, KindDef] = {}
    files = sorted({*folder.glob("*.yaml"), *folder.glob("*.yml")})
    for file in files:
        data = _read_yaml(file)
        if not isinstance(data, dict):
            raise ConfigError(f"{file.name}: config must be a mapping")
        try:
            definition = parse_definition(data)
        except ConfigError as exc:
            raise ConfigError(f"{file.name}: {exc}") from None
        if definition.name in found:
            raise ConfigError(f"duplicate kind: {definition.name}")
        found[definition.name] = definition
    return found


def _resolve_all(raw: dict[str, KindDef]) -> dict[str, KindDef]:
    resolved: dict[str, KindDef] = {}
    for name in raw:
        _resolve(name, raw, resolved, [])
    return resolved


def _resolve(name: str, raw: dict[str, KindDef], resolved: dict[str, KindDef], stack: list[str]) -> KindDef:
    if name in resolved:
        return resolved[name]
    if name not in raw:
        raise ConfigError(f"unknown kind: {name}")
    if name in stack:
        raise ConfigError(f"kind cycle: {' -> '.join((*stack, name))}")
    item = raw[name]
    if item.base:
        parent = _resolve(item.base, raw, resolved, [*stack, name])
        allow = item.allow or parent.allow
        defaults = _merge(parent.defaults, item.defaults)
        required = _union(parent.required, item.required)
        forbid = _union(parent.forbid, item.forbid)
    else:
        if not item.allow:
            raise ConfigError(f"{item.name} requires allow")
        allow, defaults, required, forbid = item.allow, item.defaults, item.required, item.forbid
    _check_policy(item.name, allow, required, forbid, defaults)
    done = KindDef(item.name, allow, required, defaults, forbid, item.base)
    resolved[name] = done
    return done


def _root(definition: KindDef, catalog: dict[str, KindDef]) -> str:
    seen: set[str] = set()
    current = definition
    while current.base:
        if current.name in seen:
            raise ConfigError(f"kind cycle: {current.name}")
        seen.add(current.name)
        current = catalog[current.base]
    return current.name


def _check_policy(name: str, allow: tuple[str, ...], required: tuple[str, ...], forbid: tuple[str, ...], defaults: dict) -> None:
    for path in (*required, *forbid):
        if path.split(".", 1)[0] not in allow:
            raise ConfigError(f"unknown block for {name}: {path}")
    overlap = set(required) & set(forbid)
    if overlap:
        raise ConfigError(f"a block cannot be required and forbidden: {', '.join(sorted(overlap))}")
    unknown = set(defaults) - set(allow)
    if unknown:
        raise ConfigError(f"unknown default: {', '.join(sorted(unknown))}")


def _union(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*left, *right)))


def _build(repo: str, kind: str, base: str, spec: dict, allow: tuple[str, ...], templates: set[str], template_dir: str) -> Config:
    secrets = spec.get("secrets") or {}
    if not isinstance(secrets, dict):
        raise ConfigError("secrets must be a mapping")
    provider = _text(secrets.get("provider"), "secrets.provider")
    if provider not in PROVIDERS:
        raise ConfigError(f"secrets.provider must be one of: {', '.join(PROVIDERS)}")
    if set(secrets) - {"provider"}:
        raise ConfigError("secrets only accepts provider; cloud identifiers belong in the environment")

    access = spec.get("access") or {}
    if not isinstance(access, dict):
        raise ConfigError("access must be a mapping")
    _known(access, {"teams", "users"}, "access field")

    actions = spec.get("actions") or {}
    if not isinstance(actions, dict):
        raise ConfigError("actions must be a mapping")
    _known(actions, {"variables", "secrets", "workflows"}, "actions field")

    apps = _apps(spec.get("apps") or [], templates) if "apps" in allow else []
    owners = _codeowners(spec.get("codeowners") or [])
    variables = _variables(actions.get("variables") or [])
    secret_refs = _secrets(actions.get("secrets") or [])
    workflows = _workflows(actions.get("workflows") or [], templates)
    owners, variables, secret_refs, workflows = _flatten(owners, variables, secret_refs, workflows, apps)
    return Config(
        repo=repo,
        provider=provider,
        kind=kind,
        base=base,
        teams=_access(access.get("teams") or [], "access.teams"),
        users=_access(access.get("users") or [], "access.users"),
        rulesets=_rulesets(spec.get("rulesets") or []),
        repo_settings=_settings(spec.get("repo_settings") or {}),
        variables=variables,
        secrets=secret_refs,
        workflows=workflows,
        codeowners=owners,
        apps=apps,
        template_dir=template_dir,
    )


def _enforce(kind: str, spec: dict, definition: KindDef) -> None:
    for path in definition.required:
        if not _present(spec, path):
            raise ConfigError(f"{kind} requires {path}")
    for path in definition.forbid:
        if _present(spec, path):
            raise ConfigError(f"{kind} forbids {path}")


def _present(spec: dict, path: str) -> bool:
    if path.startswith("apps."):
        apps = spec.get("apps")
        field = path.split(".", 1)[1]
        if not isinstance(apps, list) or not apps:
            return False
        return all(isinstance(app, dict) and _nonempty(app.get(field)) for app in apps)
    return _nonempty(_dig(spec, path))


def _dig(spec: dict, path: str):
    current: object = spec
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _nonempty(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return value is not None


def _merge(default: dict, override: dict) -> dict:
    return _merge_values(copy.deepcopy(default), override)


def _merge_values(base, override):
    if isinstance(base, dict) and isinstance(override, dict):
        merged = {}
        for key in list(base) + [key for key in override if key not in base]:
            if key in base and key in override:
                merged[key] = _merge_values(base[key], override[key])
            elif key in override:
                merged[key] = override[key]
            else:
                merged[key] = base[key]
        return merged
    return override


def _apps(items: object, templates: set[str]) -> list[App]:
    apps = []
    seen: set[str] = set()
    for item in _list(items, "apps"):
        _known(item, {"name", "path", "codeowners", "variables", "secrets", "workflows"}, "apps field")
        name = _slug(item.get("name"), "apps.name")
        if name in seen:
            raise ConfigError(f"duplicate app: {name}")
        seen.add(name)
        path = _text(item.get("path"), "apps.path")
        if any(char.isspace() for char in path):
            raise ConfigError("apps.path must not contain whitespace")
        apps.append(
            App(
                name,
                path,
                _owner_list(item.get("codeowners") or [], "apps.codeowners"),
                tuple(_variables(item.get("variables") or [], "apps.variables")),
                tuple(_secrets(item.get("secrets") or [], "apps.secrets")),
                tuple(_workflows(item.get("workflows") or [], templates, "apps.workflows")),
            )
        )
    return apps


def _flatten(owners, variables, secrets, workflows, apps: list[App]):
    seen_paths = {row.path for row in owners}
    seen_variables = {item.name for item in variables}
    seen_secrets = {item.name for item in secrets}
    seen_workflows = {item.name for item in workflows}
    for app in apps:
        if app.path in seen_paths:
            raise ConfigError(f"duplicate codeowners path: {app.path}")
        seen_paths.add(app.path)
        if app.owners:
            owners.append(CodeOwner(app.path, app.owners))
        for variable in app.variables:
            if variable.name in seen_variables:
                raise ConfigError(f"duplicate variable: {variable.name}")
            seen_variables.add(variable.name)
            variables.append(variable)
        for secret in app.secrets:
            if secret.name in seen_secrets:
                raise ConfigError(f"duplicate secret: {secret.name}")
            seen_secrets.add(secret.name)
            secrets.append(secret)
        for workflow in app.workflows:
            if workflow.name in seen_workflows:
                raise ConfigError(f"duplicate workflow: {workflow.name}")
            seen_workflows.add(workflow.name)
            workflows.append(workflow)
    return owners, variables, secrets, workflows


def _access(items: object, label: str) -> list[AccessEntry]:
    entries = []
    seen: set[str] = set()
    for item in _list(items, label):
        _known(item, {"name", "permission"}, f"{label} field")
        name = _text(item.get("name"), f"{label}.name")
        if name in seen:
            raise ConfigError(f"duplicate {label}: {name}")
        seen.add(name)
        permission = _text(item.get("permission"), f"{label}.permission")
        if permission not in PERMISSIONS:
            raise ConfigError(f"{label} permission must be one of: {', '.join(PERMISSIONS)}")
        entries.append(AccessEntry(name, permission))
    return entries


def _rulesets(items: object) -> list[RuleSet]:
    rules = []
    seen: set[str] = set()
    for item in _list(items, "rulesets"):
        _known(item, {"name", "target", "ref", "pull_request", "status_checks", "block_force_push"}, "rulesets field")
        pull = item.get("pull_request") or {}
        if not isinstance(pull, dict):
            raise ConfigError("rulesets.pull_request must be a mapping")
        _known(pull, {"required_reviews", "dismiss_stale"}, "rulesets.pull_request field")
        checks = item.get("status_checks") or []
        if not isinstance(checks, list) or not all(isinstance(check, str) and check for check in checks):
            raise ConfigError("rulesets.status_checks must be a list of names")
        target = _text(item.get("target"), "rulesets.target")
        if target != "branch":
            raise ConfigError("rulesets.target must be branch")
        ref = _text(item.get("ref"), "rulesets.ref")
        if not ref.startswith("refs/heads/"):
            raise ConfigError("rulesets.ref must start with refs/heads/")
        reviews = pull.get("required_reviews", 0)
        if not isinstance(reviews, int) or isinstance(reviews, bool) or reviews < 0:
            raise ConfigError("rulesets.pull_request.required_reviews must be zero or greater")
        rule_name = _text(item.get("name"), "rulesets.name")
        if rule_name in seen:
            raise ConfigError(f"duplicate ruleset: {rule_name}")
        seen.add(rule_name)
        rules.append(
            RuleSet(
                name=rule_name,
                target=target,
                ref=ref,
                required_reviews=reviews,
                dismiss_stale=bool(pull.get("dismiss_stale", False)),
                status_checks=tuple(checks),
                block_force_push=bool(item.get("block_force_push", False)),
            )
        )
    return rules


def _settings(raw: object) -> dict[str, bool]:
    if not isinstance(raw, dict):
        raise ConfigError("repo_settings must be a mapping")
    unknown = set(raw) - set(SETTING_KEYS)
    if unknown:
        raise ConfigError(f"unknown repo_settings: {', '.join(sorted(unknown))}")
    settings = {}
    for key, value in raw.items():
        if not isinstance(value, bool):
            raise ConfigError(f"repo_settings.{key} must be true or false")
        settings[key] = value
    return settings


def _variables(items: object, label: str = "actions.variables") -> list[Variable]:
    variables = []
    seen: set[str] = set()
    for item in _list(items, label):
        _known(item, {"name", "value"}, f"{label} field")
        name = _text(item.get("name"), f"{label}.name")
        if name in seen:
            raise ConfigError(f"duplicate variable: {name}")
        seen.add(name)
        variables.append(Variable(name, _text(item.get("value"), f"{label}.value")))
    return variables


def _secrets(items: object, label: str = "actions.secrets") -> list[SecretRef]:
    secrets = []
    seen: set[str] = set()
    for item in _list(items, label):
        _known(item, {"name", "required"}, f"{label} field")
        name = _text(item.get("name"), f"{label}.name")
        if name in seen:
            raise ConfigError(f"duplicate secret: {name}")
        seen.add(name)
        secrets.append(SecretRef(name, bool(item.get("required", False))))
    return secrets


def _workflows(items: object, templates: set[str], label: str = "actions.workflows") -> list[WorkflowRef]:
    workflows = []
    seen: set[str] = set()
    for item in _list(items, label):
        _known(item, {"name", "template"}, f"{label} field")
        template = _text(item.get("template"), f"{label}.template")
        if template not in templates:
            raise ConfigError(f"unknown workflow template: {template}")
        name = _slug(item.get("name"), f"{label}.name")
        if name in seen:
            raise ConfigError(f"duplicate workflow: {name}")
        seen.add(name)
        workflows.append(WorkflowRef(name, template, f".github/workflows/{name}.yml"))
    return workflows


def _codeowners(items: object) -> list[CodeOwner]:
    rows = []
    seen: set[str] = set()
    for item in _list(items, "codeowners"):
        _known(item, {"path", "owners"}, "codeowners field")
        path = _text(item.get("path"), "codeowners.path")
        if any(char.isspace() for char in path):
            raise ConfigError("codeowners.path must not contain whitespace")
        if path in seen:
            raise ConfigError(f"duplicate codeowners path: {path}")
        seen.add(path)
        owners = item.get("owners")
        if not isinstance(owners, list) or not owners:
            raise ConfigError("codeowners.owners must be a non-empty list")
        rows.append(CodeOwner(path, _owner_list(owners, "codeowners.owners")))
    return rows


def _owner_list(items: object, label: str) -> tuple[str, ...]:
    if not isinstance(items, list):
        raise ConfigError(f"{label} must be a list")
    owners = []
    for owner in items:
        text = _text(owner, label)
        if not text.startswith("@"):
            raise ConfigError("codeowners owners must start with @")
        owners.append(text)
    return tuple(owners)


def _names(items: object, label: str, known: frozenset[str]) -> list[str]:
    if not isinstance(items, list):
        raise ConfigError(f"{label} must be a list")
    names = []
    for item in items:
        name = _text(item, label)
        if name not in known:
            raise ConfigError(f"unknown block: {name}")
        if name in names:
            raise ConfigError(f"duplicate block: {name}")
        names.append(name)
    return names


def _version(data: dict) -> None:
    version = _text(data.get("apiVersion"), "apiVersion")
    if version != API_VERSION:
        raise ConfigError(f"apiVersion must be {API_VERSION}")


def _known(mapping: dict, allowed: set[str], label: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise ConfigError(f"unknown {label}: {', '.join(sorted(unknown))}")


def _list(items: object, label: str) -> list[dict]:
    if not isinstance(items, list):
        raise ConfigError(f"{label} must be a list")
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError(f"{label} entries must be mappings")
    return items


def _slug(value: object, label: str) -> str:
    text = _text(value, label)
    if not _SLUG.match(text):
        raise ConfigError(f"{label} must be a lowercase slug")
    return text


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} is required")
    return value.strip()


def _read_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid yaml: {path}") from exc
