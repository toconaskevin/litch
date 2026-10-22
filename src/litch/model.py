from dataclasses import dataclass, field

PERMISSIONS = ("pull", "triage", "push", "maintain", "admin")
PROVIDERS = ("azure", "aws", "gcp", "local")
GITHUB_APP_CLIENT_ID = "litch-github-app-client-id"
GITHUB_APP_ID = "litch-github-app-id"
GITHUB_APP_INSTALLATION_ID = "litch-github-app-installation-id"
GITHUB_APP_PEM = "litch-github-app-pem"
GITHUB_APP_SECRETS = (
    GITHUB_APP_CLIENT_ID,
    GITHUB_APP_ID,
    GITHUB_APP_INSTALLATION_ID,
    GITHUB_APP_PEM,
)
API_VERSION = "litch.dev/v1"
SPEC_KEYS = frozenset({
    "access",
    "rulesets",
    "repo_settings",
    "secrets",
    "actions",
    "codeowners",
    "apps",
})
BLOCKS = SPEC_KEYS | frozenset({
    "access.teams",
    "access.users",
    "actions.variables",
    "actions.secrets",
    "actions.workflows",
    "apps.codeowners",
    "apps.variables",
    "apps.secrets",
    "apps.workflows",
})

PROVIDER_ENV = {
    "azure": ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_KEY_VAULT_URL"),
    "aws": ("AWS_ROLE_ARN", "AWS_REGION"),
    "gcp": ("GCP_WORKLOAD_IDENTITY_PROVIDER", "GCP_SERVICE_ACCOUNT"),
    "local": (),
}

OIDC_AUDIENCE = {
    "azure": "api://AzureADTokenExchange",
    "aws": "sts.amazonaws.com",
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AccessEntry:
    name: str
    permission: str


@dataclass(frozen=True)
class RuleSet:
    name: str
    target: str
    ref: str
    required_reviews: int
    dismiss_stale: bool
    status_checks: tuple[str, ...]
    block_force_push: bool


@dataclass(frozen=True)
class Variable:
    name: str
    value: str


@dataclass(frozen=True)
class SecretRef:
    name: str
    required: bool


@dataclass(frozen=True)
class WorkflowRef:
    name: str
    template: str
    path: str


@dataclass(frozen=True)
class CodeOwner:
    path: str
    owners: tuple[str, ...]


@dataclass(frozen=True)
class App:
    name: str
    path: str
    owners: tuple[str, ...]
    variables: tuple[Variable, ...] = ()
    secrets: tuple[SecretRef, ...] = ()
    workflows: tuple[WorkflowRef, ...] = ()


@dataclass(frozen=True)
class KindDef:
    name: str
    allow: tuple[str, ...]
    required: tuple[str, ...]
    defaults: dict
    forbid: tuple[str, ...]
    base: str = ""


@dataclass
class Config:
    repo: str
    provider: str
    kind: str
    base: str
    teams: list[AccessEntry] = field(default_factory=list)
    users: list[AccessEntry] = field(default_factory=list)
    rulesets: list[RuleSet] = field(default_factory=list)
    repo_settings: dict[str, bool] = field(default_factory=dict)
    variables: list[Variable] = field(default_factory=list)
    secrets: list[SecretRef] = field(default_factory=list)
    workflows: list[WorkflowRef] = field(default_factory=list)
    codeowners: list[CodeOwner] = field(default_factory=list)
    apps: list[App] = field(default_factory=list)
    template_dir: str = ""

    @property
    def owner(self) -> str:
        return self.repo.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.repo.split("/", 1)[1]
