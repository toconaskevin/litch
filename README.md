# Litch

Litch sets a GitHub repository to the state declared in a YAML file: access, rulesets, repository settings, variables, secrets, a CI workflow, and `CODEOWNERS`.

```bash
pip install .
litch plan --config path/to/repo.yaml --templates path/to/templates
litch apply --config path/to/repo.yaml --templates path/to/templates
litch drift --config path/to/repo.yaml --templates path/to/templates
```

Another workflow calls the composite action. `config` is the repository YAML. `kinds` is optional: a file with the same `metadata.name` replaces the packaged kind. `templates` is the directory that holds the app workflows. Litch ships none of them: it copies the file to `.github/workflows/<name>.yml`. The `multi-repository-setup` repository is an example caller, with `configs/`, `kinds/`, and `templates/`.

```yaml
- uses: actions/checkout@v7
- uses: toconaskevin/litch@main
  with:
    command: plan
    config: configs/multi-app.yaml
    kinds: kinds
    templates: templates
```

The job requests `id-token: write` and passes the provider variables in `env`. The GitHub token still comes from the vault.

`plan` prints the diff and writes nothing. `apply` applies it. `drift` exits with code 1 when something declared does not match. A second run against the same state prints `sin cambios`.

Anything absent from the YAML stays untouched, except users and teams under `access`: removing them from the file removes them from the repository on apply.

## Configuration

Every file declares `apiVersion: litch.dev/v1` and a `kind`. The repository and the rest look like this:

```yaml
apiVersion: litch.dev/v1
kind: single-app
repo: octocat/demo
spec:
  secrets:
    provider: azure
```

Every kind, including `single-app` and `multi-app`, is a `ConfigDefinition`. Litch loads them from the package and, when present, from `kinds/` next to the repository YAML or from the `--definitions` directory. A file with the same name replaces the packaged one.

The code accepts the blocks it knows how to write to GitHub: `access`, `rulesets`, `repo_settings`, `secrets`, `actions`, `codeowners`, and `apps`. The kind's `allow` chooses which of them are accepted. When the kind allows `apps`, Litch flattens them the same way for every kind: one `CODEOWNERS` row per path, variables and secrets on the repository, and one workflow per name. `multi-app` allows `apps` and requires it. `custom01` declares `base: single-app`, inherits that `allow`, and adds `required`, `defaults`, and `forbid`.

```yaml
apiVersion: litch.dev/v1
kind: ConfigDefinition
metadata:
  name: custom01
spec:
  base: single-app
  required: [access, rulesets, codeowners]
  defaults:
    repo_settings:
      delete_branch_on_merge: true
  forbid: [actions.workflows]
```

The instance uses `kind: custom01`. Litch merges defaults down the chain (the instance value wins), checks `required` and `forbid`, and applies the blocks that are allowed.

The `secrets` block only names the provider:

```yaml
secrets:
  provider: azure   # azure | aws | gcp
```

The role ARN, service account, vault, and tenant stay out of that block. The operator sets those values in the environment, under the names below. The workflow that calls the action is the same for all three clouds: it requests `id-token: write` and passes those variables.

| Provider | Variables |
| --- | --- |
| `azure` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_KEY_VAULT_URL` |
| `aws` | `AWS_ROLE_ARN`, `AWS_REGION` |
| `gcp` | `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT` |

If one is missing, Litch exits before calling GitHub.

The name in `actions.secrets` is the name in the vault and in GitHub. The API token comes from the vault under the fixed name `litch-github-token` and is not repeated in the YAML. In Azure Key Vault, underscores in the name are read as hyphens (`DEPLOY_TOKEN` looks up `DEPLOY-TOKEN`).

When Litch runs in GitHub Actions, OIDC requests the JWT with an audience fixed in the code: `api://AzureADTokenExchange` for Azure, `sts.amazonaws.com` for AWS, and the value of `GCP_WORKLOAD_IDENTITY_PROVIDER` for GCP. There is no such JWT locally. The `local` provider reads the value from an environment variable of the same name (hyphens become uppercase underscores) and sits outside the portfolio path.

GitHub does not return the value of a secret. If the name already exists, apply does not rewrite it. To rotate it, delete it on the repository and apply again.

## Token permissions

The token stored as `litch-github-token` needs Administration, Contents, Workflows, Secrets, and Variables, read and write, on the repository under test. If the YAML names teams, the repository is in an organization and the token can administer teams as well. Teams and users named in the YAML already exist; Litch does not create accounts.

`access.teams[].name` is the team slug. Rulesets on a private repository require GitHub Team; a public repository works on the free plan.

## Workflows

`actions.workflows[].template` is the name of a file in the `templates` directory, without the extension. Litch writes it to `.github/workflows/<name>.yml` and leaves the contents unchanged. The status check is the one that file declares. If the config names a template that is not in the directory, Litch fails. A kind with no workflows does not need the directory.
