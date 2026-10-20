# Litch

Litch deja un repositorio de GitHub en el estado que declara un YAML: accesos, rulesets, ajustes del repo, variables, secrets, un workflow de CI y `CODEOWNERS`.

```bash
pip install .
litch plan --config path/to/repo.yaml --templates path/to/templates
litch apply --config path/to/repo.yaml --templates path/to/templates
litch drift --config path/to/repo.yaml --templates path/to/templates
```

Desde otro workflow se llama la composite action. `config` es el YAML del repo. `kinds` es opcional: un archivo con el mismo `metadata.name` reemplaza al kind del paquete. `templates` es el directorio con los workflows de la app. Litch no trae ninguno: copia el archivo a `.github/workflows/<name>.yml`. El repo `multi-repository-setup` es un caller de ejemplo con `configs/`, `kinds/` y `templates/`.

```yaml
- uses: actions/checkout@v7
- uses: toconaskevin/litch@main
  with:
    command: plan
    config: configs/multi-app.yaml
    kinds: kinds
    templates: templates
```

El job pide `id-token: write` y pasa las variables del provider en `env`. El token de GitHub sigue saliendo del vault.

`plan` muestra el diff y no escribe. `apply` lo aplica. `drift` sale con código 1 si algo declarado no coincide. Una segunda corrida sobre el mismo estado imprime `sin cambios`.

Lo que no está en el YAML no se toca, salvo los usuarios y equipos de `access`: si se quitan del archivo, el apply los quita del repo.

## Configuración

Cada archivo declara `apiVersion: litch.dev/v1` y un `kind`. El repo y el resto van así:

```yaml
apiVersion: litch.dev/v1
kind: single-app
repo: octocat/demo
spec:
  secrets:
    provider: azure
```

Cada kind, incluidos `single-app` y `multi-app`, es un `ConfigDefinition`. Litch los carga del paquete y, si existe, de `kinds/` junto al YAML del repo o del directorio `--definitions`. Un archivo con el mismo nombre reemplaza al del paquete.

El código acepta los bloques que sabe escribir en GitHub: `access`, `rulesets`, `repo_settings`, `secrets`, `actions`, `codeowners` y `apps`. El `allow` del kind elige cuáles entran. `apps`, cuando el kind lo permite, se aplana igual para todos: una fila de `CODEOWNERS` por path, variables y secrets al repo, y un workflow por nombre. `multi-app` permite `apps` y lo exige. `custom01` declara `base: single-app`, hereda ese `allow`, y suma `required`, `defaults` y `forbid`.

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

La instancia usa `kind: custom01`. Litch mezcla los defaults de la cadena (el valor de la instancia gana), comprueba `required` y `forbid`, y aplica los bloques permitidos.

El bloque `secrets` solo nombra el provider:

```yaml
secrets:
  provider: azure   # azure | aws | gcp
```

No van ahí el role ARN, la service account, el vault ni el tenant. Esos valores los define quien opera Litch, en el entorno, con los nombres de abajo. El workflow que llama a la action es el mismo para las tres nubes: pide `id-token: write` y pasa esas variables.

| Provider | Variables |
| --- | --- |
| `azure` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_KEY_VAULT_URL` |
| `aws` | `AWS_ROLE_ARN`, `AWS_REGION` |
| `gcp` | `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT` |

Si falta una, Litch sale antes de llamar a GitHub.

El nombre de `actions.secrets` es el nombre en el vault y en GitHub. El token de la API sale del vault con el nombre fijo `litch-github-token` y no se repite en el YAML. En Azure Key Vault los guiones bajos del nombre se leen como guiones (`DEPLOY_TOKEN` busca `DEPLOY-TOKEN`).

OIDC, cuando Litch corre en GitHub Actions, pide el JWT con una audiencia fija del código: `api://AzureADTokenExchange` en Azure, `sts.amazonaws.com` en AWS, y el valor de `GCP_WORKLOAD_IDENTITY_PROVIDER` en GCP. En local no hay ese JWT; el provider `local` lee el valor de una variable de entorno con el mismo nombre (los guiones pasan a guiones bajos en mayúsculas) y no forma parte del camino de portfolio.

GitHub no devuelve el valor de un secret. Si el nombre ya existe, apply no lo reescribe. Para rotarlo, se borra en el repo y se vuelve a aplicar.

## Permisos del token

El token guardado como `litch-github-token` necesita, sobre el repo de prueba, Administration, Contents, Workflows, Secrets y Variables en lectura y escritura. Si el YAML nombra equipos, el repo está en una organización y el token también puede administrar equipos. Los equipos y usuarios del YAML ya existen; Litch no crea cuentas.

`access.teams[].name` es el slug del equipo. Los rulesets de un repo privado piden GitHub Team; en un repo público alcanza la cuenta gratuita.

## Workflows

`actions.workflows[].template` es el nombre de un archivo en el directorio `templates`, sin la extensión. Litch lo escribe en `.github/workflows/<name>.yml` sin cambiarle el contenido. El check es el que declara ese archivo. Si el config nombra un template que no está en el directorio, Litch falla. Un kind sin workflows no necesita el directorio.
