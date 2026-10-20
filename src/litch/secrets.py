import json
import os
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree

from litch.model import PROVIDER_ENV, OIDC_AUDIENCE

GITHUB_OIDC_URL = "ACTIONS_ID_TOKEN_REQUEST_URL"
GITHUB_OIDC_TOKEN = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"


class SecretError(RuntimeError):
    pass


class SecretSource:
    def get(self, name: str) -> str | None:
        raise NotImplementedError


def open_source(provider: str) -> SecretSource:
    missing = [key for key in PROVIDER_ENV[provider] if not os.environ.get(key, "").strip()]
    if missing:
        raise SecretError(f"missing environment for provider {provider}: {', '.join(missing)}")
    if provider == "local":
        return LocalSource()
    if provider == "azure":
        return AzureSource()
    if provider == "aws":
        return AwsSource()
    if provider == "gcp":
        return GcpSource()
    raise SecretError(f"unknown provider: {provider}")


def vault_name(provider: str, name: str) -> str:
    if provider == "azure":
        return name.replace("_", "-")
    return name


class LocalSource(SecretSource):
    def get(self, name: str) -> str | None:
        value = os.environ.get(name, "").strip()
        if value:
            return value
        alt = name.replace("-", "_").upper()
        value = os.environ.get(alt, "").strip()
        return value or None


class AzureSource(SecretSource):
    def get(self, name: str) -> str | None:
        token = _azure_token()
        vault = os.environ["AZURE_KEY_VAULT_URL"].rstrip("/")
        secret_id = urllib.parse.quote(vault_name("azure", name), safe="")
        url = f"{vault}/secrets/{secret_id}?api-version=7.4"
        try:
            body = _json(url, headers={"Authorization": f"Bearer {token}"})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            vault_secret = vault_name("azure", name)
            raise _secret_error(f"azure: key vault rejected {vault_secret} ({exc.code})", exc) from None
        value = body.get("value")
        return value if isinstance(value, str) and value else None


class AwsSource(SecretSource):
    def get(self, name: str) -> str | None:
        creds = _aws_credentials()
        region = os.environ["AWS_REGION"]
        url = f"https://secretsmanager.{region}.amazonaws.com/"
        payload = json.dumps({"SecretId": name}).encode()
        headers = _aws_headers(creds, region, payload)
        try:
            body = _json(url, payload, headers)
        except urllib.error.HTTPError as exc:
            raw = _error_body(exc)
            if exc.code == 400 and "ResourceNotFoundException" in raw:
                return None
            raise _secret_error(f"aws: secrets manager rejected {name} ({exc.code})", raw) from None
        value = body.get("SecretString")
        return value if isinstance(value, str) and value else None


class GcpSource(SecretSource):
    def get(self, name: str) -> str | None:
        token = _gcp_token()
        project = _gcp_project()
        secret_id = urllib.parse.quote(name, safe="")
        url = (
            "https://secretmanager.googleapis.com/v1/projects/"
            f"{urllib.parse.quote(project, safe='')}/secrets/{secret_id}/versions/latest:access"
        )
        try:
            body = _json(url, headers={"Authorization": f"Bearer {token}"})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise _secret_error(f"gcp: secret manager rejected {name} ({exc.code})", exc) from None
        data = (body.get("payload") or {}).get("data")
        if not isinstance(data, str) or not data:
            return None
        import base64

        return base64.b64decode(data).decode("utf-8")


def github_oidc_token(audience: str) -> str:
    url = os.environ.get(GITHUB_OIDC_URL, "").strip()
    bearer = os.environ.get(GITHUB_OIDC_TOKEN, "").strip()
    if not url or not bearer:
        raise SecretError("the calling job must set permissions: id-token: write so GitHub can issue an OIDC token")
    joiner = "&" if "?" in url else "?"
    request = urllib.request.Request(
        f"{url}{joiner}audience={urllib.parse.quote(audience, safe='')}",
        headers={"Authorization": f"bearer {bearer}", "Accept": "application/json"},
    )
    try:
        body = _read(request)
    except urllib.error.HTTPError as exc:
        raise _secret_error(f"github: OIDC token request failed ({exc.code})", exc) from None
    token = body.get("value")
    if not isinstance(token, str) or not token:
        raise SecretError("GitHub did not return an OIDC token")
    return token


def _azure_token() -> str:
    assertion = github_oidc_token(OIDC_AUDIENCE["azure"])
    tenant = os.environ["AZURE_TENANT_ID"]
    form = urllib.parse.urlencode(
        {
            "client_id": os.environ["AZURE_CLIENT_ID"],
            "scope": "https://vault.azure.net/.default",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "grant_type": "client_credentials",
        }
    ).encode()
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant, safe='')}/oauth2/v2.0/token"
    audience = OIDC_AUDIENCE["azure"]
    client = os.environ["AZURE_CLIENT_ID"]
    try:
        body = _json(url, form, {"Content-Type": "application/x-www-form-urlencoded"})
    except urllib.error.HTTPError as exc:
        raise _secret_error(
            f"azure: rejected the GitHub OIDC token ({exc.code}) for client {client} audience {audience}",
            exc,
        ) from None
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise SecretError("Azure did not return an access token")
    return token


def _aws_credentials() -> dict[str, str]:
    assertion = github_oidc_token(OIDC_AUDIENCE["aws"])
    form = urllib.parse.urlencode(
        {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": os.environ["AWS_ROLE_ARN"],
            "RoleSessionName": "litch",
            "WebIdentityToken": assertion,
        }
    ).encode()
    request = urllib.request.Request(
        "https://sts.amazonaws.com/",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    role = os.environ["AWS_ROLE_ARN"]
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise _secret_error(
            f"aws: rejected the GitHub OIDC token ({exc.code}) for role {role}",
            exc,
        ) from None
    root = ElementTree.fromstring(payload)
    ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
    creds = root.find(".//s:Credentials", ns)
    if creds is None:
        raise SecretError("aws sts did not return credentials")
    return {
        "access_key": _xml_text(creds, "s:AccessKeyId", ns),
        "secret_key": _xml_text(creds, "s:SecretAccessKey", ns),
        "token": _xml_text(creds, "s:SessionToken", ns),
    }


def _aws_headers(creds: dict[str, str], region: str, payload: bytes) -> dict[str, str]:
    import datetime
    import hashlib
    import hmac

    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    host = f"secretsmanager.{region}.amazonaws.com"
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = (
        "content-type:application/x-amz-json-1.1\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        f"x-amz-security-token:{creds['token']}\n"
        "x-amz-target:secretsmanager.GetSecretValue\n"
    )
    signed = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
    canonical = f"POST\n/\n\n{canonical_headers}\n{signed}\n{payload_hash}"
    scope = f"{date}/{region}/secretsmanager/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = ("AWS4" + creds["secret_key"]).encode()
    for part in (date, region, "secretsmanager", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/x-amz-json-1.1",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Security-Token": creds["token"],
        "X-Amz-Target": "secretsmanager.GetSecretValue",
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            f"Credential={creds['access_key']}/{scope}, "
            f"SignedHeaders={signed}, Signature={signature}"
        ),
    }


def _gcp_token() -> str:
    provider = os.environ["GCP_WORKLOAD_IDENTITY_PROVIDER"]
    assertion = github_oidc_token(provider)
    form = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": f"//iam.googleapis.com/{provider}",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_token": assertion,
        }
    ).encode()
    try:
        exchanged = _json(
            "https://sts.googleapis.com/v1/token",
            form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
    except urllib.error.HTTPError as exc:
        raise _secret_error(
            f"gcp: rejected the GitHub OIDC token ({exc.code}) for provider {provider}",
            exc,
        ) from None
    federated = exchanged.get("access_token")
    if not isinstance(federated, str) or not federated:
        raise SecretError("gcp sts did not return an access token")
    account = os.environ["GCP_SERVICE_ACCOUNT"]
    quoted = urllib.parse.quote(account, safe="")
    try:
        generated = _json(
            f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{quoted}:generateAccessToken",
            json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"]}).encode(),
            {"Authorization": f"Bearer {federated}", "Content-Type": "application/json"},
        )
    except urllib.error.HTTPError as exc:
        raise _secret_error(f"gcp: could not mint a token for {account} ({exc.code})", exc) from None
    token = generated.get("accessToken")
    if not isinstance(token, str) or not token:
        raise SecretError("gcp did not return a service account token")
    return token


def _gcp_project() -> str:
    provider = os.environ["GCP_WORKLOAD_IDENTITY_PROVIDER"]
    parts = provider.split("/")
    if len(parts) < 2 or parts[0] != "projects" or not parts[1]:
        raise SecretError("GCP_WORKLOAD_IDENTITY_PROVIDER must start with projects/<id>/")
    return parts[1]


def _xml_text(node: ElementTree.Element, path: str, ns: dict[str, str]) -> str:
    found = node.find(path, ns)
    if found is None or not found.text:
        raise SecretError("aws sts response is missing credentials")
    return found.text


def _json(url: str, data: bytes | None = None, headers: dict[str, str] | None = None) -> dict:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    return _read(request)


def _read(request: urllib.request.Request) -> dict:
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _error_body(exc: urllib.error.HTTPError) -> str:
    return exc.read().decode("utf-8", errors="replace")


def _secret_error(prefix: str, error: urllib.error.HTTPError | str) -> SecretError:
    raw = error if isinstance(error, str) else _error_body(error)
    detail = _detail_text(raw)
    if len(detail) > 400:
        detail = detail[:400].rstrip() + "..."
    if detail:
        return SecretError(f"{prefix}: {detail}")
    return SecretError(prefix)


def _detail_text(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw[:1] in "{[":
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = None
        if isinstance(body, dict):
            text = _json_detail(body)
            if text:
                return text
    if raw[:1] == "<":
        text = _xml_message(raw)
        if text:
            return text
    return " ".join(raw.split())


def _json_detail(body: dict) -> str:
    error = body.get("error")
    if isinstance(error, dict):
        return _join(_plain(error.get("code")), _plain(error.get("message")))
    description = _plain(body.get("error_description"))
    if description:
        return description
    message = _plain(body.get("message") or body.get("Message"))
    kind = _plain(body.get("__type")).rsplit("#", 1)[-1].rsplit(".", 1)[-1]
    if kind and message:
        return f"{kind}: {message}"
    if message:
        return message
    if isinstance(error, str):
        return _plain(error)
    return ""


def _xml_message(raw: str) -> str:
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return ""
    code = ""
    message = ""
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag == "Code" and node.text and not code:
            code = " ".join(node.text.split())
        elif tag == "Message" and node.text and not message:
            message = " ".join(node.text.split())
    return _join(code, message)


def _plain(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def _join(code: str, message: str) -> str:
    if code and message:
        return f"{code}: {message}"
    return message or code
