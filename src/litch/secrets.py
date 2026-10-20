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
            raise SecretError(f"azure key vault returned {exc.code} for {vault_name('azure', name)}") from None
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
            if exc.code == 400:
                detail = exc.read().decode("utf-8", errors="replace")
                if "ResourceNotFoundException" in detail:
                    return None
            raise SecretError(f"aws secrets manager returned {exc.code}") from None
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
            raise SecretError(f"gcp secret manager returned {exc.code}") from None
        data = (body.get("payload") or {}).get("data")
        if not isinstance(data, str) or not data:
            return None
        import base64

        return base64.b64decode(data).decode("utf-8")


def github_oidc_token(audience: str) -> str:
    url = os.environ.get(GITHUB_OIDC_URL, "").strip()
    bearer = os.environ.get(GITHUB_OIDC_TOKEN, "").strip()
    if not url or not bearer:
        raise SecretError("OIDC is available when Litch runs in GitHub Actions (id-token: write)")
    joiner = "&" if "?" in url else "?"
    request = urllib.request.Request(
        f"{url}{joiner}audience={urllib.parse.quote(audience, safe='')}",
        headers={"Authorization": f"bearer {bearer}", "Accept": "application/json"},
    )
    body = _read(request)
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
    body = _json(url, form, {"Content-Type": "application/x-www-form-urlencoded"})
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
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise SecretError(f"aws sts returned {exc.code}") from None
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
    exchanged = _json(
        "https://sts.googleapis.com/v1/token",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    federated = exchanged.get("access_token")
    if not isinstance(federated, str) or not federated:
        raise SecretError("gcp sts did not return an access token")
    account = urllib.parse.quote(os.environ["GCP_SERVICE_ACCOUNT"], safe="")
    generated = _json(
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{account}:generateAccessToken",
        json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"]}).encode(),
        {"Authorization": f"Bearer {federated}", "Content-Type": "application/json"},
    )
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
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError:
        raise
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))
