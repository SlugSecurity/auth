import fcntl
import http.client
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import TypedDict

from contracts import JSONObject, is_object_dict, json_object, json_string, native_attrs

DOMAIN: str = "auth.slugsec.club"
URL: str = "https://auth.slugsec.club"
PORTAL_URL: str = "https://my.slugsec.club"
ROOT = Path(__file__).resolve().parents[1]


class RuntimeConfig(TypedDict):
    version: str
    domain: str
    origin: str
    portal_origin: str
    state_dir: str
    observe_dir: str
    operator_credentials: str
    operator_session: str
    trusted_proxy: str


def load_config(path: str | Path) -> RuntimeConfig:
    raw: object = json.loads(Path(path).read_text())
    required = {
        "version",
        "domain",
        "origin",
        "portal_origin",
        "state_dir",
        "observe_dir",
        "operator_credentials",
        "operator_session",
        "trusted_proxy",
    }

    if not is_object_dict(raw) or set(raw) != required:
        raise RuntimeError("Production runtime configuration fields are incomplete")

    if not all(isinstance(item, str) for item in raw.values()):
        raise RuntimeError("Production runtime configuration values must be strings")

    value: RuntimeConfig = {
        "version": json_string(raw["version"]),
        "domain": json_string(raw["domain"]),
        "origin": json_string(raw["origin"]),
        "portal_origin": json_string(raw["portal_origin"]),
        "state_dir": json_string(raw["state_dir"]),
        "observe_dir": json_string(raw["observe_dir"]),
        "operator_credentials": json_string(raw["operator_credentials"]),
        "operator_session": json_string(raw["operator_session"]),
        "trusted_proxy": json_string(raw["trusted_proxy"]),
    }

    if (
        value["version"] != "1.11.2"
        or value["domain"] != DOMAIN
        or value["origin"] != URL
        or value["portal_origin"] != PORTAL_URL
        or value["trusted_proxy"] != ""
    ):
        raise RuntimeError(
            "Production version, origins or proxy trust do not match this deployment"
        )

    for name in (
        "state_dir",
        "observe_dir",
        "operator_credentials",
        "operator_session",
    ):
        item = value[name]

        if not item.startswith("/"):
            raise RuntimeError("Production runtime paths must be absolute")

        candidate = Path(item)

        if ".." in candidate.parts or candidate == ROOT or ROOT in candidate.parents:
            raise RuntimeError(
                "Keep runtime secrets and persistent data outside the checkout"
            )

    state, observations = Path(value["state_dir"]), Path(value["observe_dir"])

    if (
        state == observations
        or state in observations.parents
        or observations in state.parents
    ):
        raise RuntimeError(
            "Portal state must be separate from readonly Kanidm observations"
        )

    for key in ("operator_credentials", "operator_session"):
        if Path(value[key]) == state or state in Path(value[key]).parents:
            raise RuntimeError(
                "Operator credentials and sessions must stay outside portal state"
            )

    return value


CONFIG = load_config(
    os.environ.get("IDENTITY_RUNTIME_CONFIG", "/run/identity/runtime.json")
)
STATE = Path(CONFIG["state_dir"])
DATA = Path(CONFIG["observe_dir"])
CREDENTIALS = STATE / "credentials.json"
OPERATOR_CREDENTIALS = Path(CONFIG["operator_credentials"])
OPERATOR_SESSION = Path(CONFIG["operator_session"])
POSIX_STATUS = DATA / "posix" / "status.json"
BACKUP_STATUS = DATA / "backup" / "status.json"
ISOLATED_POSIX = os.environ.get("IDENTITY_PROCESS_ROLE") == "posix"
PUBLIC_READINESS = os.environ.get("IDENTITY_PROCESS_ROLE") == "portal"


def _ownership(path: str | Path) -> tuple[int, int, int, int]:
    path = Path(path)

    if not path.is_absolute() or ".." in path.parts or path.resolve() != path:
        raise RuntimeError(
            "Private write paths must not follow symlinks or parent traversal"
        )

    if (
        path in {POSIX_STATUS, POSIX_STATUS.parent}
        or POSIX_STATUS.parent in path.parents
    ):
        return 10004, 10002, 0o640, 0o750

    if path == STATE / "posix-defaults" or STATE / "posix-defaults" in path.parents:
        return 10004, 10004, 0o600, 0o700

    if path == STATE or STATE in path.parents:
        return 10002, 10002, 0o600, 0o700

    raise RuntimeError(
        "Private writes must stay inside their assigned service directory"
    )


def prepare_private_directory(path: Path) -> None:
    uid, gid, _, mode = _ownership(path)
    service_root = POSIX_STATUS.parent if path.is_relative_to(DATA) else STATE
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    current = Path("/")

    try:
        for part in path.parts[1:]:
            current /= part
            created = False

            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                with suppress(FileExistsError):
                    os.mkdir(
                        part,
                        mode=mode if current.is_relative_to(service_root) else 0o777,
                        dir_fd=descriptor,
                    )
                    created = True

                child = os.open(part, flags, dir_fd=descriptor)

            os.close(descriptor)
            descriptor = child

            if created and current != path and current.is_relative_to(service_root):
                parent_uid, parent_gid, _, parent_mode = _ownership(current)

                if os.geteuid() == 0:
                    os.fchown(descriptor, parent_uid, parent_gid)

                os.fchmod(descriptor, parent_mode)

        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)

        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def protect_private_file(descriptor: int, path: Path) -> None:
    uid, gid, mode, _ = _ownership(path)

    if os.geteuid() == 0:
        os.fchown(descriptor, uid, gid)
    else:
        os.fchown(descriptor, -1, gid)

    os.fchmod(descriptor, mode)


def command(
    *args: str,
    check: bool = True,
    env: Mapping[str, str] | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )

    if check and result.returncode:
        raise RuntimeError(
            f"{args[0]} {' '.join(args[1:3])} failed (exit {result.returncode})"
        )

    return result


def _private_json(path: Path) -> JSONObject:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode) or status.st_mode & 0o077:
            raise ValueError(
                "Private JSON must be a regular file with private permissions"
            )

        with os.fdopen(descriptor, closefd=False) as stream:
            return json_object(json.load(stream))
    finally:
        os.close(descriptor)


def load_credentials() -> JSONObject:
    return _private_json(CREDENTIALS)


def update_credentials(update: Callable[[JSONObject], None]) -> JSONObject:
    prepare_private_directory(STATE)
    lock_path = STATE / "credentials.lock"
    lock_fd = os.open(
        lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )

    with os.fdopen(lock_fd, "a") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("Credential locks must be regular files")

        protect_private_file(lock.fileno(), STATE / "credentials.lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        current: JSONObject = (
            load_credentials()
            if CREDENTIALS.exists()
            else {
                "url": URL,
                "ca_path": str(DATA / "ca.pem"),
                "accounts": {},
            }
        )
        update(current)

        with tempfile.NamedTemporaryFile(mode="w", dir=STATE, delete=False) as stream:
            temporary = Path(stream.name)

            try:
                protect_private_file(stream.fileno(), CREDENTIALS)
                json.dump(current, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
                temporary.replace(CREDENTIALS)
                directory_fd = os.open(
                    STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )

                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                temporary.unlink(missing_ok=True)

        return current


def cli_env(
    name: str, *, interactive: bool = False, bootstrap_password: bool = False
) -> dict[str, str]:
    if name not in ("admin", "idm_admin") or not OPERATOR_SESSION.is_dir():
        raise RuntimeError("This operation requires the separate operator container")

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("KANIDM_")
        and key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
    }
    environment.update(
        HOME=str(OPERATOR_SESSION),  # cli needs a home cache despite the token path
        KANIDM_URL=URL,
        KANIDM_CA_PATH=str(DATA / "ca.pem"),
        KANIDM_NAME=name,
        KANIDM_TOKEN_CACHE_PATH=str(OPERATOR_SESSION / "tokens.json"),
        KANIDM_INSTANCE="identity-production",
        NO_PROXY="*",
    )

    if (
        bootstrap_password
        and not interactive
        and os.environ.get("IDENTITY_BOOTSTRAP_PASSWORD") == "1"
    ):
        credential = _private_json(OPERATOR_CREDENTIALS)
        accounts = json_object(credential.get("accounts", {}))

        if credential.get("url") != URL or set(accounts) != {
            "admin",
            "idm_admin",
        }:
            raise RuntimeError(
                "Operator credentials must belong to this production origin"
            )

        password = accounts[name]

        if (
            not isinstance(password, str)
            or not password
            or password.startswith(("CHANGE", "REPLACE"))
        ):
            raise RuntimeError(
                "Provision operator credentials privately before bootstrap"
            )

        environment["KANIDM_PASSWORD"] = password

    return environment


def operator_token(name: str = "idm_admin") -> str:
    environment = cli_env(name)
    cache = Path(environment["KANIDM_TOKEN_CACHE_PATH"])

    try:
        saved = _private_json(cache)
        instances = json_object(saved["instances"])
        instance = json_object(instances["identity-production"])
        tokens = json_object(instance["tokens"])

        if not set(tokens).issubset({f"admin@{DOMAIN}", f"idm_admin@{DOMAIN}"}):
            raise ValueError

        token = json_string(tokens[f"{name}@{DOMAIN}"])
        identity = json_object(api("/v1/self", token))
        attrs = native_attrs(json_object(identity["youare"])["attrs"])
        expected = (
            "00000000-0000-0000-0000-000000000000"
            if name == "admin"
            else "00000000-0000-0000-0000-000000000018"
        )

        if (
            attrs.get("uuid") != [expected]
            or attrs.get("name") != [name]
            or attrs.get("spn") != [f"{name}@{DOMAIN}"]
        ):
            raise ValueError

        return token
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()

        raise RuntimeError(
            "Operator session unavailable or expired, use interactive login or reauth"
        ) from error


def cli(
    *args: str, name: str = "idm_admin", check: bool = True
) -> subprocess.CompletedProcess[str]:
    client = shutil.which("kanidm")

    if client is None:
        raise RuntimeError("The pinned production operator image lacks the Kanidm CLI")

    if args != ("login",):
        return command(client, *args, env=cli_env(name), check=check)

    try:
        operator_token(name)
        return subprocess.CompletedProcess([client, *args], 0, "", "")
    except RuntimeError:
        if os.environ.get("IDENTITY_BOOTSTRAP_PASSWORD") != "1":
            raise

        result = command(
            client, *args, env=cli_env(name, bootstrap_password=True), check=check
        )
        operator_token(name)
        return result


def entry_exists(kind: str, name: str) -> bool:
    result = cli(kind, "get", name, "--output", "json")

    if result.stdout.strip() == "No matching entries":
        return False

    entry: object = json.loads(result.stdout or "null")

    if not is_object_dict(entry):
        return False

    attrs = json_object(entry.get("attrs", {}))
    return bool(attrs.get("uuid"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


def _json_response(
    request: str | urllib.request.Request, timeout: float
) -> tuple[int, object]:
    try:
        with opener().open(request, timeout=timeout) as response:
            payload: object = json.load(response)
            return response.status, payload
    except http.client.HTTPException:
        raise urllib.error.URLError(
            "Native API returned an invalid HTTP response"
        ) from None


def api(
    path: object, token: object, method: str = "GET", body: object = None
) -> object:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise RuntimeError("Native API paths must stay on the configured origin")

    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        raise RuntimeError("A native service token is required")

    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        URL + path,
        data=payload,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    return _json_response(request, timeout=10)[1]


def ready() -> None:
    deadline = time.monotonic() + 30

    while time.monotonic() < deadline:
        try:
            status, payload = _json_response(URL + "/status", timeout=2)

            if status == 200 and payload is True:
                require_native_credential_compare()
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass

        time.sleep(0.25)

    raise RuntimeError("Kanidm did not pass verified TLS and HTTP readiness")


def require_native_credential_compare() -> None:
    status, payload = _json_response(URL + "/v1/identity/_capabilities", timeout=10)

    if (
        status != 200
        or not is_object_dict(payload)
        or type(payload.get("credential_update_compare")) is not int
        or payload["credential_update_compare"] != 1
    ):
        raise RuntimeError("The native credential comparison capability is unavailable")
