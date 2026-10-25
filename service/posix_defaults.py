import argparse
import json
import shutil
import sys
import tempfile
import time
import urllib.error
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from typing import Literal, Protocol, TypedDict

import operations
from contracts import (
    JSONObject,
    NativeAPI,
    NativeAttrs,
    ProductionRuntime,
    json_array,
    json_object,
    json_string,
    native_attrs,
)
from native_names import native_name
from runtime_view import runtime as container

SERVICE = native_name("posix_provisioner", container)
DISPLAY_NAME = "Dedicated POSIX defaults provisioning"
STATE = container.STATE / "posix-defaults"
DIRECTORY = STATE
CONFIG = DIRECTORY / "service.json"
STATUS = (
    container.POSIX_STATUS
    if isinstance(container, ProductionRuntime)
    else DIRECTORY / "status.json"
)


class POSIXConfig(TypedDict):
    service_name: str
    service_uuid: str
    token: str
    token_expiry: str
    token_id: str | None


class Verification(TypedDict):
    service_name: str
    service_uuid: str
    token_id: str
    token_expiry: str
    purpose: Literal["readwrite"]
    credential_verified: Literal[True]


class PassResult(TypedDict):
    checked: int
    changed: int
    skipped: int
    failed: int


class Options(argparse.Namespace):
    command: str


class CLI(Protocol):
    def __call__(self, *arguments: str) -> CompletedProcess[str]: ...


last_verification: Verification | None = None
DYNAMIC_UUID_MINIMUM = uuid.UUID("00000000-0000-0000-0001-000000000000")
EXCLUDED_CLASSES = {"builtin", "service_account", "system", "recycled", "tombstone"}
EXCLUDED_NAMES = {"admin", "idm_admin", "anonymous"}


def _require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _uuid(value: object) -> uuid.UUID:
    try:
        parsed = uuid.UUID(json_string(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise RuntimeError("A canonical person UUID is required") from error

    _require(str(parsed) == value, "A canonical person UUID is required")
    return parsed


def _expiry(value: object) -> datetime:
    _require(
        isinstance(value, str), "POSIX provisioning token expiry needs a timestamp"
    )

    try:
        parsed = datetime.fromisoformat(json_string(value).replace("Z", "+00:00"))
        _require(
            parsed.tzinfo is not None,
            "POSIX provisioning token expiry needs a timezone",
        )
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as error:
        raise RuntimeError("POSIX provisioning token expiry is invalid") from error


def _config() -> POSIXConfig:
    config = operations.load_private(CONFIG)
    _require(
        config.get("service_name") == SERVICE
        and json_string(config.get("token")).startswith("eyJ"),
        "The dedicated POSIX provisioning configuration requires review",
    )
    _uuid(config.get("service_uuid"))
    _require(
        _expiry(config["token_expiry"]) > datetime.now(UTC),
        "POSIX provisioning token expired, an operator must rotate it",
    )

    token_id = config.get("token_id")
    return {
        "service_name": json_string(config["service_name"]),
        "service_uuid": json_string(config["service_uuid"]),
        "token": json_string(config["token"]),
        "token_expiry": json_string(config["token_expiry"]),
        "token_id": json_string(token_id) if token_id is not None else None,
    }


def _verified_api() -> NativeAPI:
    global last_verification
    last_verification = None
    config = _config()

    def api(path: str, method: str = "GET", body: object = None) -> object:
        return container.api(path, config["token"], method=method, body=body)

    attrs = native_attrs(json_object(json_object(api("/v1/self"))["youare"])["attrs"])
    _require(
        attrs.get("uuid") == [config["service_uuid"]]
        and attrs.get("name") == [SERVICE]
        and "service_account" in attrs.get("class", [])
        and f"idm_unix_admins@{container.DOMAIN}" in attrs.get("memberof", []),
        "The POSIX token does not belong to the dedicated Unix service",
    )

    payload = operations.claims(config["token"])
    _require(
        payload.get("account_id") == config["service_uuid"]
        and payload.get("purpose") == "readwrite"
        and operations.timestamp(config["token_expiry"]) == payload.get("expiry")
        and (not config.get("token_id") or config["token_id"] == payload["token_id"]),
        "Authenticated POSIX token metadata differs from its configuration",
    )

    last_verification = {
        "service_name": SERVICE,
        "service_uuid": config["service_uuid"],
        "token_id": json_string(payload["token_id"]),
        "token_expiry": config["token_expiry"],
        "purpose": "readwrite",
        "credential_verified": True,
    }

    return api


def _eligible(attrs: NativeAttrs) -> bool:
    classes = set(attrs.get("class", []))
    identifiers = attrs.get("uuid", [])
    names = attrs.get("name", [])

    return (
        {"person", "account"}.issubset(classes)
        and not classes.intersection(EXCLUDED_CLASSES)
        and len(identifiers) == 1
        and _uuid(identifiers[0]) >= DYNAMIC_UUID_MINIMUM
        and len(names) == 1
        and names[0] not in EXCLUDED_NAMES
    )


def _gid(attrs: NativeAttrs) -> str:
    values = attrs.get("gidnumber", [])
    _require(
        len(values) == 1
        and values[0].isascii()
        and values[0].isdigit()
        and 0 < int(values[0]) <= 2_147_483_647,
        "Native POSIX eligibility is missing a valid GID",
    )

    return values[0]


def ensure_person(person_uuid: str, api: NativeAPI | None = None) -> bool:
    _uuid(person_uuid)
    api = api or _verified_api()
    path = f"/v1/person/{person_uuid}"
    before = native_attrs(json_object(api(path) or {}).get("attrs", {}))
    _require(
        before.get("uuid") == [person_uuid] and _eligible(before),
        "POSIX defaults apply only to existing human accounts",
    )

    if "posixaccount" in before["class"]:
        _gid(before)
        return False

    api(path + "/_unix", method="POST", body={})
    after = native_attrs(json_object(api(path) or {}).get("attrs", {}))
    _require(
        after.get("uuid") == before["uuid"]
        and after.get("name") == before["name"]
        and _eligible(after)
        and "posixaccount" in after["class"],
        "Native POSIX defaults did not take effect on the expected account",
    )
    _gid(after)

    if before.get("gidnumber"):
        _require(
            after.get("gidnumber") == before["gidnumber"],
            "Native POSIX defaults changed an existing GID",
        )

    return True


def reconcile() -> PassResult:
    api = _verified_api()
    entries = api("/v1/person")
    _require(isinstance(entries, list), "Unexpected native person listing")

    result: PassResult = {"checked": 0, "changed": 0, "skipped": 0, "failed": 0}

    for entry in json_array(entries):
        try:
            attrs = native_attrs(json_object(entry).get("attrs", {}))

            if not _eligible(attrs):
                result["skipped"] += 1
                continue

            result["checked"] += 1

            if "posixaccount" in attrs["class"]:
                _gid(attrs)
            else:
                result["changed"] += ensure_person(attrs["uuid"][0], api=api)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()

            if status in {401, 403}:
                raise

            result["failed"] += 1
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            result["failed"] += 1

    return result


def _write(path: Path, value: object) -> None:
    operations.write_private(path, value)


@contextmanager
def _bootstrap_lock() -> Generator[None]:
    with operations.private_lock(DIRECTORY / "bootstrap.lock"):
        yield


def _private_unix_directory(cli: CLI) -> None:
    group_name = "idm_unix_authentication_read"

    def attrs() -> NativeAttrs:
        return native_attrs(
            json_object(
                json.loads(cli("group", "get", group_name, "--output", "json").stdout)
            )["attrs"]
        )

    before = attrs()
    _require(
        before.get("uuid") == ["00000000-0000-0000-0000-000000000053"]
        and before.get("name") == [group_name],
        "The native Unix-reader group changed identity",
    )

    original_members = set(before.get("member", []))
    anonymous = {
        f"anonymous@{container.DOMAIN}",
        "00000000-0000-0000-0000-ffffffffffff",
    }

    if original_members.intersection(anonymous):
        cli("group", "remove-members", group_name, "anonymous")

    _require(
        set(attrs().get("member", [])) == original_members - anonymous,
        "The private Unix-reader policy did not preserve other members",
    )


def _unix_administration(cli: CLI, account: NativeAttrs, config: JSONObject) -> None:
    def group() -> NativeAttrs:
        return native_attrs(
            json_object(
                json.loads(
                    cli("group", "get", "idm_unix_admins", "--output", "json").stdout
                )
            )["attrs"]
        )

    before = group()
    _require(
        before.get("uuid") == ["00000000-0000-0000-0000-000000000044"]
        and before.get("name") == ["idm_unix_admins"],
        "The native Unix-administrator group changed identity",
    )

    service_uuid = account["uuid"][0]

    if {service_uuid, account["spn"][0]}.intersection(before.get("member", [])):
        return

    _require(
        not account.get("primary_credential")
        and not account.get("user_auth_token_session"),
        "New POSIX provisioning privilege refuses a native interactive credential or session",
    )

    with operations.operator_api() as api:
        inventory = [
            json_object(item)
            for item in json_array(
                api(f"/v1/service_account/{service_uuid}/_api_token")
            )
        ]

    installed = operations.claims(config["token"]) if config.get("token") else None
    _require(
        (installed is None and not inventory)
        or (
            installed is not None
            and installed["account_id"] == service_uuid
            and installed.get("purpose") == "readwrite"
            and len(inventory) == 1
            and inventory[0].get("account_id") == service_uuid
            and inventory[0].get("token_id") == installed["token_id"]
            and inventory[0].get("purpose") == "readwrite"
            and inventory[0].get("expiry") == installed.get("expiry")
            and installed.get("expiry") == operations.timestamp(config["token_expiry"])
            and config.get("token_id", installed["token_id"]) == installed["token_id"]
        ),
        "New POSIX provisioning privilege refuses an unrecorded native token or credential",
    )

    cli(
        "group", "add-members", "idm_unix_admins", SERVICE
    )  # native unix administration also permits credential changes
    after = group()
    _require(
        after.get("uuid") == before["uuid"]
        and account["spn"][0] in after.get("member", []),
        "The dedicated POSIX service permission did not take effect",
    )


def bootstrap() -> None:
    client = shutil.which("kanidm")

    if client is None:
        raise RuntimeError("Run the POSIX bootstrap in the pinned Nix dev shell")

    with (
        _bootstrap_lock(),
        tempfile.TemporaryDirectory(prefix="identity-posix-bootstrap-") as directory,
    ):
        environment = container.cli_env("idm_admin")
        environment["KANIDM_TOKEN_CACHE_PATH"] = str(Path(directory) / "tokens")

        def cli(*arguments: str) -> CompletedProcess[str]:
            if isinstance(container, ProductionRuntime):
                return container.cli(*arguments)

            return container.command(client, *arguments, env=environment)

        def attrs() -> NativeAttrs:
            result = cli("service-account", "get", SERVICE, "--output", "json")

            if result.stdout.strip() == "No matching entries":
                return {}

            entry: object = json.loads(result.stdout)

            if entry == "No matching entries":
                return {}

            return native_attrs(json_object(entry)["attrs"])

        cli("login")
        try:
            _private_unix_directory(cli)
            actual = attrs()

            if not actual:
                cli("service-account", "create", SERVICE, DISPLAY_NAME, "idm_admin")
                actual = attrs()

            _require(
                actual.get("name") == [SERVICE]
                and actual.get("displayname") == [DISPLAY_NAME]
                and actual.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"]
                and "service_account" in actual.get("class", []),
                "The existing POSIX service principal requires review",
            )

            service_uuid = actual["uuid"][0]
            _uuid(service_uuid)
            current = operations.load_private(CONFIG) if CONFIG.exists() else {}

            if current:
                _require(
                    current.get("service_name") == SERVICE
                    and current.get("service_uuid") == service_uuid,
                    "The saved POSIX service principal changed identity",
                )

            _unix_administration(cli, actual, current)

            if not current:
                current = {
                    "service_name": SERVICE,
                    "service_uuid": service_uuid,
                }
                _write(CONFIG, current)
        finally:
            if not isinstance(container, ProductionRuntime):
                cli("logout")

    if not operations.load_private(CONFIG).get("token"):
        operations.rotate("posix")

    _verified_api()


def _status(
    result: PassResult | None = None, error: BaseException | None = None
) -> None:
    succeeded = result is not None and not result["failed"]

    if succeeded:
        assert result is not None
        status: JSONObject = {
            "last_success": time.time(),
            "last_error": None,
            **json_object(result),
        }
    else:
        try:
            status = operations.load_private(STATUS, forbidden_mode=0o027)
        except OSError, RuntimeError, ValueError, TypeError:
            status = {}

        status.update(
            last_failure=time.time(),
            last_error=type(error).__name__ if error else "PersonDefaultsError",
        )

        if result is not None:
            status.update(json_object(result))

    status.update(checked_at=time.time(), credential_verified=False)

    if succeeded and last_verification:
        status.update(json_object(last_verification))

    _write(STATUS, status)

    if isinstance(container, ProductionRuntime) and container.ISOLATED_POSIX:
        return

    try:
        operations.record_event("posix_pass" if succeeded else "posix_failure")
    except OSError, RuntimeError, ValueError, TypeError:
        print("POSIX event counter write failed", file=sys.stderr, flush=True)


def run(interval: float = 2) -> None:
    first = True
    while True:
        try:
            result = reconcile()
            _status(result=result)

            if first or result["changed"] or result["failed"]:
                print(json.dumps(result, sort_keys=True), flush=True)

            first = False
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()

            try:
                _status(error=error)
            except (
                RuntimeError,
                OSError,
                ValueError,
                KeyError,
                TypeError,
            ) as status_error:
                print(
                    f"POSIX status write failed: {type(status_error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )

            print(
                f"POSIX defaults check failed: {type(error).__name__}",
                file=sys.stderr,
                flush=True,
            )

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["bootstrap", "run", "check"])
    arguments = parser.parse_args(namespace=Options())

    if arguments.command == "bootstrap":
        bootstrap()
    elif arguments.command == "run":
        run()
    else:
        result = reconcile()
        _status(result=result)
        print(json.dumps(result, sort_keys=True))
        sys.exit(bool(result["failed"]))
