import argparse
import base64
import fcntl
import hmac
import json
import os
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from collections.abc import Collection, Generator, Mapping
from contextlib import ExitStack, closing, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

from contracts import (
    JSONObject,
    NativeAPI,
    ProductionRuntime,
    is_object_dict,
    json_array,
    json_number,
    json_object,
    json_string,
    native_attrs,
)
from native_names import native_name
from runtime_view import runtime as container


class PrincipalSpec(TypedDict):
    name: str
    file: Path
    token: str
    expiry: str
    uuid: str
    id: str
    purpose: Literal["readonly", "readwrite"]
    lock: Path
    groups: NotRequired[tuple[str, ...]]
    roles: NotRequired[tuple[str, ...]]
    role: NotRequired[str]
    nested: NotRequired[str]
    people: NotRequired[bool]
    delegated_teams: NotRequired[bool]


class TokenClaims(TypedDict):
    account_id: str
    token_id: str
    expiry: NotRequired[int | None]
    purpose: NotRequired[str]


class MissingToken(TypedDict):
    account_id: str
    token_id: None
    expiry: NotRequired[int | None]
    purpose: NotRequired[str]


type ActiveClaims = TokenClaims | MissingToken


class NativeToken(TypedDict):
    account_id: str
    token_id: str
    label: NotRequired[str]
    expiry: NotRequired[int | None]
    purpose: NotRequired[str]


class RotationJournal(TypedDict):
    service_uuid: str
    old_id: str | None
    before_ids: list[str]
    previous_retirements: list[str]
    expiry: int
    purpose: str
    phase: str
    label: str
    new_id: NotRequired[str]


class RotationResult(TypedDict):
    service: str
    expires_at: str
    pending_retirements: int
    consumer_reload_required: bool
    recovered: bool


class RetirementResult(TypedDict):
    service: str
    retired: int


class DependencySnapshot(TypedDict):
    ready: bool
    checked_at: float
    checks: dict[str, bool]
    token_remaining_seconds: dict[str, float]
    signals: dict[str, int | float | None]
    alarms: list[str]


class Options(argparse.Namespace):
    action: str
    service: str | None
    days: int


DIRECTORY = container.STATE / "operations"
EVENTS = DIRECTORY / "events.json"
RETIREMENTS = DIRECTORY / "retirements.json"
OBSERVER = container.STATE / "metrics" / "observer" / "credentials.json"
OBSERVER_STATUS = container.STATE / "metrics" / "dashboards" / "observer-status"
LABEL_PREFIX = "Identity"
PRINCIPALS: dict[str, PrincipalSpec] = {
    "enrollment": {
        "name": native_name("enrollment_service", container),
        "file": container.STATE / "enrollment" / "kanidm.json",
        "token": "worker_token",
        "expiry": "worker_token_expiry",
        "uuid": "worker_uuid",
        "id": "worker_token_id",
        "purpose": "readwrite",
        "lock": container.STATE / "enrollment" / "kanidm.lock",
        "groups": (native_name("members", container),),
        "roles": (
            f"idm_people_on_boarding@{container.DOMAIN}",
            f"{native_name('enrollment_workers', container)}@{container.DOMAIN}",
        ),
    },
    "posix": {
        "name": native_name("posix_provisioner", container),
        "file": container.STATE / "posix-defaults" / "service.json",
        "token": "token",
        "expiry": "token_expiry",
        "uuid": "service_uuid",
        "id": "token_id",
        "purpose": "readwrite",
        "lock": container.STATE / "posix-defaults" / "bootstrap.lock",
        "role": f"idm_unix_admins@{container.DOMAIN}",
    },
    "monitor": {
        "name": native_name("directory_reader", container),
        "file": container.CREDENTIALS,
        "token": "token",
        "expiry": "token_expiry",
        "uuid": "service_uuid",
        "id": "token_id",
        "purpose": "readonly",
        "nested": "monitoring",
        "lock": container.STATE / "credentials.lock",
        "groups": (native_name("members", container),),
    },
    "authorization": {
        "name": native_name("authorization_reader", container),
        "file": container.STATE / "enrollment" / "kanidm.json",
        "token": "authorization_token",
        "expiry": "authorization_token_expiry",
        "uuid": "authorization_uuid",
        "id": "authorization_token_id",
        "purpose": "readonly",
        "lock": container.STATE / "enrollment" / "kanidm.lock",
        "groups": (native_name("officers", container),),
        "people": True,
        "roles": (
            f"idm_people_admins@{container.DOMAIN}",
            f"idm_access_control_admins@{container.DOMAIN}",
            f"idm_account_policy_admins@{container.DOMAIN}",
        ),
    },
    "access": {
        "name": native_name("membership_controller", container),
        "file": container.STATE / "access" / "config.json",
        "token": "token",
        "expiry": "token_expiry",
        "uuid": "service_uuid",
        "id": "token_id",
        "purpose": "readwrite",
        "lock": container.STATE / "access" / "bootstrap.lock",
        "role": f"{native_name('membership_controllers', container)}@{container.DOMAIN}",
        "delegated_teams": True,
    },
}
EVENT_NAMES = frozenset(
    {
        "enrollment_created",
        "enrollment_failed",
        "recovery_started",
        "recovery_failed",
        "recovery_completed",
        "posix_pass",
        "posix_failure",
        "token_rotated",
        "token_retired",
        "team_granted",
        "team_revoked",
        "team_expired",
        "passkey_added",
    }
)
ALARM_NAMES = frozenset(
    [
        name + suffix
        for name in PRINCIPALS
        for suffix in ("_token_expiring", "_token_expired", "_capability_failed")
    ]
    + [
        name + suffix
        for name in ("kanidm", "enrollment")
        for suffix in ("_certificate_expiring", "_certificate_failed")
    ]
    + [
        "posix_worker_stale",
        "access_worker_stale",
        "native_backup_stale",
        "paired_backup_stale",
        "paired_restore_stale",
        "team_ledger_unavailable",
        "team_grants_overdue",
        "team_native_sync_stale",
    ]
)
SAFE_FAILURES = (OSError, ValueError, TypeError, KeyError, RuntimeError)


def require(value: object, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def authorize_registration_export(token: str) -> None:
    _, installed = _configuration(PRINCIPALS["monitor"])
    require(
        hmac.compare_digest(token, json_string(installed.get("token"))),
        "Registration export requires the installed observer credential",
    )

    attrs = native_attrs(
        json_object(json_object(container.api("/v1/self", token))["youare"])["attrs"]
    )
    require(
        attrs.get("name") == [PRINCIPALS["monitor"]["name"]]
        and "service_account" in attrs.get("class", [])
        and claims(token).get("purpose") == "readonly",
        "Registration export requires the native read only observer",
    )


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("Expected a canonical native UUID")

    require(str(uuid.UUID(value)) == value, "Expected a canonical native UUID")

    return value


def claims(token: object) -> TokenClaims:
    require(
        isinstance(token, str) and len(token) <= 32768 and token.count(".") == 2,
        "Expected a non-compact native service token",
    )

    token = json_string(token)
    encoded = token.split(".")[1]
    value = json_object(
        json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    )
    result: TokenClaims = {
        "account_id": canonical_uuid(value.get("account_id")),
        "token_id": canonical_uuid(value.get("token_id")),
    }

    if "expiry" in value:
        expiry = value["expiry"]

        if expiry is not None and (
            not isinstance(expiry, int) or isinstance(expiry, bool)
        ):
            raise RuntimeError("Token expiry must use integer seconds")

        result["expiry"] = expiry

    if "purpose" in value:
        result["purpose"] = json_string(value["purpose"])

    return result


def timestamp(value: object) -> float:
    require(isinstance(value, str), "Token expiry requires an RFC3339 timestamp")

    parsed = datetime.fromisoformat(json_string(value).replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "Token expiry requires a timezone")

    return parsed.timestamp()


@contextmanager
def _parent_directory(path: Path, *, create: bool = False) -> Generator[int]:
    absolute = path.absolute()
    require(
        ".." not in absolute.parts and bool(absolute.name),
        "Private paths must not contain parent traversal",
    )

    production = isinstance(container, ProductionRuntime)

    if create and isinstance(container, ProductionRuntime):
        container.prepare_private_directory(path.parent)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:-1]:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create or production:
                    raise

                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)

                child = os.open(part, flags, dir_fd=descriptor)

            os.close(descriptor)
            descriptor = child

        if create and not production:
            os.fchmod(descriptor, 0o700)

        yield descriptor
    finally:
        os.close(descriptor)


def load_private(
    path: Path, *, owner: int | None = None, forbidden_mode: int = 0o077
) -> JSONObject:
    with _parent_directory(path) as parent:
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and not info.st_mode & forbidden_mode
                and (owner is None or info.st_uid == owner),
                "JSON must be a regular file with trusted permissions and ownership",
            )

            with os.fdopen(descriptor, closefd=False) as file:
                return json_object(json.load(file))
        finally:
            os.close(descriptor)


def _configuration(spec: PrincipalSpec) -> tuple[JSONObject, JSONObject]:
    root = load_private(spec["file"])
    nested = spec.get("nested")
    config = json_object(root.get(nested, {})) if nested else root
    return root, config


def write_private(path: Path, value: object) -> None:
    with _parent_directory(path, create=True) as parent:
        temporary = ".identity-" + uuid.uuid4().hex
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            with os.fdopen(descriptor, "w", closefd=False) as file:
                os.fchmod(file.fileno(), 0o600)

                if isinstance(container, ProductionRuntime):
                    container.protect_private_file(file.fileno(), path)

                json.dump(value, file, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
        finally:
            os.close(descriptor)

            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent)


@contextmanager
def private_lock(path: Path) -> Generator[None]:
    with _parent_directory(path, create=True) as parent:
        descriptor = os.open(
            path.name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=parent,
        )
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and not info.st_mode & 0o077,
                "The maintenance lock must be a private regular unshared file",
            )

            os.fchmod(descriptor, 0o600)

            if isinstance(container, ProductionRuntime):
                container.protect_private_file(descriptor, path)

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)


@contextmanager
def operator_api() -> Generator[NativeAPI]:
    def api(path: str, method: str = "GET", body: object = None) -> object:
        return container.api(path, token, method=method, body=body)

    if isinstance(container, ProductionRuntime):
        token = container.operator_token("idm_admin")

        yield api
        return

    client = shutil.which("kanidm")

    if client is None:
        raise RuntimeError("Run token maintenance in the pinned Nix dev shell")

    with tempfile.TemporaryDirectory(prefix="identity-token-maintenance-") as directory:
        environment = container.cli_env("idm_admin")
        cache = Path(directory) / "tokens"
        environment["KANIDM_TOKEN_CACHE_PATH"] = str(cache)

        def cli(*arguments: str) -> subprocess.CompletedProcess[str]:
            return container.command(client, *arguments, env=environment)

        cli("login")
        try:
            instance = json_object(
                json_object(load_private(cache)["instances"])[
                    environment["KANIDM_INSTANCE"]
                ]
            )
            tokens = json_object(instance["tokens"])
            require(
                set(tokens) == {f"idm_admin@{container.DOMAIN}"},
                "The temporary operator token cache has unexpected identities",
            )
            token = json_string(tokens[f"idm_admin@{container.DOMAIN}"])

            attrs = native_attrs(
                json_object(json_object(api("/v1/self"))["youare"])["attrs"]
            )
            require(
                attrs.get("name") == ["idm_admin"]
                and attrs.get("uuid") == ["00000000-0000-0000-0000-000000000018"],
                "The operator token does not identify the native IDM administrator",
            )

            yield api
        finally:
            cli("logout")


def _principal(
    spec: PrincipalSpec, api: NativeAPI, expected_uuid: object = None
) -> str:
    attrs = native_attrs(
        json_object(api("/v1/service_account/" + spec["name"]))["attrs"]
    )
    require(
        attrs.get("name") == [spec["name"]]
        and "service_account" in attrs.get("class", [])
        and attrs.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"]
        and len(attrs.get("uuid", [])) == 1,
        "The existing service principal requires review, no roles were changed",
    )

    native_uuid = canonical_uuid(attrs["uuid"][0])
    require(
        expected_uuid is None or expected_uuid == native_uuid,
        "The saved service principal changed identity",
    )

    return native_uuid


def _inventory(api: NativeAPI, service_uuid: str) -> list[NativeToken]:
    result: list[NativeToken] = []

    for raw in json_array(api(f"/v1/service_account/{service_uuid}/_api_token")):
        row = json_object(raw)
        token: NativeToken = {
            "account_id": canonical_uuid(row.get("account_id")),
            "token_id": canonical_uuid(row.get("token_id")),
        }

        if "label" in row:
            token["label"] = json_string(row["label"])

        if "purpose" in row:
            token["purpose"] = json_string(row["purpose"])

        if "expiry" in row:
            expiry = row["expiry"]

            if expiry is not None and (
                not isinstance(expiry, int) or isinstance(expiry, bool)
            ):
                raise RuntimeError("Native inventory expiry must use integer seconds")

            token["expiry"] = expiry

        result.append(token)

    return result


def _capability(
    spec: PrincipalSpec, token: object, service_uuid: str
) -> dict[str, list[str]]:
    token = json_string(token)

    def api(path: str) -> object:
        return container.api(path, token)

    attrs = native_attrs(json_object(json_object(api("/v1/self"))["youare"])["attrs"])
    require(
        attrs.get("uuid") == [service_uuid]
        and attrs.get("name") == [spec["name"]]
        and "service_account" in attrs.get("class", []),
        "Kanidm rejected the intended service identity",
    )

    role = spec.get("role")

    if role:
        require(
            role in attrs.get("memberof", []),
            "The service no longer has its required native role",
        )

    require(
        set(spec.get("roles", ())).issubset(attrs.get("memberof", [])),
        "The service no longer has its required native roles",
    )

    if spec.get("delegated_teams"):
        role = json_string(role)
        require(
            "account" in attrs.get("class", [])
            and not {"person", "group", "recycled", "tombstone"}.intersection(
                attrs.get("class", [])
            )
            and set(attrs.get("memberof", [])).issubset(
                {role, f"idm_all_accounts@{container.DOMAIN}"}
            ),
            "The group writer has unexpected native privilege",
        )

        _, config = _configuration(spec)
        for raw_policy in json_array(config["policies"]):
            identifier = canonical_uuid(json_object(raw_policy)["group_uuid"])
            team = native_attrs(
                json_object(api("/v1/group/" + identifier)).get("attrs", {})
            )
            require(
                team.get("uuid") == [identifier]
                and "group" in team.get("class", [])
                and not {"dyngroup", "recycled", "tombstone"}.intersection(
                    team.get("class", [])
                )
                and team.get("entry_managed_by") == [role],
                "A managed group changed native delegation",
            )

    if spec.get("people") or spec["name"] in {
        PRINCIPALS["posix"]["name"],
        PRINCIPALS["enrollment"]["name"],
    }:
        people = json_array(api("/v1/person"))

        if spec.get("people"):
            ordinary: list[dict[str, list[str]]] = []

            for raw_person in people:
                if not is_object_dict(raw_person):
                    continue

                person = native_attrs(json_object(raw_person).get("attrs", {}))

                if "person" in person.get("class", []) and "builtin" not in person.get(
                    "class", []
                ):
                    ordinary.append(person)

            if ordinary:
                identifier = canonical_uuid(ordinary[0].get("uuid", [""])[0])
                status = json_object(
                    api(f"/v1/person/{identifier}/_credential/_status")
                )
                json_array(status.get("creds"))

    for group in spec.get("groups", ()):
        attrs_group = native_attrs(
            json_object(api("/v1/group/" + group)).get("attrs", {})
        )
        require(
            attrs_group.get("name") == [group],
            "The required configured group read failed",
        )

    return attrs


def _pending(service: str) -> tuple[JSONObject, list[str]]:
    data = load_private(RETIREMENTS) if RETIREMENTS.exists() else {}
    ids = [
        canonical_uuid(identifier) for identifier in json_array(data.get(service, []))
    ]
    return data, ids


def _set_pending(service: str, ids: Collection[str]) -> None:
    data, _ = _pending(service)
    data[service] = json_array(sorted(set(ids)))
    write_private(RETIREMENTS, data)


def _journals() -> JSONObject:
    path = DIRECTORY / "rotation-journal.json"
    return load_private(path) if path.exists() else {}


def _journal(service: str, record: RotationJournal | None) -> None:
    data = _journals()

    if record is None:
        data.pop(service, None)
    else:
        data[service] = json_object(record)

    write_private(DIRECTORY / "rotation-journal.json", data)


def _owned_candidates(
    record: RotationJournal, inventory: list[NativeToken]
) -> list[NativeToken]:
    candidates = [row for row in inventory if row.get("label") == record["label"]]
    require(len(candidates) <= 1, "The native transaction label is ambiguous")

    for row in candidates:
        canonical_uuid(row.get("token_id"))
        require(
            row.get("account_id") == record["service_uuid"]
            and row["token_id"] not in record["before_ids"]
            and row["token_id"] != record["old_id"],
            "A transaction label matched an existing or foreign token",
        )

    return candidates


def _rotation_result(
    service: str, config: JSONObject, ids: Collection[str], recovered: bool = False
) -> RotationResult:
    return {
        "service": service,
        "expires_at": json_string(config[PRINCIPALS[service]["expiry"]]),
        "pending_retirements": len(ids),
        "consumer_reload_required": False,
        "recovered": recovered,
    }


def rotation_journal(value: object) -> RotationJournal:
    record = json_object(value)
    expiry = record["expiry"]

    if not isinstance(expiry, int) or isinstance(expiry, bool):
        raise RuntimeError("Rotation expiry must use integer seconds")

    old = record["old_id"]
    result: RotationJournal = {
        "service_uuid": canonical_uuid(record["service_uuid"]),
        "old_id": canonical_uuid(old) if old is not None else None,
        "before_ids": [
            canonical_uuid(item) for item in json_array(record["before_ids"])
        ],
        "previous_retirements": [
            canonical_uuid(item) for item in json_array(record["previous_retirements"])
        ],
        "expiry": expiry,
        "purpose": json_string(record["purpose"]),
        "phase": json_string(record["phase"]),
        "label": json_string(record["label"]),
    }

    if "new_id" in record:
        result["new_id"] = canonical_uuid(record["new_id"])

    return result


def _recover_rotation(
    service: str,
    spec: PrincipalSpec,
    api: NativeAPI,
    native_uuid: str,
    root: JSONObject,
    config: JSONObject,
) -> RotationResult | None:
    raw_record = _journals().get(service)

    if raw_record is None:
        return None

    record = rotation_journal(raw_record)
    require(
        record.get("service_uuid") == native_uuid
        and record.get("purpose") == spec["purpose"]
        and record.get("phase") in {"prepared", "issued", "installed"}
        and record["label"].startswith(f"{LABEL_PREFIX} {service} rotation "),
        "The saved rotation transaction needs review",
    )

    if record["old_id"] is not None:
        canonical_uuid(record["old_id"])

    for identifier in record["before_ids"] + record["previous_retirements"]:
        canonical_uuid(identifier)

    active: ActiveClaims = (
        claims(config[spec["token"]])
        if config.get(spec["token"])
        else {
            "account_id": native_uuid,
            "token_id": None,
        }
    )
    require(
        active["account_id"] == native_uuid, "The installed token changed principal"
    )

    inventory = _inventory(api, native_uuid)
    candidates = _owned_candidates(record, inventory)
    candidate_id = candidates[0]["token_id"] if candidates else record.get("new_id")

    if active["token_id"] == record["old_id"]:
        for row in candidates:
            api(
                f"/v1/service_account/{native_uuid}/_api_token/{row['token_id']}",
                method="DELETE",
            )

        require(
            not _owned_candidates(record, _inventory(api, native_uuid)),
            "The incomplete candidate could not be revoked",
        )

        _set_pending(service, record["previous_retirements"])
        _journal(service, None)
        return None

    require(
        candidate_id is not None
        and active["token_id"] == candidate_id
        and len(candidates) == 1
        and candidates[0].get("expiry") == record["expiry"]
        and candidates[0].get("purpose") == spec["purpose"]
        and active.get("expiry") == record["expiry"]
        and active.get("purpose", "readonly") == spec["purpose"],
        "Installed credentials do not match the saved native transaction",
    )

    _, pending_ids = _pending(service)
    ids = set(pending_ids) | set(record["previous_retirements"])

    if record["old_id"] is not None and any(
        row.get("token_id") == record["old_id"] and row.get("account_id") == native_uuid
        for row in inventory
    ):
        ids.add(record["old_id"])

    require(
        active["token_id"] not in ids, "The installed token is in the retirement queue"
    )

    if record["expiry"] <= time.time():
        _set_pending(service, ids)
        _journal(service, None)
        return None

    _capability(spec, config[spec["token"]], native_uuid)
    _set_pending(service, ids)
    record["phase"] = "installed"
    record["new_id"] = canonical_uuid(active["token_id"])
    _journal(service, record)

    if service == "monitor":
        write_private(OBSERVER, {"url": root["url"], **config})

    return _rotation_result(service, config, ids, recovered=True)


def rotate(
    service: str, days: object = 30, api: NativeAPI | None = None
) -> RotationResult:
    if (
        service not in PRINCIPALS
        or not isinstance(days, int)
        or isinstance(days, bool)
        or not 1 <= days <= 30
    ):
        raise RuntimeError(
            "Select a configured principal and an expiry of 1 to 30 days"
        )

    spec = PRINCIPALS[service]

    if api is None:
        with operator_api() as native_api:
            return rotate(service, days, native_api)

    with ExitStack() as stack:
        stack.enter_context(private_lock(DIRECTORY / "maintenance.lock"))
        stack.enter_context(private_lock(spec["lock"]))

        root, config = _configuration(spec)
        old_token = config.get(spec["token"])
        old: ActiveClaims = (
            claims(old_token)
            if old_token
            else {
                "account_id": canonical_uuid(config.get(spec["uuid"])),
                "token_id": None,
            }
        )

        service_uuid = _principal(
            spec, api, config.get(spec["uuid"]) or old["account_id"]
        )
        require(
            old["account_id"] == service_uuid,
            "The old token belongs to another principal",
        )

        resumed = _recover_rotation(service, spec, api, service_uuid, root, config)

        if resumed is not None:
            return resumed

        _, previous_ids = _pending(service)
        require(
            old["token_id"] not in previous_ids,
            "The active token is in the retirement queue",
        )

        before = _inventory(api, service_uuid)
        require(
            old_token is not None or not before,
            "Initial token provisioning refuses an unrecorded native token",
        )

        expiry = int(time.time()) + days * 86400
        record: RotationJournal = {
            "service_uuid": service_uuid,
            "old_id": old["token_id"],
            "before_ids": [canonical_uuid(row.get("token_id")) for row in before],
            "previous_retirements": previous_ids,
            "expiry": expiry,
            "purpose": spec["purpose"],
            "phase": "prepared",
            "label": f"{LABEL_PREFIX} {service} rotation {uuid.uuid4()}",
        }
        _journal(service, record)  # native issuance may succeed without a response

        try:
            token = json_string(
                api(
                    f"/v1/service_account/{service_uuid}/_api_token",
                    method="POST",
                    body={
                        "label": record["label"],
                        "expiry": expiry,
                        "read_write": spec["purpose"] == "readwrite",
                        "compact": False,
                    },
                )
            )

            candidate = claims(token)
            inventory = _inventory(api, service_uuid)
            matches = _owned_candidates(record, inventory)

            require(
                len(matches) == 1
                and matches[0]["token_id"] == candidate["token_id"]
                and candidate["account_id"] == service_uuid
                and matches[0].get("expiry") == expiry
                and matches[0].get("purpose") == spec["purpose"]
                and candidate.get("expiry") == expiry
                and candidate.get("purpose", "readonly") == spec["purpose"],
                "Generated token inventory, purpose or expiry did not match",
            )

            _capability(spec, token, service_uuid)
            record["phase"] = "issued"
            record["new_id"] = canonical_uuid(candidate["token_id"])
            _journal(service, record)

            ids = set(previous_ids)

            if old["token_id"] is not None and any(
                row.get("token_id") == old["token_id"]
                and row.get("account_id") == service_uuid
                for row in before
            ):
                ids.add(old["token_id"])

            _set_pending(
                service, ids
            )  # configuration replacement hides the old token id

            config.update(
                {
                    spec["token"]: token,
                    spec["uuid"]: service_uuid,
                    spec["id"]: candidate["token_id"],
                    spec["expiry"]: datetime.fromtimestamp(expiry, UTC).isoformat(),
                }
            )

            if service == "monitor":
                config["account"] = spec["name"]

            write_private(spec["file"], root)
            result = _recover_rotation(service, spec, api, service_uuid, root, config)

            if result is None:
                raise RuntimeError(
                    "Installed rotation did not produce a verified result"
                )

            result["recovered"] = False
        except SAFE_FAILURES:
            try:
                actual_root, actual = _configuration(spec)
                _recover_rotation(service, spec, api, service_uuid, actual_root, actual)
            except SAFE_FAILURES:
                pass

            raise RuntimeError(
                "Token rotation did not complete, retry to recover its recorded transaction"
            ) from None

    record_event("token_rotated")
    return result


def retire(service: str, api: NativeAPI | None = None) -> RetirementResult:
    require(service in PRINCIPALS, "Select a configured principal")

    if api is None:
        with operator_api() as native_api:
            return retire(service, native_api)

    spec = PRINCIPALS[service]
    with private_lock(DIRECTORY / "maintenance.lock"), private_lock(spec["lock"]):
        _, config = _configuration(spec)
        active = claims(config[spec["token"]])
        native_uuid = _principal(spec, api, config.get(spec["uuid"]))
        require(
            active["account_id"] == native_uuid,
            "The installed token belongs to another principal",
        )

        _recover_rotation(service, spec, api, native_uuid, *_configuration(spec))
        _capability(spec, config[spec["token"]], native_uuid)

        if service == "monitor":
            status = load_private(OBSERVER_STATUS)
            require(
                status.get("token_id") == active["token_id"]
                and status.get("credential_verified") is True
                and 0 <= time.time() - json_number(status["timestamp"]) <= 60,
                "Wait for the running observer to acknowledge the new token before retirement",
            )

        pending = load_private(RETIREMENTS) if RETIREMENTS.exists() else {}
        ids = [canonical_uuid(item) for item in json_array(pending.get(service, []))]
        require(
            active["token_id"] not in ids,
            "Refusing to revoke the installed token",
        )

        inventory = _inventory(api, native_uuid)
        for token_id in ids:
            canonical_uuid(token_id)

            if any(
                row.get("token_id") == token_id and row.get("account_id") == native_uuid
                for row in inventory
            ):
                api(
                    f"/v1/service_account/{native_uuid}/_api_token/{token_id}",
                    method="DELETE",
                )

        require(
            not set(ids).intersection(
                row.get("token_id") for row in _inventory(api, native_uuid)
            ),
            "Native token retirement did not take effect",
        )

        pending[service] = []
        write_private(RETIREMENTS, pending)
        _journal(service, None)

    record_event("token_retired")
    return {"service": service, "retired": len(ids)}


def record_event(name: str) -> None:
    require(name in EVENT_NAMES, "Unknown operational event")

    with private_lock(DIRECTORY / "events.lock"):
        data = load_private(EVENTS) if EVENTS.exists() else {}
        counters = json_object(data.get("counters", {}))
        previous = counters.get(name, 0)

        if not isinstance(previous, int) or isinstance(previous, bool) or previous < 0:
            raise RuntimeError("The aggregate event store needs review")

        counters[name] = previous + 1
        data["counters"] = counters
        data["updated_at"] = time.time()
        write_private(EVENTS, data)


def certificate_remaining(url: str, now: float) -> float:
    parsed = urllib.parse.urlsplit(url)
    require(
        parsed.scheme == "https" and parsed.hostname and not parsed.username,
        "A trusted HTTPS origin is required",
    )

    hostname = parsed.hostname

    if hostname is None:
        raise RuntimeError("A trusted HTTPS origin is required")

    context = ssl.create_default_context(cafile=str(container.DATA / "ca.pem"))
    with (
        socket.create_connection((hostname, parsed.port or 443), timeout=3) as raw,
        context.wrap_socket(raw, server_hostname=hostname) as tls,
    ):
        certificate: Mapping[str, object] | None = tls.getpeercert()

        if certificate is None:
            raise RuntimeError("The peer certificate is unavailable")

        return ssl.cert_time_to_seconds(json_string(certificate["notAfter"])) - now


def _trusted_status(
    path: Path, owner: int, now: float | None, maximum_age: float
) -> JSONObject:
    value = load_private(path, owner=owner, forbidden_mode=0o027)
    now = time.time() if now is None else now
    require(
        0 <= now - json_number(value["checked_at"]) <= maximum_age,
        "Worker status export is stale",
    )

    return value


def _public_posix_status(now: float | None) -> tuple[JSONObject, float]:
    if not isinstance(container, ProductionRuntime):
        raise RuntimeError("The native runtime has no public POSIX export")

    status = _trusted_status(container.POSIX_STATUS, 10004, now, 30)
    now = time.time() if now is None else now
    require(
        status.get("service_name") == PRINCIPALS["posix"]["name"]
        and status.get("credential_verified") is True
        and status.get("purpose") == "readwrite"
        and not status.get("last_error")
        and 0 <= now - json_number(status["checked_at"]) <= 30
        and 0 <= now - json_number(status["last_success"]) <= 30,
        "POSIX worker did not authenticate successfully",
    )

    canonical_uuid(status["service_uuid"])
    canonical_uuid(status["token_id"])
    expiry = timestamp(status["token_expiry"])
    require(expiry > now, "POSIX service token expired")

    return status, expiry


def team_backlog(now: float) -> dict[str, int | float]:
    path = container.STATE / "access" / "grants.sqlite3"
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o077,
        "Group ledger must be a private owned file",
    )

    uri = "file:" + urllib.parse.quote(str(path.absolute())) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=0.2)) as db:
        deadline = time.monotonic() + 0.05
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        row: tuple[object, ...] | None = db.execute(
            "SELECT COALESCE(SUM(status='granted' AND expires_at<=?),0),"
            "COALESCE(SUM(sync_status IN ('pending','error')),0),"
            "MIN(CASE WHEN sync_status IN ('pending','error') THEN changed_at END) "
            "FROM team_grants",
            (now,),
        ).fetchone()

    if row is None or len(row) != 3:
        raise RuntimeError("Invalid group backlog row")

    overdue, pending, oldest = row

    if (
        not isinstance(overdue, int)
        or not isinstance(pending, int)
        or overdue < 0
        or pending < 0
    ):
        raise RuntimeError("Invalid group backlog counts")

    age = max(0.0, now - json_number(oldest)) if pending else 0.0
    require(age >= 0, "Invalid group backlog age")

    return {
        "team_grants_overdue": overdue,
        "team_native_sync_pending": pending,
        "team_native_sync_oldest_age_seconds": age,
    }


def dependency_snapshot(now: float | None = None) -> DependencySnapshot:
    fixed_now = now
    now = time.time() if now is None else now
    checks: dict[str, bool] = {}
    expiries: dict[str, float] = {}
    alarms: list[str] = []
    expiry: float | None

    try:
        container.require_native_credential_compare()
        checks["native_credential_guard"] = True
    except SAFE_FAILURES:
        checks["native_credential_guard"] = False

    for service, spec in PRINCIPALS.items():
        try:
            if (
                service == "posix"
                and isinstance(container, ProductionRuntime)
                and container.PUBLIC_READINESS
            ):
                _, expiry = _public_posix_status(fixed_now)
                expiries[service] = expiry - now
                checks[service] = True

                if expiry - now < 7 * 86400:
                    alarms.append(service + "_token_expiring")

                continue

            _, config = _configuration(spec)
            token = config[spec["token"]]
            payload = claims(token)
            expected = canonical_uuid(config.get(spec["uuid"]) or payload["account_id"])
            require(expected == payload["account_id"], "Service identity mismatch")

            expiry = payload.get("expiry")

            if expiry is None:
                raise RuntimeError("Service token needs an explicit expiry")

            if config.get(spec["expiry"]):
                require(
                    abs(timestamp(config[spec["expiry"]]) - expiry) < 1,
                    "Saved and native token expiries differ",
                )

            expiries[service] = expiry - now

            if expiry <= now:
                alarms.append(service + "_token_expired")

            require(expiry > now, "Service token expired")
            _capability(spec, token, expected)
            require(
                payload.get("purpose", "readonly") == spec["purpose"],
                "Service purpose mismatch",
            )
            checks[service] = True

            if expiry - now < 7 * 86400:
                alarms.append(service + "_token_expiring")
        except SAFE_FAILURES:
            checks[service] = False
            alarms.append(service + "_capability_failed")

    try:
        if isinstance(container, ProductionRuntime):
            status, _ = _public_posix_status(fixed_now)
        else:
            status = load_private(container.STATE / "posix-defaults" / "status.json")

        status_now = time.time() if fixed_now is None else fixed_now
        age = status_now - json_number(status["last_success"])
        require(
            0 <= age <= 30 and not status.get("last_error"),
            "POSIX worker is stale or failed",
        )

        checks["posix_worker"] = True
    except SAFE_FAILURES:
        checks["posix_worker"] = False
        age = None
        alarms.append("posix_worker_stale")

    signals: dict[str, int | float | None] = {"posix_success_age_seconds": age}

    try:
        path = container.STATE / "access" / "status.json"
        status = load_private(path, owner=os.geteuid())
        status_now = time.time() if fixed_now is None else fixed_now
        access_age = status_now - json_number(status["at"])
        require(
            status.get("ok") is True and 0 <= access_age <= 65,
            "Group worker is stale or failed",
        )

        checks["access_worker"] = True
    except SAFE_FAILURES:
        access_age = None
        checks["access_worker"] = False
        alarms.append("access_worker_stale")

    signals["access_success_age_seconds"] = access_age
    backlog: dict[str, int | float | None]

    try:
        backlog = dict(team_backlog(now))
        checks["access_ledger"] = True

        if backlog["team_grants_overdue"]:
            alarms.append("team_grants_overdue")

        if (
            backlog["team_native_sync_pending"]
            and json_number(backlog["team_native_sync_oldest_age_seconds"]) > 120
        ):
            alarms.append("team_native_sync_stale")
    except (*SAFE_FAILURES, sqlite3.Error):
        backlog = dict.fromkeys(
            (
                "team_grants_overdue",
                "team_native_sync_pending",
                "team_native_sync_oldest_age_seconds",
            )
        )
        checks["access_ledger"] = False
        alarms.append("team_ledger_unavailable")

    signals.update(backlog)

    for service, url in {
        "kanidm": container.URL,
        "enrollment": container.PORTAL_URL,
    }.items():
        try:
            remaining = certificate_remaining(url, now)
            checks[service + "_tls"] = True
            signals[service + "_certificate_remaining_seconds"] = remaining

            if remaining < 14 * 86400:
                alarms.append(service + "_certificate_expiring")
        except SAFE_FAILURES:
            signals[service + "_certificate_remaining_seconds"] = None
            checks[service + "_tls"] = False
            alarms.append(service + "_certificate_failed")

    backup_time = None

    if isinstance(container, ProductionRuntime):
        try:
            status = _trusted_status(container.BACKUP_STATUS, 0, now, 600)
            require(
                status.get("present") is True
                and 0 <= json_number(status["latest_at"]) <= now,
                "No native backup is available",
            )
            backup_time = float(json_number(status["latest_at"]))
        except SAFE_FAILURES:
            pass
    else:
        backups: list[float] = []
        for path in (container.DATA / "backups").glob("*"):
            try:
                if not path.is_file() or not path.name.endswith((".json", ".json.gz")):
                    continue

                info = path.stat()

                if info.st_size and info.st_mtime <= now:
                    backups.append(info.st_mtime)
            except OSError:
                continue

        backup_time = max(backups) if backups else None

    signals["native_backup_age_seconds"] = (
        now - backup_time if backup_time is not None else None
    )

    if (
        backup_time is None
        or json_number(signals["native_backup_age_seconds"]) > 26 * 3600
    ):
        alarms.append("native_backup_stale")

    paired = {}
    try:
        path = DIRECTORY / "paired-backup.json"
        paired = load_private(path, owner=os.geteuid())
        paired_signals: dict[str, int | float] = {}

        for field in ("created_at", "restored_at"):
            if field in paired:
                age = now - timestamp(paired[field])
                require(age >= 0, "Paired backup receipt is in the future")
                paired_signals[
                    "paired_"
                    + ("backup" if field == "created_at" else "restore")
                    + "_age_seconds"
                ] = age

        paired_signals["paired_local_replica_verified"] = int(
            paired.get("local_replica_verified") is True
        )
        paired_signals["paired_offsite_verified"] = int(
            paired.get("offsite_verified") is True
        )

        signals.update(paired_signals)
    except SAFE_FAILURES:
        paired = {}

    for name, limit in (("backup", 26 * 3600), ("restore", 31 * 86400)):
        key = "paired_" + name + "_age_seconds"
        signals.setdefault(key, None)

        if signals[key] is None or json_number(signals[key]) > limit:
            alarms.append("paired_" + name + "_stale")

    return {
        "ready": all(checks.values()),
        "checked_at": now,
        "checks": checks,
        "token_remaining_seconds": expiries,
        "signals": signals,
        "alarms": alarms,
    }


def render_metrics(snapshot: DependencySnapshot) -> str:
    lines = [
        "# TYPE identity_readiness gauge",
        f"identity_readiness {int(snapshot['ready'])}",
        "# TYPE identity_readiness_checked_timestamp_seconds gauge",
        f"identity_readiness_checked_timestamp_seconds {snapshot['checked_at']}",
        "# TYPE identity_dependency_ready gauge",
    ]

    for name, success in snapshot["checks"].items():
        lines.append(f'identity_dependency_ready{{dependency="{name}"}} {int(success)}')

    lines.append("# TYPE identity_service_token_remaining_seconds gauge")
    for service, remaining in snapshot["token_remaining_seconds"].items():
        lines.append(
            f'identity_service_token_remaining_seconds{{service="{service}"}} {remaining}'
        )

    for signal, value in snapshot["signals"].items():
        lines.extend(
            [
                f"# TYPE identity_{signal}_known gauge",
                f"identity_{signal}_known {int(value is not None)}",
            ]
        )

        if value is not None:
            lines.extend(
                [f"# TYPE identity_{signal} gauge", f"identity_{signal} {value}"]
            )

    lines.append("# TYPE identity_operational_alarm gauge")
    for alarm in sorted(ALARM_NAMES):
        lines.append(
            f'identity_operational_alarm{{alarm="{alarm}"}} {int(alarm in snapshot["alarms"])}'
        )

    lines.append("# TYPE identity_application_events_total counter")
    try:
        raw_events = (
            json_object(load_private(EVENTS).get("counters", {}))
            if EVENTS.exists()
            else {}
        )
        events: dict[str, int] = {}

        for key, event_value in raw_events.items():
            if (
                not isinstance(event_value, int)
                or isinstance(event_value, bool)
                or event_value < 0
            ):
                raise RuntimeError("The aggregate event store needs review")

            events[key] = event_value

        require(
            set(events).issubset(EVENT_NAMES), "The aggregate event store needs review"
        )

        for name in sorted(EVENT_NAMES):
            count = events.get(name, 0)
            lines.append(f'identity_application_events_total{{event="{name}"}} {count}')

        lines.extend(
            [
                "# TYPE identity_application_event_store_read_success gauge",
                "identity_application_event_store_read_success 1",
            ]
        )
    except SAFE_FAILURES:
        lines.extend(
            [
                "# TYPE identity_application_event_store_read_success gauge",
                "identity_application_event_store_read_success 0",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        description="Operator token maintenance and aggregate readiness for Kanidm\n\nToken authorization is checked by Kanidm over verified TLS. Decoded JWS fields are only compared with its authenticated token inventory, never trusted alone"
    )
    parser.add_argument("action", choices=["rotate", "retire", "report"])
    parser.add_argument("service", choices=sorted(PRINCIPALS), nargs="?")
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args(namespace=Options())

    if args.action == "report":
        result: DependencySnapshot | RotationResult | RetirementResult = (
            dependency_snapshot()
        )
    else:
        if args.service is None:
            parser.error("Token maintenance requires one configured service")

        result = (
            rotate(args.service, args.days)
            if args.action == "rotate"
            else retire(args.service)
        )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SAFE_FAILURES as error:
        raise SystemExit(
            f"Operator check failed: {type(error).__name__}, no credentials were printed"
        ) from None
