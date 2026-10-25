#!/usr/bin/env python3

import copy
import fcntl
import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NotRequired, TypedDict, TypeGuard

from flask import has_request_context, request

import operations
from contracts import (
    Attrs,
    ProductionRuntime,
    is_list,
    is_object_dict,
    is_str_list,
    json_array,
    json_object,
    native_attrs,
)
from native_names import NATIVE_NAMES, native_name
from runtime_view import runtime as container


class EnrollmentConfig(TypedDict, total=False):
    worker_uuid: str
    worker_token: str
    worker_token_expiry: str
    workers_uuid: str
    accounts_uuid: str
    authorization_uuid: str
    authorization_token: str
    authorization_token_expiry: str


class OwnedProfile(TypedDict):
    uuid: str
    name: str
    displayname: str
    mail: str


class OwnedPerson(OwnedProfile):
    created: bool
    create_attempted: bool
    admitted: bool


class CredentialPolicy(TypedDict):
    minimum: str
    attestation_required: bool


class PrivilegedAccount(TypedDict):
    uuid: str
    username: str | None
    protected: bool
    active: bool
    credential_minimum: str
    attestation_verification_required: bool
    mfa_ready: bool
    roles: list[str]


class PrivilegedReadiness(TypedDict):
    ready: bool
    accounts: list[PrivilegedAccount]
    role_manifest: list[str]


class AccountStatus(TypedDict):
    uuid: str
    username: str
    provisioned: bool
    credential_present: bool
    passkey_present: bool
    expired: bool
    not_yet_valid: bool
    admitted: bool
    approved: bool
    status: str


class CredentialSession(TypedDict):
    token: str
    expires_at: int
    person_uuid: str
    recovery: bool
    primary_replaced: NotRequired[bool]


class CredentialStatus(TypedDict):
    spn: str
    primary_state: str
    can_commit: NotRequired[bool]
    warnings: NotRequired[list[object]]
    mfaregstate: NotRequired[object]


class TotpDetails(TypedDict):
    accountname: str
    issuer: str
    secret: list[int]
    algo: str
    step: int
    digits: int


class BootstrapReport(TypedDict):
    config_path: str
    worker_account: str
    delegated_groups: list[str]
    password_only_default: bool
    mfa_policy_groups: list[str]
    native_protected_roles: list[str]
    privileged_readiness: PrivilegedReadiness


class ApprovedAccountGroup(TypedDict):
    accounts_group: str
    accounts_uuid: str


class MembershipSync(TypedDict):
    uuid: str
    active: bool
    changed: int


class ActivatedRole(TypedDict):
    uuid: str
    role: str
    protected: bool


OFFICERS = native_name("officers", container)
WORKER = native_name("enrollment_service", container)
WORKERS = native_name("enrollment_workers", container)
AUTHORIZER = native_name("authorization_reader", container)
PRIVILEGED_POLICY = native_name("privileged_accounts", container)
HIGH_PRIVILEGE = "idm_high_privilege"
PRIVILEGED_ROLE_GROUPS = (
    OFFICERS,
    "team_ctf_leads",
)
AUTHORIZATION_READ_ROLES = (
    "idm_people_admins",
    "idm_access_control_admins",
    "idm_account_policy_admins",
    "idm_unix_authentication_read",  # native credential status requires gidnumber for posix accounts
)
CREDENTIAL_STRENGTH = (
    "any",
    "external",
    "mfa",
    "passkey",
    "attested_passkey",
    "attested_residentkey",
    "invalid",
)
ADMISSION = (native_name("members", container),)
ACCOUNTS = native_name("approved_accounts", container)
DIRECTORY = container.STATE / "enrollment"
CONFIG = DIRECTORY / "kanidm.json"
PEOPLE = DIRECTORY / "kanidm-people.json"
USERNAME = re.compile(r"[a-z][a-z0-9_-]{2,31}\Z")
RESERVED = {
    "admin",
    "root",
    "system",
    "anonymous",
    "idm_admin",
    "oauth",
    "google",
    "kanidm",
    "slugsec",
}

if isinstance(container, ProductionRuntime):
    RESERVED.update(NATIVE_NAMES)


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _write(path: Path, value: object) -> None:
    operations.write_private(path, value)


@contextmanager
def _locked() -> Generator[None]:
    if isinstance(container, ProductionRuntime):
        container.prepare_private_directory(DIRECTORY)
    else:
        DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
        DIRECTORY.chmod(0o700)

    with (DIRECTORY / "kanidm.lock").open("a+") as lock:
        os.chmod(lock.name, 0o600)

        if isinstance(container, ProductionRuntime):
            container.protect_private_file(lock.fileno(), DIRECTORY / "kanidm.lock")

        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _is_config(value: object) -> TypeGuard[EnrollmentConfig]:
    if not is_object_dict(value):
        return False

    fields = (
        "worker_uuid",
        "worker_token",
        "worker_token_expiry",
        "workers_uuid",
        "accounts_uuid",
        "authorization_uuid",
        "authorization_token",
        "authorization_token_expiry",
    )
    return all(field not in value or isinstance(value[field], str) for field in fields)


def configuration() -> EnrollmentConfig:
    require(CONFIG.is_file(), "Initialize the enrollment Kanidm integration first")
    value: object = json.loads(CONFIG.read_text())

    if not _is_config(value):
        raise RuntimeError("Enrollment configuration is invalid")

    return value


def _config_text(config: EnrollmentConfig, field: str) -> str:
    value = config.get(field)

    if not isinstance(value, str) or not value:
        raise RuntimeError("Enrollment configuration field is unavailable")

    return value


def _is_owned_person(value: object) -> TypeGuard[OwnedPerson]:
    if not is_object_dict(value):
        return False

    return all(
        isinstance(value.get(field), str)
        for field in ("uuid", "name", "displayname", "mail")
    ) and all(
        isinstance(value.get(field), bool)
        for field in ("created", "create_attempted", "admitted")
    )


def owned_people() -> dict[str, OwnedPerson]:
    document: object = json.loads(PEOPLE.read_text()) if PEOPLE.is_file() else {}

    if not is_object_dict(document):
        raise RuntimeError("Enrollment account registry is invalid")

    people: dict[str, OwnedPerson] = {}

    for key, value in document.items():
        if not _is_owned_person(value):
            raise RuntimeError("Enrollment account registry is invalid")

        people[key] = value

    return people


def _entry_attrs(entry: object) -> Attrs:
    if not is_object_dict(entry):
        return {}

    try:
        return native_attrs(entry.get("attrs", {}))
    except ValueError as error:
        raise RuntimeError("Native entry attributes are invalid") from error


def _attrs(kind: str, name: str) -> Attrs:
    result = container.cli(kind, "get", name, "--output", "json", name="idm_admin")

    if result.stdout.strip() == "No matching entries":
        return {}

    return _entry_attrs(json.loads(result.stdout or "null"))


def _uuid(value: object) -> str:
    try:
        canonical = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as error:
        raise RuntimeError("A canonical person UUID is required") from error

    require(canonical == value, "A canonical person UUID is required")
    return canonical


def _date(value: object) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError

        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None, "Account expiry must include its timezone")
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, AttributeError, OverflowError) as error:
        raise RuntimeError(
            "An RFC3339 account expiry with a timezone is required"
        ) from error


def _worker_api(path: str, method: str = "GET", body: object = None) -> object:
    return container.api(
        path, _config_text(configuration(), "worker_token"), method=method, body=body
    )


@dataclass
class _RequestAuthorizationReads:
    values: dict[tuple[str, str], object] = field(
        default_factory=dict[tuple[str, str], object], repr=False
    )


def authorization_read_api(
    path: str, token: str, method: str = "GET", body: object = None
) -> object:
    if method != "GET" or body is not None:
        return container.api(path, token, method=method, body=body)

    if (
        not has_request_context()
        or request.method != "GET"
        or request.path not in {"/access", "/access/groups", "/access/members"}
    ):
        return container.api(path, token)

    reads = request.environ.get(
        "identity.authorization_reads"
    )  # authorization changes must be visible on the next request

    if not isinstance(reads, _RequestAuthorizationReads):
        reads = _RequestAuthorizationReads()
        request.environ["identity.authorization_reads"] = reads
    key = (token, path)

    if key not in reads.values:
        reads.values[key] = container.api(path, token)

    return copy.deepcopy(reads.values[key])


def authorization_api(path: str) -> object:
    token = configuration().get("authorization_token")

    if not isinstance(token, str) or not token:
        raise RuntimeError("Authorization observer is unavailable")

    return authorization_read_api(path, token)


def _authorization_person(person_uuid: str) -> Attrs:
    entry = authorization_api(f"/v1/person/{_uuid(person_uuid)}")
    attrs = _entry_attrs(entry)

    require(attrs.get("uuid") == [person_uuid], "Authorization identity is unavailable")

    require("memberof" in attrs, "Authorization memberships are unavailable")

    return attrs


def _privileged_membership(person: Attrs) -> bool:
    memberships = {value.split("@", 1)[0] for value in person.get("memberof", [])}
    return bool(memberships.intersection({HIGH_PRIVILEGE, *PRIVILEGED_ROLE_GROUPS}))


def active_person(person: Attrs) -> bool:
    now = datetime.now(UTC)
    return not (
        any(_date(value) <= now for value in person.get("account_expire", []))
        or any(_date(value) > now for value in person.get("account_valid_from", []))
    )


def _account_group() -> Attrs:
    config = configuration()
    group_uuid = _uuid(config.get("accounts_uuid"))
    entry = authorization_api(f"/v1/group/{group_uuid}")
    attrs = _entry_attrs(entry)

    require(
        attrs.get("uuid") == [group_uuid]
        and attrs.get("name") == [ACCOUNTS]
        and "group" in attrs.get("class", [])
        and not {"dyngroup", "recycled", "tombstone"}.intersection(
            attrs.get("class", [])
        )
        and attrs.get("entry_managed_by")
        in ([WORKERS + f"@{container.DOMAIN}"], [config.get("workers_uuid")]),
        "Approved-account group delegation is unavailable",
    )

    return attrs


def _human_identity(person_uuid: str, *, require_active: bool) -> Attrs:
    person_uuid = _uuid(person_uuid)
    person = _authorization_person(person_uuid)
    classes = set(person.get("class", []))

    require(
        {"person", "account"}.issubset(classes)
        and not {
            "system",
            "service_account",
            "group",
            "recycled",
            "tombstone",
        }.intersection(classes)
        and uuid.UUID(person_uuid).int
        >= uuid.UUID("00000000-0000-0000-0001-000000000000").int
        and len(person.get("spn", [])) == 1
        and (not require_active or active_person(person)),
        "An active approved human account is required",
    )

    return person


def _approved_identity(person_uuid: str, *, require_active: bool) -> Attrs:
    person = _human_identity(person_uuid, require_active=require_active)
    refs = {person_uuid, person["spn"][0]}

    require(
        refs.intersection(_account_group().get("member", [])),
        "The account has not completed approval and credential setup",
    )

    return person


def approved_account(person_uuid: str) -> Attrs:
    return _approved_identity(person_uuid, require_active=True)


def bootstrap_accounts() -> ApprovedAccountGroup:
    with _locked():
        container.cli("login")
        current = configuration()
        workers = _attrs("group", WORKERS)
        worker = _attrs("service-account", WORKER)

        require(
            current.get("worker_uuid") == worker.get("uuid", [None])[0]
            and workers.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"],
            "Existing enrollment principals changed identity",
        )

        if not container.entry_exists("group", ACCOUNTS):
            container.cli("group", "create", ACCOUNTS, WORKERS)
        group = _attrs("group", ACCOUNTS)

        require(
            group.get("entry_managed_by") == [WORKERS + f"@{container.DOMAIN}"]
            and (
                not current.get("accounts_uuid")
                or current.get("accounts_uuid") == group.get("uuid", [None])[0]
            ),
            "Existing approved-account group requires administrator review",
        )

        current["accounts_uuid"] = _uuid(group["uuid"][0])
        current["workers_uuid"] = _uuid(workers["uuid"][0])
        _write(CONFIG, current)
        _account_group()

    return {
        "accounts_group": ACCOUNTS,
        "accounts_uuid": _config_text(current, "accounts_uuid"),
    }


def membership_sync(person_uuid: str, active: bool) -> MembershipSync:
    require(type(active) is bool, "Club admission state must be explicit")

    with _locked():
        person = _human_identity(person_uuid, require_active=False)
        refs = {person_uuid, person["spn"][0]}
        approved = bool(refs.intersection(_account_group().get("member", [])))
        active = active and approved and active_person(person)
        changed = 0

        for name in ADMISSION:
            entry = authorization_api(f"/v1/group/{name}")
            group = _entry_attrs(entry)

            require(
                group.get("name") == [name]
                and "group" in group.get("class", [])
                and not {"dyngroup", "recycled", "tombstone"}.intersection(
                    group.get("class", [])
                )
                and group.get("entry_managed_by") == [WORKERS + f"@{container.DOMAIN}"],
                "Club-admission group delegation changed",
            )

            group_uuid = _uuid(group.get("uuid", [None])[0])

            if bool(refs.intersection(group.get("member", []))) != active:
                _worker_api(
                    f"/v1/group/{group_uuid}/_attr/member",
                    method="POST" if active else "DELETE",
                    body=[person_uuid],
                )
                changed += 1

            after = _entry_attrs(authorization_api(f"/v1/group/{group_uuid}"))

            require(
                after.get("uuid") == [group_uuid]
                and bool(refs.intersection(after.get("member", []))) == active,
                "Annual club admission did not synchronize",
            )

        records = owned_people()

        for record in records.values():
            if record["uuid"] == person_uuid:
                record["admitted"] = active
        _write(PEOPLE, records)

    return {"uuid": person_uuid, "active": active, "changed": changed}


def _authorization_policy_groups() -> dict[str, Attrs]:
    observer = _entry_attrs(
        json_object(authorization_api("/v1/self")).get("youare", {})
    )

    require(
        observer.get("uuid") == [configuration().get("authorization_uuid")]
        and all(
            role + f"@{container.DOMAIN}" in observer.get("memberof", [])
            for role in AUTHORIZATION_READ_ROLES
        ),
        "Native policy read permissions are unavailable",
    )

    entries = authorization_api("/v1/group")

    if not is_list(entries):
        raise RuntimeError("Native group policy metadata is unavailable")

    groups: dict[str, Attrs] = {}

    for entry in entries:
        attrs = _entry_attrs(entry)
        spn = attrs.get("spn", [None])[0]

        if (
            "group" not in attrs.get("class", [])
            or not isinstance(spn, str)
            or spn in groups
        ):
            raise RuntimeError(
                "Native group policy identity or class metadata is unavailable"
            )

        require(
            isinstance(attrs.get("uuid"), list) and len(attrs["uuid"]) == 1,
            "Native group policy UUID is unavailable",
        )

        _uuid(attrs["uuid"][0])
        groups[spn] = attrs

    return groups


def _effective_privileged_policy(
    person: Attrs,
    prospective_role: str | None = None,
    groups: dict[str, Attrs] | None = None,
) -> CredentialPolicy:
    groups = _authorization_policy_groups() if groups is None else groups
    memberships = set(person["memberof"])

    if prospective_role is not None:
        require(prospective_role in PRIVILEGED_ROLE_GROUPS, "Unknown prospective role")
        pending = [
            prospective_role + f"@{container.DOMAIN}",
            HIGH_PRIVILEGE + f"@{container.DOMAIN}",
        ]

        while pending:
            spn = pending.pop()

            if spn in memberships:
                continue

            require(spn in groups, "Prospective native group policy is unavailable")
            memberships.add(spn)
            pending.extend(groups[spn].get("memberof", []))

    require(
        PRIVILEGED_POLICY + f"@{container.DOMAIN}" in memberships,
        "The privileged account policy is not inherited",
    )

    minimum = "mfa"
    attestation_required = False

    for spn in memberships:
        require(spn in groups, "Inherited native group policy metadata is unavailable")

        group = groups[spn]

        if "account_policy" not in group["class"]:
            require(
                spn != PRIVILEGED_POLICY + f"@{container.DOMAIN}",
                "Privileged policy class is absent",
            )
            continue

        values = group.get("credential_type_minimum")

        if values is None:
            value = "any"
        else:
            require(
                len(values) == 1 and values[0] in CREDENTIAL_STRENGTH,
                "Native credential policy minimum is absent or unrecognized",
            )
            value = values[0]

        if spn == PRIVILEGED_POLICY + f"@{container.DOMAIN}":
            require(
                CREDENTIAL_STRENGTH.index(value) >= CREDENTIAL_STRENGTH.index("mfa"),
                "Privileged credential policy is weaker than MFA",
            )

        if CREDENTIAL_STRENGTH.index(value) > CREDENTIAL_STRENGTH.index(minimum):
            minimum = value
        attestation_required |= "webauthn_attestation_ca_list" in group

    return {"minimum": minimum, "attestation_required": attestation_required}


def _mfa_ready(person: object, credential_status: object, policy: object) -> bool:
    if not is_object_dict(policy):
        raise RuntimeError("Effective native credential policy is unavailable")

    minimum = policy.get("minimum")

    if (
        not isinstance(minimum, str)
        or minimum not in CREDENTIAL_STRENGTH
        or not isinstance(policy.get("attestation_required"), bool)
    ):
        raise RuntimeError("Effective native credential policy is unavailable")

    if policy["attestation_required"] or minimum not in ("mfa", "passkey"):
        return False  # summaries cannot prove attestation allowlist compliance

    if not is_object_dict(credential_status):
        raise RuntimeError("Native credential readiness is unavailable")

    credentials = credential_status.get("creds")

    if not is_list(credentials):
        raise RuntimeError("Native credential readiness is unavailable")

    if not credentials:
        attributes = _entry_attrs({"attrs": person})
        return not attributes.get("primary_credential") and bool(
            attributes.get("passkeys") or attributes.get("attested_passkeys")
        )

    if len(credentials) != 1 or not is_object_dict(credentials[0]):
        return False

    kind = credentials[0].get("type_")

    if not is_object_dict(kind) or len(kind) != 1:
        return False

    if "Passkey" in kind:
        return False  # legacy primary webauthn cannot authenticate on 1.11.2

    factors = kind.get("PasswordMfa")

    if not is_list(factors) or len(factors) != 3:
        return False

    return (
        minimum == "mfa"
        and is_str_list(factors[0])
        and is_str_list(factors[1])
        and type(factors[2]) is int
        and factors[2] >= 0
        and bool(factors[0] or factors[1])
    )


def privileged_account_ready(person_uuid: str) -> bool:
    person = _authorization_person(person_uuid)

    if (
        not _privileged_membership(person)
        or HIGH_PRIVILEGE + f"@{container.DOMAIN}" not in person["memberof"]
        or not active_person(person)
    ):
        return False

    return _mfa_ready(
        person,
        authorization_api(f"/v1/person/{person_uuid}/_credential/_status"),
        _effective_privileged_policy(person),
    )


def _person(person_uuid: str) -> Attrs:
    entry = _worker_api(f"/v1/person/{_uuid(person_uuid)}")
    return _entry_attrs(entry)


def _wait_for_posix(person_uuid: str, username: str, timeout: float = 8) -> None:
    deadline = time.monotonic() + timeout
    while True:
        attrs = _person(person_uuid)
        require(
            attrs.get("uuid") == [person_uuid] and attrs.get("name") == [username],
            "Owned account identity changed while waiting for POSIX provisioning",
        )

        if "posixaccount" in attrs.get("class", []):
            return

        require(
            time.monotonic() < deadline,
            "Account setup is waiting for POSIX provisioning. Try again.",
        )
        time.sleep(0.25)


def _owned(person_uuid: str) -> OwnedPerson:
    person_uuid = _uuid(person_uuid)
    matches = [
        record for record in owned_people().values() if record["uuid"] == person_uuid
    ]

    require(len(matches) == 1, "The enrollment service does not own this person")

    require(
        matches[0].get("created"), "The enrollment account has not been provisioned"
    )

    return matches[0]


def _apply_credential_policy() -> list[str]:
    container.require_native_credential_compare()
    groups = [
        native_attrs(value)
        for value in json_array(
            json.loads(container.cli("group", "list", "--output", "json").stdout)
        )
    ]
    managers = {
        manager for attrs in groups for manager in attrs.get("entry_managed_by", [])
    }
    unlisted = {
        attrs["name"][0]
        for attrs in groups
        if attrs.get("name")
        and attrs["name"][0].startswith("team_")
        and attrs["name"][0].endswith("_leads")
        and attrs.get("spn", [None])[0] in managers
        and attrs["name"][0] not in PRIVILEGED_ROLE_GROUPS
    }

    require(
        not unlisted, "A delegated manager is missing from the privileged role manifest"
    )

    privileged = {HIGH_PRIVILEGE, *PRIVILEGED_ROLE_GROUPS}

    require(
        all(_attrs("group", name).get("uuid") for name in privileged),
        "A privileged account-policy group is absent",
    )

    if not container.entry_exists("group", PRIVILEGED_POLICY):
        container.cli("group", "create", PRIVILEGED_POLICY, "idm_admin")
        container.cli(
            "group",
            "set-description",
            PRIVILEGED_POLICY,
            "MFA policy for directory administrators, club officers and delegated "
            "group managers",
        )

    policy = _attrs("group", PRIVILEGED_POLICY)

    require(
        policy.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"],
        "Privileged account-policy group has an unexpected manager",
    )

    if "account_policy" not in policy.get("class", []):
        container.cli("group", "account-policy", "enable", PRIVILEGED_POLICY)

    strength = CREDENTIAL_STRENGTH
    minimum = policy.get("credential_type_minimum", ["any"])[0]

    require(minimum in strength, "Privileged credential policy is unrecognized")

    if strength.index(minimum) < strength.index("mfa"):
        container.cli(
            "group",
            "account-policy",
            "credential-type-minimum",
            PRIVILEGED_POLICY,
            "mfa",
        )

    missing = sorted(
        name
        for name in privileged
        if name + f"@{container.DOMAIN}" not in policy.get("member", [])
    )

    if missing:
        container.cli("group", "add-members", PRIVILEGED_POLICY, *missing)

    policy = _attrs("group", PRIVILEGED_POLICY)

    require(
        "account_policy" in policy.get("class", [])
        and policy.get("credential_type_minimum", [None])[0] in strength[2:]
        and all(
            name + f"@{container.DOMAIN}" in policy.get("member", [])
            for name in privileged
        ),
        "Privileged credential requirements did not take effect",
    )

    protected = _attrs("group", HIGH_PRIVILEGE)
    missing_protection = [
        role
        for role in PRIVILEGED_ROLE_GROUPS
        if role + f"@{container.DOMAIN}" not in protected.get("member", [])
    ]

    if missing_protection:
        container.cli(
            "group", "add-members", HIGH_PRIVILEGE, *missing_protection, name="admin"
        )

    protected = _attrs("group", HIGH_PRIVILEGE)

    require(
        all(
            role + f"@{container.DOMAIN}" in protected.get("member", [])
            for role in PRIVILEGED_ROLE_GROUPS
        ),
        "Native privileged-account reset protection did not take effect",
    )

    baseline = _attrs("group", "idm_all_persons")

    require(
        "account_policy" in baseline.get("class", []),
        "Default person account policy is absent",
    )

    if baseline.get("credential_type_minimum") != ["any"]:
        container.cli(
            "group",
            "account-policy",
            "credential-type-minimum",
            "idm_all_persons",
            "any",
        )

    require(
        _attrs("group", "idm_all_persons").get("credential_type_minimum") == ["any"],
        "Default password-only credential policy did not take effect",
    )

    return sorted(privileged)


def _bootstrap_authorization(current: EnrollmentConfig) -> None:
    if not container.entry_exists("service-account", AUTHORIZER):
        container.cli(
            "service-account",
            "create",
            AUTHORIZER,
            "Read-only protected-person authorization observer",
            "idm_admin",
        )

    service = _attrs("service-account", AUTHORIZER)

    require(
        service.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"],
        "Authorization observer has an unexpected manager",
    )

    require(
        not current.get("authorization_uuid")
        or current.get("authorization_uuid") == service.get("uuid", [None])[0],
        "Authorization observer changed identity",
    )

    for role in AUTHORIZATION_READ_ROLES:
        actor = "admin" if role == "idm_access_control_admins" else "idm_admin"
        container.cli("group", "add-members", role, AUTHORIZER, name=actor)

    if not current.get("authorization_token"):
        expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat(timespec="seconds")
        result = container.cli(
            "service-account",
            "api-token",
            "generate",
            AUTHORIZER,
            "Read-only authorization observer, expires after 30 days",
            expiry,
            "--output",
            "json",
        )
        token = json_object(json.loads(result.stdout)).get("result")

        if not isinstance(token, str) or not token.startswith("eyJ"):
            raise RuntimeError(
                "Unexpected authorization token format, token was not printed"
            )

        current.update(
            {
                "authorization_token": token,
                "authorization_token_expiry": expiry,
            }
        )

    current["authorization_uuid"] = service["uuid"][0]
    _write(CONFIG, current)


def privileged_readiness() -> PrivilegedReadiness:
    entries = authorization_api("/v1/person")

    if not is_list(entries):
        raise RuntimeError("Authorization person listing is unavailable")

    policy_groups = _authorization_policy_groups()
    accounts: list[PrivilegedAccount] = []

    for entry in entries:
        person = _entry_attrs(entry)
        require("memberof" in person, "Authorization memberships are unavailable")

        if not _privileged_membership(person):
            continue

        person_uuid = _uuid(person.get("uuid", [None])[0])
        policy = _effective_privileged_policy(person, groups=policy_groups)
        accounts.append(
            {
                "uuid": person_uuid,
                "username": person.get("name", [None])[0],
                "protected": HIGH_PRIVILEGE + f"@{container.DOMAIN}"
                in person["memberof"],
                "active": active_person(person),
                "credential_minimum": policy["minimum"],
                "attestation_verification_required": policy["attestation_required"]
                or policy["minimum"].startswith("attested_"),
                "mfa_ready": _mfa_ready(
                    person,
                    authorization_api(f"/v1/person/{person_uuid}/_credential/_status"),
                    policy,
                ),
                "roles": sorted(
                    role
                    for role in PRIVILEGED_ROLE_GROUPS
                    if role + f"@{container.DOMAIN}" in person["memberof"]
                ),
            }
        )

    return {
        "ready": bool(accounts)
        and all(
            account["protected"] and account["mfa_ready"] and account["active"]
            for account in accounts
        ),
        "accounts": sorted(accounts, key=lambda account: account["username"] or ""),
        "role_manifest": list(PRIVILEGED_ROLE_GROUPS),
    }


def activate_privileged_role(person_uuid: str, role: str) -> ActivatedRole:
    require(
        role in PRIVILEGED_ROLE_GROUPS, "Role is absent from the privileged manifest"
    )
    person_uuid = _uuid(person_uuid)
    container.require_native_credential_compare()

    with _locked():
        container.cli("login")
        _apply_credential_policy()
        person = _authorization_person(person_uuid)

        require(
            active_person(person)
            and _mfa_ready(
                person,
                authorization_api(f"/v1/person/{person_uuid}/_credential/_status"),
                _effective_privileged_policy(person, prospective_role=role),
            ),
            "Enroll and save a passkey or password plus MFA before role activation",
        )

        container.cli("group", "add-members", HIGH_PRIVILEGE, person_uuid, name="admin")

        require(
            privileged_account_ready(person_uuid),
            "Protected MFA readiness changed before role activation",
        )

        container.cli("group", "add-members", role, person_uuid)

        require(
            role + f"@{container.DOMAIN}"
            in _authorization_person(person_uuid)["memberof"],
            "Privileged role activation did not take effect",
        )

    return {"uuid": person_uuid, "role": role, "protected": True}


def bootstrap() -> BootstrapReport:
    with _locked():
        container.ready()
        container.require_native_credential_compare()
        container.cli("login")

        for policy_group in (
            "idm_people_self_name_write",
            "idm_people_self_mail_write",
        ):
            require(
                not _attrs("group", policy_group).get("member"),
                "The locked username/name/email enrollment policy is not in effect",
            )
        for group in ADMISSION:
            require(
                bool(_attrs("group", group).get("uuid")),
                f"Admission group {group} is absent",
            )

        privileged_policy_groups = _apply_credential_policy()

        if not container.entry_exists("group", WORKERS):
            container.cli("group", "create", WORKERS, "idm_admin")
            container.cli(
                "group",
                "set-description",
                WORKERS,
                "Enrollment service, provisions accounts and membership",
            )

        workers = _attrs("group", WORKERS)

        require(
            workers.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"],
            "Existing enrollment worker group has an unexpected manager",
        )

        if not container.entry_exists("service-account", WORKER):
            container.cli(
                "service-account",
                "create",
                WORKER,
                "One-time enrollment service",
                "idm_admin",
            )

        service = _attrs("service-account", WORKER)

        require(
            service.get("entry_managed_by") == [f"idm_admin@{container.DOMAIN}"],
            "Existing enrollment service account has an unexpected manager",
        )

        current: EnrollmentConfig = configuration() if CONFIG.is_file() else {}

        if current:
            require(
                current.get("worker_uuid") == service.get("uuid", [None])[0],
                "Existing enrollment principal changed identity",
            )

        current["worker_uuid"] = service["uuid"][0]
        _bootstrap_authorization(current)
        container.cli("group", "add-members", WORKERS, WORKER)
        container.cli("group", "add-members", "idm_people_on_boarding", WORKER)

        for group in ADMISSION:
            attrs = _attrs("group", group)
            manager = attrs.get("entry_managed_by", [])

            if manager == [WORKERS + f"@{container.DOMAIN}"]:
                continue

            require(
                not manager,
                f"Existing admission-group manager for {group} requires review",
            )

            container.cli("group", "set-entry-manager", group, WORKERS, name="admin")

            require(
                _attrs("group", group).get("entry_managed_by")
                == [WORKERS + f"@{container.DOMAIN}"],
                f"Delegation of {group} did not take effect",
            )

        if not current.get("worker_token"):
            expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat(
                timespec="seconds"
            )
            result = container.cli(
                "service-account",
                "api-token",
                "generate",
                WORKER,
                "Enrollment service, expires after 30 days",
                expiry,
                "--readwrite",
                "--output",
                "json",
            )
            token = json_object(json.loads(result.stdout)).get("result")

            if not isinstance(token, str) or not token.startswith("eyJ"):
                raise RuntimeError(
                    "Unexpected enrollment service token format, token was not printed"
                )

            current.update(
                {
                    "worker_token": token,
                    "worker_token_expiry": expiry,
                }
            )

        _write(
            CONFIG, current
        )  # later bootstrap failures must not discard capabilities

        _worker_api(f"/v1/group/{ADMISSION[0]}")

    return {
        "config_path": str(CONFIG),
        "worker_account": WORKER,
        "delegated_groups": list(ADMISSION),
        "password_only_default": True,
        "mfa_policy_groups": privileged_policy_groups,
        "native_protected_roles": list(PRIVILEGED_ROLE_GROUPS),
        "privileged_readiness": privileged_readiness(),
    }


def provision_person(
    request_id: object,
    person_uuid: object,
    username: object,
    display_name: object,
    email: object,
) -> str:
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise RuntimeError("An enrollment request ID is required")

    person_uuid = _uuid(person_uuid)

    if (
        not isinstance(username, str)
        or not USERNAME.fullmatch(username)
        or username in RESERVED
        or username.startswith(("idm_", "system_", "identity_"))
    ):
        raise RuntimeError(
            "Choose an available lowercase username of 3 to 32 letters, digits, underscores or hyphens"
        )

    if not isinstance(display_name, str) or not 1 <= len(display_name) <= 256:
        raise RuntimeError("The verified display name is required")

    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 254
        or "@" not in email
        or any(ord(char) < 32 for char in email)
    ):
        raise RuntimeError("A verified contact email is required")

    expected: OwnedProfile = {
        "uuid": person_uuid,
        "name": username,
        "displayname": display_name,
        "mail": email,
    }

    with _locked():
        records = owned_people()
        record = records.get(request_id)

        if record is not None:
            require(
                all(record.get(key) == value for key, value in expected.items()),
                "Enrollment request identity or verified profile changed",
            )
        else:
            require(
                not any(
                    item["uuid"] == person_uuid or item["name"] == username
                    for item in records.values()
                ),
                "Another enrollment request owns this account",
            )

            require(
                not _person(person_uuid),
                "The requested UUID already belongs to a directory account",
            )
            record = OwnedPerson(
                uuid=person_uuid,
                name=username,
                displayname=display_name,
                mail=email,
                created=False,
                create_attempted=False,
                admitted=False,
            )
            records[request_id] = record
            _write(PEOPLE, records)

        actual = _person(person_uuid)

        if not actual:
            require(
                not record["created"],
                "An owned account disappeared, recovery requires administrator review",
            )

            record["create_attempted"] = True
            _write(PEOPLE, records)
            attrs = {
                "uuid": [person_uuid],
                "name": [username],
                "displayname": [display_name],
                "mail": [email],
            }
            _worker_api("/v1/person", method="POST", body={"attrs": attrs})
            actual = _person(person_uuid)

        require(
            record["create_attempted"]
            and actual.get("uuid") == [person_uuid]
            and actual.get("name") == [username],
            "Owned Kanidm account does not match its enrollment record",
        )

        for key, expected_value in (("displayname", display_name), ("mail", email)):
            if key not in actual:  # native onboarding may hide displayname and mail
                continue

            require(
                actual[key] == [expected_value],
                "Frozen Kanidm account profile does not match its enrollment record",
            )

        require(
            not actual.get("account_expire"),
            "Owned enrollment account unexpectedly has an expiry",
        )

        _wait_for_posix(person_uuid, username)
        record["created"] = True
        _write(PEOPLE, records)

    return person_uuid


def account_status(person_uuid: str) -> AccountStatus:
    record = _owned(person_uuid)
    attrs = _person(person_uuid)

    require(
        attrs.get("uuid") == [person_uuid] and attrs.get("name") == [record["name"]],
        "Owned Kanidm account disappeared or changed identity",
    )

    expired = any(
        _date(value) <= datetime.now(UTC) for value in attrs.get("account_expire", [])
    )
    not_yet_valid = any(
        _date(value) > datetime.now(UTC)
        for value in attrs.get("account_valid_from", [])
    )
    passkey_present = bool(attrs.get("passkeys") or attrs.get("attested_passkeys"))
    credential_present = passkey_present or bool(attrs.get("primary_credential"))
    admitted = False

    if record["admitted"] and credential_present:
        spn = attrs.get("spn", [None])[0]
        admitted = isinstance(spn, str) and all(
            spn in _entry_attrs(_worker_api(f"/v1/group/{group}")).get("member", [])
            for group in ADMISSION
        )

    approved = False

    if credential_present:
        group = _account_group()
        approved = bool(
            {person_uuid, attrs.get("spn", [None])[0]}.intersection(
                group.get("member", [])
            )
        )

    return {
        "uuid": person_uuid,
        "username": record["name"],
        "provisioned": True,
        "credential_present": credential_present,
        "passkey_present": passkey_present,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "admitted": admitted,
        "approved": approved,
        "status": "expired" if expired else "active" if approved else "setup_required",
    }


class CredentialValidationError(RuntimeError):
    def __init__(
        self, message: str, *, restart: bool = False, state: str | None = None
    ) -> None:
        super().__init__(message)
        self.restart = restart
        self.state = state


@contextmanager
def _credential_errors() -> Generator[None]:
    try:
        yield
    except CredentialValidationError:
        raise
    except RuntimeError, OSError, ValueError:
        raise CredentialValidationError(
            "Account setup is unavailable. Try again."
        ) from None


def _credential_error(error: object) -> CredentialValidationError:
    feedback_items = error.get("passwordquality") if is_object_dict(error) else None

    if is_list(feedback_items):
        for feedback in feedback_items:
            if is_object_dict(feedback):
                minimum = feedback.get("tooshort")
                maximum = feedback.get("toolong")

                if isinstance(minimum, int) and 1 <= minimum <= 4096:
                    return CredentialValidationError(
                        f"Use at least {minimum} characters for your password."
                    )

                if isinstance(maximum, int) and 1 <= maximum <= 4096:
                    return CredentialValidationError(
                        f"Use no more than {maximum} characters for your password."
                    )

            if feedback == "badlisted":
                return CredentialValidationError(
                    "Choose a password that has not appeared in password leaks."
                )

            if feedback == "dontreusepasswords":
                return CredentialValidationError(
                    "Choose a password you have not used for this account."
                )

        return CredentialValidationError(
            "Use a stronger password, such as several unrelated words."
        )

    if error in (
        "sessionexpired",
        "invalidstate",
        "cu0005intenttokenconflict",
        "cu0006intenttokeninvalidated",
    ):
        return CredentialValidationError(
            "Your setup session expired. Start again.", restart=True
        )

    return CredentialValidationError("Account setup is unavailable. Try again.")


def _credential_api(action: str, body: object) -> object:
    request = urllib.request.Request(
        container.URL + "/v1/credential/_" + action,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with container.opener().open(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            native_error = json.load(error)
        except ValueError, OSError:
            native_error = None
        raise _credential_error(native_error) from None
    except urllib.error.URLError, OSError, ValueError:
        raise CredentialValidationError(
            "Account setup is unavailable. Try again."
        ) from None


def _credential_person(person_uuid: str, recovery: bool) -> str:
    record = _owned(person_uuid)

    require(
        not _privileged_membership(_authorization_person(person_uuid)),
        "Privileged accounts require administrator-assisted credential recovery",
    )

    status = account_status(person_uuid)

    require(
        not status["expired"] and not status["not_yet_valid"],
        "This account is not currently eligible for setup or recovery",
    )

    if recovery:
        require(
            status["approved"] and status["credential_present"],
            "Recovery requires an active approved account",
        )
    else:
        require(
            not status["credential_present"] and not status["admitted"],
            "Existing accounts must use the separately authorized recovery process",
        )

    person = _person(person_uuid)

    require(
        person.get("uuid") == [person_uuid] and person.get("name") == [record["name"]],
        "Owned account identity changed during credential setup",
    )

    spn = person.get("spn", [None])[0]

    if not isinstance(spn, str) or not spn:
        raise RuntimeError("Owned account SPN is absent")

    return spn


def _credential_session(person_uuid: str, session: object) -> str:
    if not is_object_dict(session):
        raise RuntimeError("Credential session does not belong to this person")

    recovery = session.get("recovery")
    token = session.get("token")

    if (
        session.get("person_uuid") != _uuid(person_uuid)
        or not isinstance(token, str)
        or not token
        or not isinstance(recovery, bool)
    ):
        raise RuntimeError("Credential session does not belong to this person")

    expiry = session.get("expires_at")

    if not isinstance(expiry, int) or expiry <= datetime.now(UTC).timestamp():
        raise CredentialValidationError(
            "Your setup session expired. Start again.", restart=True
        )

    return _credential_person(person_uuid, recovery)


def _is_credential_status(value: object) -> TypeGuard[CredentialStatus]:
    return (
        is_object_dict(value)
        and isinstance(value.get("spn"), str)
        and isinstance(value.get("primary_state"), str)
        and ("can_commit" not in value or isinstance(value["can_commit"], bool))
        and ("warnings" not in value or is_list(value["warnings"]))
    )


def _credential_status_matches(status: object, spn: str) -> CredentialStatus:
    if (
        not _is_credential_status(status)
        or status["spn"] != spn
        or status["primary_state"] != "Modifiable"
    ):
        raise RuntimeError("Credential session identity or permissions changed")

    return status


def begin_credentials(person_uuid: str, recovery: object = False) -> CredentialSession:
    if not isinstance(recovery, bool):
        raise RuntimeError("Credential recovery mode must be explicit")

    with _credential_errors(), _locked():
        container.require_native_credential_compare()
        spn = _credential_person(person_uuid, recovery)
        intent = _worker_api(f"/v1/person/{person_uuid}/_credential/_update_intent/600")

        if not is_object_dict(intent):
            raise RuntimeError("Kanidm did not return a credential setup capability")

        intent_token = intent.get("token")

        if not isinstance(intent_token, str) or not intent_token:
            raise RuntimeError("Kanidm did not return a credential setup capability")

        exchanged = _credential_api("exchange_intent", intent_token)

        if (
            not is_list(exchanged)
            or len(exchanged) != 2
            or not is_object_dict(exchanged[0])
        ):
            raise RuntimeError("Kanidm did not return a credential session")

        token = exchanged[0].get("token")

        if not isinstance(token, str) or not token:
            raise RuntimeError("Kanidm did not return a credential session")

        _credential_status_matches(exchanged[1], spn)
        return {
            "token": token,
            "expires_at": int(datetime.now(UTC).timestamp()) + 890,
            "person_uuid": person_uuid,
            "recovery": recovery,
        }


def credential_status(person_uuid: str, session: CredentialSession) -> CredentialStatus:
    with _credential_errors(), _locked():
        spn = _credential_session(person_uuid, session)
        status = _credential_api("status", {"token": session["token"]})
        return _credential_status_matches(status, spn)


def _credential_update(
    person_uuid: str, session: CredentialSession, action: object
) -> CredentialStatus:
    spn = _credential_session(person_uuid, session)
    status = _credential_api("status", {"token": session["token"]})
    _credential_status_matches(status, spn)
    return _credential_status_matches(
        _credential_api("update", [action, {"token": session["token"]}]), spn
    )


def set_password(
    person_uuid: str,
    session: CredentialSession,
    password: object,
    replace_primary: object = False,
) -> CredentialStatus:
    if not isinstance(password, str) or not 1 <= len(password) <= 4096:
        raise CredentialValidationError("Enter a password of up to 4096 characters.")

    if not isinstance(replace_primary, bool):
        raise RuntimeError("Primary replacement must be explicit")

    with _credential_errors(), _locked():
        _credential_session(person_uuid, session)

        if replace_primary:
            require(session["recovery"], "Primary replacement requires recovery")

        if replace_primary and not session.get("primary_replaced"):
            _credential_update(person_uuid, session, "primaryremove")
            session["primary_replaced"] = True

        return _credential_update(person_uuid, session, {"password": password})


def generate_totp(person_uuid: str, session: CredentialSession) -> CredentialStatus:
    with _credential_errors(), _locked():
        return _credential_update(person_uuid, session, "totpgenerate")


def verify_totp(
    person_uuid: str,
    session: CredentialSession,
    code: object,
    label: object = "Authenticator",
) -> CredentialStatus:
    if not isinstance(code, str) or re.fullmatch(r"[0-9]{6}", code) is None:
        raise CredentialValidationError(
            "Enter the six-digit code from your authenticator."
        )

    if (
        not isinstance(label, str)
        or not 1 <= len(label.strip()) <= 64
        or any(ord(char) < 32 for char in label)
    ):
        raise RuntimeError("An authenticator label is required")

    with _credential_errors(), _locked():
        status = _credential_update(
            person_uuid, session, {"totpverify": [int(code), label]}
        )
        state = status.get("mfaregstate")

        if state == "TotpTryAgain":
            raise CredentialValidationError("That code did not match. Try again.")

        if state == "TotpInvalidSha1":
            raise CredentialValidationError(
                "Your authenticator uses SHA1 codes. Confirm compatibility to "
                "continue.",
                state="TotpInvalidSha1",
            )

        if isinstance(state, dict) and "TotpNameTryAgain" in state:
            raise CredentialValidationError("Choose a different authenticator label.")

        require(state == "None", "Authenticator verification is incomplete")

        return status


def accept_totp_sha1(person_uuid: str, session: CredentialSession) -> CredentialStatus:
    with _credential_errors(), _locked():
        spn = _credential_session(person_uuid, session)
        status = _credential_status_matches(
            _credential_api("status", {"token": session["token"]}), spn
        )

        require(
            status.get("mfaregstate") == "TotpInvalidSha1",
            "No authenticator compatibility acknowledgement is pending",
        )

        return _credential_update(person_uuid, session, "totpacceptsha1")


def commit_credentials(person_uuid: str, session: CredentialSession) -> AccountStatus:
    with _credential_errors(), _locked():
        container.require_native_credential_compare()
        spn = _credential_session(person_uuid, session)
        status = _credential_status_matches(
            _credential_api("status", {"token": session["token"]}), spn
        )

        if not status.get("can_commit") or status.get("warnings"):
            raise CredentialValidationError(
                "Finish setting up your authenticator first."
            )

        _credential_api("commit", {"token": session["token"]})
        json_object(session).clear()
        return account_status(person_uuid)


def complete_credentials(person_uuid: str) -> AccountStatus:
    with _locked():
        status = account_status(person_uuid)
        require(
            status["credential_present"]
            and not status["expired"]
            and not status["not_yet_valid"],
            "A committed credential is required before account approval",
        )

        person = _person(person_uuid)
        spn = person.get("spn", [None])[0]

        if not isinstance(spn, str):
            raise RuntimeError("Owned account SPN is absent")

        group = _account_group()

        if not {person_uuid, spn}.intersection(group.get("member", [])):
            _worker_api(
                f"/v1/group/{group['uuid'][0]}/_attr/member",
                method="POST",
                body=[person_uuid],
            )

        approved_account(person_uuid)

    return account_status(person_uuid)


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(bootstrap(), indent=2))
