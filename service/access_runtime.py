import argparse
import json
import os
import re
import time
import urllib.error
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import NotRequired, TypedDict

from flask import has_request_context, request

import access
import enrollment_kanidm
import membership
import operations
from contracts import (
    JSONObject,
    NativeAttrs,
    ProductionRuntime,
    is_list,
    is_object_dict,
    is_str_list,
    json_array,
    json_object,
    json_string,
    native_attrs,
)
from native_names import native_name
from runtime_view import runtime as container


class PolicyConfig(TypedDict):
    group_uuid: str
    leads_group_uuid: str
    name: str
    max_days: int
    include_leads: bool


class AccessConfig(TypedDict):
    service_name: str
    service_uuid: str
    controller_group_uuid: str
    admission_group_uuid: str
    policies: list[PolicyConfig]
    protected_group_uuids: list[str]
    token: NotRequired[str]
    token_expiry: NotRequired[str]
    token_id: NotRequired[str]


class Arguments(argparse.Namespace):
    command: str
    actor: str
    team: str
    loop: bool


DIRECTORY = container.STATE / "access"
CONFIG = DIRECTORY / "config.json"
OIDC_CONFIG = DIRECTORY / "oidc.json"
DATABASE = DIRECTORY / "grants.sqlite3"
STATUS = DIRECTORY / "status.json"
SERVICE = native_name("membership_controller", container)
WORKERS = native_name("membership_controllers", container)
CLIENT = native_name("account_portal", container)
CALLBACK = container.PORTAL_URL + "/access/callback"


def membership_store() -> membership.MembershipStore:
    return membership.MembershipStore(
        container.STATE / "enrollment" / "enrollment.sqlite3"
    )


@dataclass(frozen=True)
class _RequestMembership:
    active: frozenset[str]


def _request_membership() -> _RequestMembership | None:
    if (
        not has_request_context()
        or request.method != "GET"
        or request.path not in {"/access", "/access/groups", "/access/members"}
    ):
        return None

    saved = request.environ.get("identity.membership_eligibility")

    if not isinstance(saved, _RequestMembership):
        saved = _RequestMembership(membership_store().active_people())
        request.environ["identity.membership_eligibility"] = saved
    return saved


def load(path: Path) -> JSONObject:
    try:
        value = json_object(json.loads(path.read_text()))

        if path.is_symlink():
            raise ValueError

        if path.stat().st_mode & 0o077:
            raise ValueError

        return value
    except (OSError, ValueError, TypeError) as error:
        raise access.AccessUnavailable("access_configuration_unavailable") from error


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    operations.write_private(path, value)


def configuration() -> tuple[AccessConfig, list[access.TeamPolicy]]:
    value = load(CONFIG)

    try:
        if value.get("service_name") != SERVICE:
            raise ValueError

        policies: list[access.TeamPolicy] = []
        configs: list[PolicyConfig] = []

        for item in json_array(value["policies"]):
            entry = json_object(item)
            max_days = entry["max_days"]

            if type(max_days) is not int:
                raise ValueError

            include_leads = entry.get("include_leads", False)

            if type(include_leads) is not bool:
                raise ValueError

            policy = access.TeamPolicy(
                access.canonical_uuid(entry["group_uuid"]),
                access.canonical_uuid(entry["leads_group_uuid"]),
                json_string(entry["name"]),
                max_days,
                include_leads,
            )
            policies.append(policy)
            configs.append(
                {
                    "group_uuid": policy.group_uuid,
                    "leads_group_uuid": policy.leads_group_uuid,
                    "name": policy.name,
                    "max_days": policy.max_days,
                    "include_leads": policy.include_leads,
                }
            )

        protected = value["protected_group_uuids"]

        if not is_str_list(protected):
            raise ValueError

        config: AccessConfig = {
            "service_name": SERVICE,
            "service_uuid": access.canonical_uuid(value["service_uuid"]),
            "controller_group_uuid": access.canonical_uuid(
                value["controller_group_uuid"]
            ),
            "admission_group_uuid": access.canonical_uuid(
                value["admission_group_uuid"]
            ),
            "policies": configs,
            "protected_group_uuids": [
                access.canonical_uuid(item) for item in protected
            ],
        }

        for field in ("token", "token_expiry", "token_id"):
            if field in value:
                text = json_string(value[field])

                if field == "token":
                    config["token"] = text
                elif field == "token_expiry":
                    config["token_expiry"] = text
                else:
                    config["token_id"] = text

        return config, policies
    except (KeyError, TypeError, ValueError, access.AccessDenied) as error:
        raise access.AccessUnavailable("access_configuration_invalid") from error


def writer_api(path: str, method: str = "GET", body: object = None) -> object:
    config, policies = configuration()

    try:
        token = json_string(config.get("token"))
        claims = operations.claims(token)
        expiry = operations.timestamp(config.get("token_expiry"))

        if (
            claims.get("account_id") != config["service_uuid"]
            or claims.get("token_id") != config.get("token_id")
            or claims.get("purpose") != "readwrite"
            or claims.get("expiry") != expiry
            or expiry <= time.time()
        ):
            raise ValueError

        allowed = {f"/v1/group/{policy.group_uuid}/_attr/member" for policy in policies}

        if method not in {"POST", "DELETE"} or path not in allowed:
            raise access.AccessDenied("writer_operation_outside_scope")

        identity = container.api("/v1/self", token)
        attrs = access.entry_attrs(
            identity.get("youare") if is_object_dict(identity) else None
        )
        permitted = {
            f"{WORKERS}@{container.DOMAIN}",
            f"idm_all_accounts@{container.DOMAIN}",
        }

        if (
            attrs.get("uuid") != [config["service_uuid"]]
            or attrs.get("name") != [SERVICE]
            or not {"service_account", "account"}.issubset(attrs.get("class", []))
            or {"person", "group", "recycled", "tombstone"}.intersection(
                attrs.get("class", [])
            )
            or "memberof" not in attrs
            or not set(attrs["memberof"]).issubset(permitted)
            or f"{WORKERS}@{container.DOMAIN}" not in attrs["memberof"]
        ):
            raise access.AccessUnavailable("team_writer_privilege_changed")

        if not is_str_list(body) or len(body) != 1:
            raise access.AccessDenied("writer_single_member_required")

        reference = body[0]

        if method == "DELETE" and "@" in reference:
            name, _, domain = reference.partition("@")

            if domain != container.DOMAIN or not re.fullmatch(
                r"[a-z][a-z0-9_.-]{0,63}", name
            ):
                raise access.AccessDenied("writer_member_reference_invalid")
        else:
            access.canonical_uuid(reference)

        return container.api(path, token, method=method, body=body)
    except (KeyError, ValueError, TypeError, RuntimeError) as error:
        if isinstance(error, access.AccessDenied):
            raise

        raise access.AccessUnavailable("team_writer_unavailable") from error


def controller() -> access.Controller:
    config, policies = configuration()
    observer = load(enrollment_kanidm.CONFIG)
    store: membership.MembershipStore | None = None

    def annual_active(person_uuid: str) -> bool:
        nonlocal store
        registration = _request_membership()

        if registration is not None:
            return person_uuid in registration.active

        if store is None:
            store = membership_store()
        return store.active(person_uuid)

    try:
        backend = access.KanidmBackend(
            writer_api,
            read_api=enrollment_kanidm.authorization_read_api,
            reader_uuid=json_string(observer["authorization_uuid"]),
            reader_token=json_string(observer["authorization_token"]),
            domain=container.DOMAIN,
        )

        if isinstance(container, ProductionRuntime):
            container.prepare_private_directory(DIRECTORY)

        instance = access.Controller(
            DATABASE,
            backend,
            policies,
            config["admission_group_uuid"],
            config["controller_group_uuid"],
            protected_group_uuids=config["protected_group_uuids"],
            membership_active=annual_active,
            approval_group_uuid=access.canonical_uuid(observer["accounts_uuid"]),
        )

        protect_grant_files()
        return instance
    except (KeyError, ValueError, TypeError, access.AccessDenied) as error:
        raise access.AccessUnavailable("access_configuration_invalid") from error


def protect_grant_files() -> None:
    if not isinstance(container, ProductionRuntime):
        return

    for suffix in ("", ".lock", "-wal", "-shm"):
        path = DATABASE.with_name(DATABASE.name + suffix)

        if path.exists():
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                container.protect_private_file(descriptor, path)
            finally:
                os.close(descriptor)


def member_snapshot(person_uuid: str) -> access.AccessSnapshot:
    instance = controller()
    own = instance.own_access(person_uuid)
    person = instance.backend.person(person_uuid)

    if person is None or person.get("uuid") != [person_uuid]:
        raise access.AccessUnavailable("native_person_identity_changed")

    groups: object = person.get("memberof")

    if not is_str_list(groups) or any(
        not group or len(group) > 512 for group in groups
    ):
        raise access.AccessUnavailable("native_memberships_unavailable")

    catalog: object = instance.backend.group_catalog()

    if not is_list(catalog):
        raise access.AccessUnavailable("native_group_metadata_unavailable")

    memberships: dict[str, access.GroupMembership] = {}
    references: dict[str, str] = {}

    for item in catalog:
        try:
            attrs = native_attrs(item)
        except ValueError as error:
            raise access.AccessUnavailable("native_group_metadata_invalid") from error

        identifiers, names, spns, classes = (
            access.Controller.refs(attrs, field)
            for field in ("uuid", "name", "spn", "class")
        )

        if (
            len(identifiers) != 1
            or len(names) != 1
            or len(spns) != 1
            or "group" not in classes
            or {"recycled", "tombstone"}.intersection(classes)
        ):
            raise access.AccessUnavailable("native_group_metadata_invalid")

        try:
            identifier = access.canonical_uuid(next(iter(identifiers)))
        except access.AccessDenied as error:
            raise access.AccessUnavailable("native_group_metadata_invalid") from error

        spn = next(iter(spns))

        if identifier in memberships or identifier in references or spn in references:
            raise access.AccessUnavailable("native_group_identity_ambiguous")

        descriptions = attrs.get("description", [])
        name = next(iter(names))
        memberships[identifier] = {
            "uuid": identifier,
            "name": name,
            "spn": spn,
            "description": descriptions[0] if descriptions else "",
            "system": uuid.UUID(identifier).int < access.NATIVE_UUID_LIMIT
            or "system" in classes,
            "present": False,
            "grant": None,
        }
        references[identifier] = references[spn] = identifier

    for reference in groups:
        if reference not in references:
            raise access.AccessUnavailable("native_membership_unresolved")

        memberships[references[reference]]["present"] = True

    for grant in own["teams"]:
        identifier = grant["team_uuid"]

        if (
            identifier not in memberships
            or memberships[identifier]["grant"] is not None
        ):
            raise access.AccessUnavailable("recorded_group_identity_invalid")

        memberships[identifier]["grant"] = grant

    visible = [
        membership
        for membership in memberships.values()
        if membership["present"] or membership["grant"] is not None
    ]
    return {
        **own,
        "groups": sorted(set(groups)),
        "memberships": sorted(
            visible,
            key=lambda entry: (
                not entry["present"],
                entry["name"].casefold(),
                entry["uuid"],
            ),
        ),
    }


def _attrs(kind: str, name: str) -> NativeAttrs | None:
    result = container.cli(kind, "get", name, "--output", "json").stdout.strip()

    if result == "No matching entries":
        return None

    value = access.entry_attrs(json.loads(result))

    if len(value.get("uuid", [])) != 1:
        raise access.AccessUnavailable("bootstrap_native_identity_invalid")

    access.canonical_uuid(value["uuid"][0])
    return value


def _oauth_attrs() -> NativeAttrs:
    result = container.cli(
        "system", "oauth2", "get", CLIENT, "--output", "json"
    ).stdout.strip()

    if result == "No matching entries":
        return {}

    entry = json.loads(result)

    if entry == "No matching entries":
        return {}

    return access.entry_attrs(entry)


def bootstrap() -> JSONObject:
    with operations.private_lock(DIRECTORY / "bootstrap.lock"):
        container.ready()
        container.require_native_credential_compare()
        container.cli("login")

        try:
            accounts_uuid = access.canonical_uuid(
                enrollment_kanidm.configuration().get("accounts_uuid")
            )
        except access.AccessDenied as error:
            raise access.AccessUnavailable(
                "approved_accounts_configuration_required"
            ) from error

        accounts = _attrs("group", enrollment_kanidm.ACCOUNTS)

        if accounts is None or accounts.get("uuid") != [accounts_uuid]:
            raise access.AccessUnavailable("approved_accounts_identity_changed")

        admin = f"idm_admin@{container.DOMAIN}"

        if not container.entry_exists("service-account", SERVICE):
            container.cli(
                "service-account",
                "create",
                SERVICE,
                "SlugSec group memberships",
                "idm_admin",
            )

        if not container.entry_exists("group", WORKERS):
            container.cli("group", "create", WORKERS, "idm_admin")
        service, workers = _attrs("service-account", SERVICE), _attrs("group", WORKERS)

        if service is None or workers is None:
            raise access.AccessUnavailable("bootstrap_native_identity_missing")

        if service.get("entry_managed_by") != [admin] or workers.get(
            "entry_managed_by"
        ) != [admin]:
            raise access.AccessUnavailable("controller_identity_manager_changed")

        existing_members = workers.get("member", [])

        if set(existing_members).difference(
            {service["uuid"][0], f"{SERVICE}@{container.DOMAIN}"}
        ):
            raise access.AccessUnavailable("controller_group_has_other_members")

        container.cli("group", "add-members", WORKERS, SERVICE)
        service = _attrs("service-account", SERVICE)

        if service is None:
            raise access.AccessUnavailable("bootstrap_native_identity_missing")

        permitted = {
            f"{WORKERS}@{container.DOMAIN}",
            f"idm_all_accounts@{container.DOMAIN}",
        }

        if set(service.get("memberof", [])).difference(permitted):
            raise access.AccessUnavailable("controller_has_unexpected_privilege")

        config = load(CONFIG) if CONFIG.exists() else {}
        teams = configuration()[0]["policies"] if config else []

        for policy in teams:
            team = _attrs("group", policy["group_uuid"])
            lead = _attrs("group", policy["leads_group_uuid"])

            if team is None or lead is None:
                raise access.AccessUnavailable("bootstrap_native_identity_missing")

            if lead.get("entry_managed_by") != [admin]:
                raise access.AccessUnavailable(
                    "lead_appointments_require_admin_manager"
                )

            if team.get("entry_managed_by") != [f"{WORKERS}@{container.DOMAIN}"]:
                raise access.AccessUnavailable("existing_team_manager_requires_review")

        admission = _attrs("group", enrollment_kanidm.ADMISSION[0])

        if admission is None:
            raise access.AccessUnavailable("bootstrap_native_identity_missing")

        protected: list[str] = []

        for name in enrollment_kanidm.PRIVILEGED_ROLE_GROUPS:
            attrs = _attrs("group", name)

            if attrs is None:
                raise access.AccessUnavailable("bootstrap_native_identity_missing")

            protected.append(attrs["uuid"][0])

        identity: dict[str, object] = {
            "service_name": SERVICE,
            "service_uuid": service["uuid"][0],
            "controller_group_uuid": workers["uuid"][0],
            "admission_group_uuid": admission["uuid"][0],
            "policies": teams,
            "protected_group_uuids": protected,
        }

        if config and any(config.get(key) != value for key, value in identity.items()):
            raise access.AccessUnavailable("existing_access_identity_changed")

        write(CONFIG, config | identity)

        client = _oauth_attrs()

        if not client:
            container.cli(
                "system",
                "oauth2",
                "create",
                CLIENT,
                "My SlugSec access",
                container.PORTAL_URL + "/access",
            )
            container.cli("system", "oauth2", "add-redirect-url", CLIENT, CALLBACK)
            container.cli("system", "oauth2", "enable-strict-redirect-url", CLIENT)
            container.cli("system", "oauth2", "enable-pkce", CLIENT)
            container.cli("system", "oauth2", "prefer-short-username", CLIENT)
            container.cli(
                "system",
                "oauth2",
                "update-scope-map",
                CLIENT,
                enrollment_kanidm.ACCOUNTS,
                "openid",
                "profile",
            )
            client = _oauth_attrs()

        expected_scope = (
            f'{enrollment_kanidm.ACCOUNTS}@{container.DOMAIN}: {{"openid", "profile"}}'
        )

        if (
            "oauth2_resource_server_basic" not in client.get("class", [])
            or client.get("oauth2_rs_origin_landing")
            != [container.PORTAL_URL + "/access"]
            or client.get("oauth2_rs_origin") != [CALLBACK]
            or client.get("oauth2_strict_redirect_uri") != ["true"]
            or client.get("oauth2_allow_insecure_client_disable_pkce", ["false"])
            != ["false"]
            or client.get("oauth2_rs_scope_map") != [expected_scope]
            or client.get("oauth2_jwt_legacy_crypto_enable", ["false"]) != ["false"]
        ):
            raise access.AccessUnavailable("access_oidc_configuration_changed")

        secret = container.cli(
            "system", "oauth2", "show-basic-secret", CLIENT
        ).stdout.strip()

        if not secret or any(char.isspace() for char in secret):
            raise access.AccessUnavailable("access_oidc_secret_invalid")

        old = load(OIDC_CONFIG) if OIDC_CONFIG.exists() else {}
        oauth = {"client_id": CLIENT, "client_secret": secret, "callback_url": CALLBACK}

        if old and old != oauth:
            raise access.AccessUnavailable("access_oidc_identity_changed")

        write(OIDC_CONFIG, oauth)

        return {
            "prepared": True,
            "token_required": not bool(config.get("token")),
            "teams": len(teams),
        }


def activate_group(actor_uuid: str, team_uuid: str) -> JSONObject:
    access.canonical_uuid(actor_uuid)
    access.canonical_uuid(team_uuid)

    if not enrollment_kanidm.privileged_account_ready(actor_uuid):
        raise access.AccessDenied("lead_mfa_required")

    with operations.private_lock(DIRECTORY / "bootstrap.lock"):
        activated = controller().activate(actor_uuid, team_uuid)
        protect_grant_files()
        return {"activated": activated}


def reconcile_memberships() -> dict[str, int]:
    try:
        access.canonical_uuid(enrollment_kanidm.configuration().get("accounts_uuid"))
        store = membership_store()
        subjects = store.subjects()
    except RuntimeError, OSError, ValueError, urllib.error.URLError:
        return {"checked": 0, "changed": 0, "failed": 1}

    result = {"checked": 0, "changed": 0, "failed": 0}

    for subject in subjects:
        result["checked"] += 1
        try:
            outcome = enrollment_kanidm.membership_sync(
                subject["person_uuid"], store.active(subject["person_uuid"])
            )
            result["changed"] += outcome["changed"]
        except RuntimeError, OSError, ValueError, urllib.error.URLError:
            result["failed"] += 1

    return result


def reconcile() -> dict[str, int]:
    annual = reconcile_memberships()
    result = controller().reconcile()
    result["failed"] += annual["failed"]

    write(
        STATUS,
        {
            "at": time.time(),
            "ok": result["failed"] == 0,
            "counts": result,
            "membership": annual,
        },
    )

    return result


def _reconcile_loop(loop: bool) -> None:
    while True:
        try:
            print(json.dumps(reconcile()), flush=True)
        except RuntimeError, OSError, ValueError, urllib.error.URLError:
            write(STATUS, {"at": time.time(), "ok": False})
            print('{"ok":false}', flush=True)

            if not loop:
                raise SystemExit(1) from None

        if not loop:
            break

        time.sleep(30)


def run() -> None:
    _reconcile_loop(True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Private runtime wiring for leased Kanidm group memberships."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bootstrap")
    activate = commands.add_parser("activate-group")
    activate.add_argument("--actor", required=True)
    activate.add_argument("--team", required=True)
    worker = commands.add_parser("reconcile")
    worker.add_argument("--loop", action="store_true")
    args = parser.parse_args(namespace=Arguments())

    if args.command == "bootstrap":
        print(json.dumps(bootstrap()))
        return

    if args.command == "activate-group":
        print(json.dumps(activate_group(args.actor, args.team)))
        return

    _reconcile_loop(args.loop)


if __name__ == "__main__":
    os.umask(0o077)
    main()
