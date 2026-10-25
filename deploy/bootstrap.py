import json
import re
from datetime import UTC, datetime

import access_runtime
import enrollment_kanidm as enrollment
import operations
import posix_defaults
from contracts import (
    JSONObject,
    NativeAttrs,
    is_object_dict,
    json_array,
    json_object,
    json_string,
    native_attrs,
)
from native_names import native_name
from runtime_view import runtime as container


def attrs(kind: str, name: str) -> NativeAttrs:
    result = container.cli(kind, "get", name, "--output", "json")

    if result.stdout.strip() == "No matching entries":
        return {}

    value: object = json.loads(result.stdout)
    return native_attrs(value.get("attrs", {})) if is_object_dict(value) else {}


def group(name: str, manager: str = "idm_admin") -> NativeAttrs:
    if not container.entry_exists("group", name):
        container.cli("group", "create", name, manager)

    value = attrs("group", name)
    enrollment.require(
        value.get("entry_managed_by") == [manager + "@" + container.DOMAIN],
        "Existing production group delegation requires review",
    )
    return value


def monitor_group(account: NativeAttrs, token_id: str | None = None) -> None:
    if f"idm_group_admins@{container.DOMAIN}" in account.get("memberof", []):
        return

    service_uuid = operations.canonical_uuid(account["uuid"][0])

    if token_id is None and {
        service_uuid,
        f"{native_name('directory_reader', container)}@{container.DOMAIN}",
    }.intersection(attrs("group", "idm_group_admins").get("member", [])):
        return

    enrollment.require(
        not account.get("primary_credential")
        and not account.get("user_auth_token_session"),
        "New monitoring privilege refuses a native interactive credential or session",
    )

    with operations.operator_api() as api:
        inventory = [
            json_object(item)
            for item in json_array(
                api(f"/v1/service_account/{service_uuid}/_api_token")
            )
        ]

    enrollment.require(
        not inventory
        or (
            token_id is not None
            and len(inventory) == 1
            and inventory[0]["account_id"] == service_uuid
            and inventory[0]["token_id"] == token_id
            and inventory[0].get("purpose") == "readonly"
        ),
        "New monitoring privilege refuses an unrecorded native token or writable credential",
    )
    container.cli(
        "group",
        "add-members",
        "idm_group_admins",
        native_name("directory_reader", container),
    )


def monitor() -> None:
    name = native_name("directory_reader", container)

    if not container.entry_exists("service-account", name):
        container.cli(
            "service-account",
            "create",
            name,
            "Read-only directory monitoring",
            "idm_admin",
        )

    account = attrs("service-account", name)
    enrollment.require(
        account.get("entry_managed_by") == ["idm_admin@" + container.DOMAIN],
        "Existing monitoring principal has an unexpected manager",
    )
    saved = container.load_credentials() if container.CREDENTIALS.exists() else {}
    monitoring: JSONObject | None = (
        json_object(saved["monitoring"]) if "monitoring" in saved else None
    )

    if monitoring is None:
        identifiers = account.get("uuid", [])
        enrollment.require(
            len(identifiers) == 1, "Monitoring principal requires one native UUID"
        )
        monitoring = {
            "account": name,
            "service_uuid": operations.canonical_uuid(identifiers[0]),
        }
        saved = container.update_credentials(
            lambda value: value.update(monitoring=value.get("monitoring", monitoring))
        )
        monitoring = json_object(saved["monitoring"])

    enrollment.require(
        monitoring.get("account") == name
        and account.get("uuid") == [monitoring.get("service_uuid")],
        "Saved monitoring principal changed identity",
    )
    initial = "token" not in monitoring

    if initial:
        monitor_group(account)
        operations.rotate("monitor")
        monitoring = json_object(container.load_credentials()["monitoring"])

    token = json_string(monitoring["token"])
    expiry = json_string(monitoring["token_expiry"])
    payload = operations.claims(token)
    expires_at = operations.timestamp(expiry)
    enrollment.require(
        account.get("uuid") == [payload["account_id"]]
        and payload.get("purpose", "readonly") == "readonly"
        and payload.get("expiry") == expires_at
        and expires_at > datetime.now(UTC).timestamp(),
        "Monitoring token identity, purpose or expiry differs",
    )
    enrollment.require(
        monitoring.get("token_id") == payload["token_id"],
        "Saved monitoring token identity differs",
    )
    identity = native_attrs(
        json_object(json_object(container.api("/v1/self", token))["youare"])["attrs"]
    )
    enrollment.require(
        identity.get("uuid") == [payload["account_id"]]
        and identity.get("name") == [name]
        and "service_account" in identity.get("class", []),
        "Kanidm rejected the intended monitoring identity",
    )

    if not initial:
        monitor_group(identity, payload["token_id"])

    for group_name in operations.PRINCIPALS["monitor"].get("groups", ()):
        observed = native_attrs(
            json_object(container.api("/v1/group/" + group_name, token))["attrs"]
        )
        enrollment.require(
            observed.get("name") == [group_name],
            "The monitoring group read failed",
        )


def run() -> None:
    container.ready()
    container.cli("login", name="admin")
    container.cli("login")

    try:
        domain = container.cli("system", "domain", "show", name="admin").stdout
        enrollment.require(
            re.search(
                r"^domain_name: " + re.escape(container.DOMAIN) + r"$",
                domain,
                re.MULTILINE,
            ),
            "This production bootstrap refuses a different domain or restored localhost database",
        )
        container.cli("system", "domain", "set-displayname", "SlugSec", name="admin")
        container.cli(
            "system",
            "domain",
            "set-image",
            str(container.ROOT / "service/branding/slugsec-logo.png"),
            "png",
            name="admin",
        )
        group(enrollment.WORKERS)

        for name in enrollment.ADMISSION:
            group(name, enrollment.WORKERS)

        for name in enrollment.PRIVILEGED_ROLE_GROUPS:
            group(name)

        for name in ("idm_people_self_name_write", "idm_people_self_mail_write"):
            if attrs("group", name).get("member"):
                container.cli("group", "purge-members", name)

            enrollment.require(
                not attrs("group", name).get("member"),
                "Verified profile write lock did not take effect",
            )

        enrollment.bootstrap()
        enrollment.bootstrap_accounts()
        posix_defaults.bootstrap()
        monitor()
        access_runtime.bootstrap()

        if not access_runtime.load(access_runtime.CONFIG).get("token"):
            operations.rotate("access")
            operations.retire("access")

        print(
            "Production policies and service capabilities provisioned, no human roles granted"
        )
        readiness = enrollment.privileged_readiness()
        print(
            "Privileged authenticators ready"
            if readiness["ready"]
            else "Enroll privileged authenticators before exposing production"
        )
    finally:
        if not hasattr(container, "operator_token"):
            container.cli("logout")
            container.cli("logout", name="admin")
