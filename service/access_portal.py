import base64
import hashlib
import hmac
import json
import math
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import NotRequired, TypedDict

from flask import (
    Flask,
    abort,
    g,
    has_request_context,
    jsonify,
    redirect,
    request,
    session,
)
from flask.typing import ResponseReturnValue
from joserfc import jwt
from joserfc.errors import BadSignatureError, InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet
from werkzeug.wrappers import Response

import access
import access_runtime as runtime
import enrollment_kanidm
import operations
from contracts import (
    CsrfCheck,
    JSONObject,
    JWKSet,
    OIDCConfig,
    Page,
    RotateSession,
    is_object_dict,
    is_str_list,
    json_number,
    json_object,
    json_string,
    jwk_set,
)
from runtime_view import runtime as container

type PageResponse = str | Response | tuple[str, int]


class MemberSession(TypedDict):
    uuid: str
    access_token: str
    jti: str
    auth_time: int
    expires_at: int | float


class MemberFlow(TypedDict):
    state: str
    nonce: str
    verifier: str
    started: int | float
    teams: bool
    group: str | None
    purpose: str


class GroupLink(TypedDict):
    uuid: str
    name: str


class GroupCard(access.GroupMembership):
    manager: NotRequired[bool]
    management: NotRequired[access.ManagedGroup | None]
    managed_through: GroupLink | None
    manages: list[GroupLink]


class MemberActivity(TypedDict):
    at: str
    action: str
    username: str
    actor: str


def member_activity(
    events: list[access.AuditRecord],
    grants: Sequence[access.GrantRecord],
    directory: access.Directory,
) -> list[MemberActivity]:
    labels = {
        "imported": "Imported",
        "granted": "Added",
        "renewed": "Membership updated",
        "revoked": "Removed",
        "expired": "Expired",
        "ineligible": "Access removed",
        "registration_paused": "Access paused",
        "registration_resumed": "Access restored",
    }
    usernames = {grant["person_uuid"]: grant["username"] for grant in grants}
    displayed = [
        event
        for event in events
        if event["event"] in labels and event["person_uuid"] is not None
    ]
    actor_ids = {
        actor for event in displayed if (actor := event["actor_uuid"]) is not None
    }

    try:
        people = directory.person_catalog() if actor_ids else []
    except access.AccessUnavailable:
        people = []

    actors = {
        attrs["uuid"][0]: attrs["name"][0]
        for attrs in people
        if len(attrs.get("uuid", [])) == 1
        and attrs["uuid"][0] in actor_ids
        and len(attrs.get("name", [])) == 1
    }
    activity: list[MemberActivity] = []

    for event in displayed:
        person = event["person_uuid"]

        if person is None:
            continue

        actor_uuid = event["actor_uuid"]

        if actor_uuid is not None:
            actor = actors.get(actor_uuid, actor_uuid)
        elif event["reason"] == "lead_membership" or event["event"] in {
            "expired",
            "ineligible",
            "registration_paused",
            "registration_resumed",
        }:
            actor = "System"
        else:
            actor = "Unknown"

        activity.append(
            {
                "at": event["at"],
                "action": labels[event["event"]],
                "username": usernames.get(person, person),
                "actor": actor,
            }
        )

    return activity


def member_session(value: object) -> MemberSession:
    if not is_object_dict(value):
        raise access.AccessDenied("sign_in_required")

    try:
        auth_time = value["auth_time"]

        if type(auth_time) is not int:
            raise ValueError

        return {
            "uuid": access.canonical_uuid(value["uuid"]),
            "access_token": json_string(value["access_token"]),
            "jti": json_string(value["jti"]),
            "auth_time": auth_time,
            "expires_at": json_number(value["expires_at"]),
        }
    except (KeyError, ValueError) as error:
        raise access.AccessDenied("sign_in_required") from error


def _flow(value: object) -> MemberFlow | None:
    if not is_object_dict(value):
        return None

    try:
        teams, group = value["teams"], value["group"]

        if type(teams) is not bool or (
            group is not None and not isinstance(group, str)
        ):
            return None

        return {
            "state": json_string(value["state"]),
            "nonce": json_string(value["nonce"]),
            "verifier": json_string(value["verifier"]),
            "started": json_number(value["started"]),
            "teams": teams,
            "group": group,
            "purpose": json_string(value["purpose"]),
        }
    except KeyError, ValueError:
        return None


SESSION_SECONDS = 900
FLOW_SECONDS = 600
PROVIDER_CACHE_SECONDS = 60
SIGN_IN_ERRORS = {"sign_in_required", "native_session_invalid"}
_provider_cache: tuple[str, float, JWKSet] | None = None


def discard_other_identities(person_uuid: str) -> None:
    for key in ("member", "membership_onboarding"):
        saved: object = session.get(key)

        if is_object_dict(saved) and saved.get("uuid") != person_uuid:
            session.pop(key, None)


def _json_request(
    url: str, *, headers: Mapping[str, str] | None = None, data: bytes | None = None
) -> JSONObject:
    incoming = urllib.request.Request(url, headers=dict(headers or {}), data=data)

    try:
        with container.opener().open(incoming, timeout=10) as response:
            encoded = response.read(128 * 1024 + 1)

            if len(encoded) > 128 * 1024:
                raise access.AccessUnavailable("oidc_response_too_large")

            document: object = json.loads(encoded)
    except urllib.error.HTTPError as error:
        error.close()
        raise

    try:
        return json_object(document)
    except ValueError as error:
        raise access.AccessUnavailable("oidc_response_invalid") from error


def oauth_configuration(*, refresh: bool = False) -> OIDCConfig:
    global _provider_cache
    config = runtime.load(runtime.OIDC_CONFIG)

    if (
        config.get("client_id") != runtime.CLIENT
        or config.get("callback_url") != runtime.CALLBACK
        or not isinstance(config.get("client_secret"), str)
        or not config["client_secret"]
    ):
        raise access.AccessUnavailable("oidc_configuration_invalid")

    issuer = container.URL + f"/oauth2/openid/{runtime.CLIENT}"
    expected = {
        "issuer": issuer,
        "authorization_endpoint": container.URL + "/ui/oauth2",
        "token_endpoint": container.URL + "/oauth2/token",
        "userinfo_endpoint": issuer + "/userinfo",
        "jwks_uri": issuer + "/public_key.jwk",
    }
    configured: OIDCConfig = {
        "client_id": json_string(config["client_id"]),
        "client_secret": json_string(config["client_secret"]),
        "callback_url": json_string(config["callback_url"]),
        "issuer": expected["issuer"],
        "authorization_endpoint": expected["authorization_endpoint"],
        "token_endpoint": expected["token_endpoint"],
        "userinfo_endpoint": expected["userinfo_endpoint"],
        "jwks_uri": expected["jwks_uri"],
        "jwks": {"keys": []},
    }

    if (
        not refresh
        and _provider_cache is not None
        and _provider_cache[0] == issuer
        and time.monotonic() < _provider_cache[1]
    ):
        configured["jwks"] = _provider_cache[2]
        return configured

    metadata = _json_request(issuer + "/.well-known/openid-configuration")

    if any(metadata.get(key) != value for key, value in expected.items()):
        raise access.AccessUnavailable("oidc_discovery_invalid")

    for field, required in (
        ("code_challenge_methods_supported", "S256"),
        ("token_endpoint_auth_methods_supported", "client_secret_basic"),
        ("id_token_signing_alg_values_supported", "ES256"),
    ):
        supported = metadata.get(field)

        if not is_str_list(supported) or required not in supported:
            raise access.AccessUnavailable("oidc_discovery_invalid")

    try:
        keys = jwk_set(_json_request(expected["jwks_uri"]))
    except ValueError as error:
        raise access.AccessUnavailable("oidc_signing_keys_unavailable") from error

    if not keys["keys"]:
        raise access.AccessUnavailable("oidc_signing_keys_unavailable")

    _provider_cache = (issuer, time.monotonic() + PROVIDER_CACHE_SECONDS, keys)
    configured["jwks"] = keys
    return configured


def _same_secret(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and hmac.compare_digest(left.encode(), right.encode())
    )


def exchange(config: OIDCConfig, flow: MemberFlow, code: str) -> MemberSession:
    basic = base64.b64encode(
        f"{config['client_id']}:{config['client_secret']}".encode()
    ).decode()
    token = _json_request(
        config["token_endpoint"],
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": runtime.CALLBACK,
                "code_verifier": flow["verifier"],
            }
        ).encode(),
    )

    try:
        claims = jwt.decode(
            json_string(token["id_token"]),
            KeySet.import_key_set(config["jwks"]),
            algorithms=["ES256"],
        ).claims
    except BadSignatureError, InvalidKeyIdError:
        refreshed = oauth_configuration(refresh=True)
        claims = jwt.decode(
            json_string(token["id_token"]),
            KeySet.import_key_set(refreshed["jwks"]),
            algorithms=["ES256"],
        ).claims

    claims = json_object(claims)
    expires, issued, authenticated = (
        claims[field] for field in ("exp", "iat", "auth_time")
    )

    if (
        type(expires) is not int
        or type(issued) is not int
        or type(authenticated) is not int
        or ("nbf" in claims and type(claims["nbf"]) is not int)
    ):
        raise ValueError("oidc_dates_invalid")

    jwt.JWTClaimsRegistry(
        leeway=30,
        iss={"essential": True, "value": config["issuer"]},
        aud={"essential": True, "value": config["client_id"]},
        exp={"essential": True},
        iat={"essential": True},
        sub={"essential": True},
        nonce={"essential": True},
    ).validate(claims)

    now = time.time()

    if (
        claims["iss"] != config["issuer"]
        or claims["aud"] != config["client_id"]
        or not _same_secret(claims.get("nonce"), flow["nonce"])
        or expires <= now
        or issued > now + 30
        or authenticated > now + 30
        or authenticated > issued + 30
    ):
        raise ValueError("oidc_identity_invalid")

    subject = access.canonical_uuid(claims["sub"])
    access.canonical_uuid(claims["jti"])
    token_type = token.get("token_type")
    access_token = token.get("access_token")
    expires_in = token.get("expires_in")

    if (
        not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or not isinstance(access_token, str)
        or len(access_token) > 32768
        or type(expires_in) is not int
        or not 0 < expires_in <= 3600
    ):
        raise ValueError("oidc_access_token_invalid")

    member: MemberSession = {
        "uuid": subject,
        "access_token": access_token,
        "jti": json_string(claims["jti"]),
        "auth_time": authenticated,
        "expires_at": min(now + SESSION_SECONDS, now + expires_in, expires),
    }

    if flow.get("purpose") == "membership":
        validate_native_session(config, member)
        enrollment_kanidm.approved_account(subject)
    else:
        validate_member(config, member)

    return member


def validate_native_session(config: OIDCConfig, member: object) -> JSONObject:
    member = member_session(member)

    if (
        type(member["expires_at"]) is float and not math.isfinite(member["expires_at"])
    ) or member["expires_at"] <= time.time():
        raise access.AccessDenied("sign_in_required")

    subject = access.canonical_uuid(member.get("uuid"))

    try:
        claims = _json_request(
            config["userinfo_endpoint"],
            headers={"Authorization": "Bearer " + member["access_token"]},
        )
    except urllib.error.HTTPError as error:
        error.close()

        if error.code in {401, 403}:
            raise access.AccessDenied("native_session_invalid") from error

        raise access.AccessUnavailable("native_session_unavailable") from error

    if (
        claims.get("sub") != subject
        or claims.get("iss") != config["issuer"]
        or claims.get("aud") != config["client_id"]
        or claims.get("jti") != member.get("jti")
        or type(claims.get("auth_time")) is not int
        or claims.get("auth_time") != member.get("auth_time")
        or type(expiry := claims.get("exp")) is not int
        or expiry <= time.time()
    ):
        raise access.AccessDenied("native_session_invalid")

    if has_request_context():
        g.account_name = account_display_name(claims)

    return claims


def account_display_name(claims: JSONObject) -> str:
    for key in ("name", "preferred_username"):
        value = claims.get(key)

        if not isinstance(value, str) or not value.strip():
            continue

        if key == "name":
            return value

        username, separator, domain = value.partition("@")

        if username and separator and domain.casefold() == container.DOMAIN.casefold():
            return username

        return value

    return "Account"


def validate_member(config: OIDCConfig, member: object) -> access.AccessSnapshot:
    member = member_session(member)
    validate_native_session(config, member)
    return runtime.member_snapshot(member["uuid"])


def privileged_ready(person_uuid: str) -> bool:
    try:
        return enrollment_kanidm.privileged_account_ready(person_uuid)
    except RuntimeError as error:
        raise access.AccessUnavailable("privileged_policy_unavailable") from error


def register(
    app: Flask, page: Page, csrf_check: CsrfCheck, rotate_session: RotateSession
) -> None:
    @app.before_request
    def start_group_timing() -> None:
        if request.method == "GET" and request.path in {
            "/access",
            "/access/groups",
            "/access/members",
        }:
            g.group_request_started = time.perf_counter()

    @app.after_request
    def finish_group_timing(response: Response) -> Response:
        started = getattr(g, "group_request_started", None)

        if isinstance(started, float):
            elapsed = (time.perf_counter() - started) * 1000
            response.headers.add("Server-Timing", f"groups;dur={elapsed:.1f}")

            if elapsed >= 1000:
                app.logger.warning(
                    "Slow group request: %s took %.0f ms", request.path, elapsed
                )

        return response

    def groups_url(
        group: str | None = None, *, login: bool = False, manage: bool = False
    ) -> str:
        parameters: dict[str, str] = {}

        if manage:
            parameters["manage"] = "1"

        if group:
            parameters["group"] = access.canonical_uuid(group)

        path = "/access/login" if login else "/access"
        return path + ("?" + urllib.parse.urlencode(parameters) if parameters else "")

    def failure(
        message: str = "Access is unavailable. Try again or contact infrastructure administration.",
        status: int = 503,
        *,
        sign_in: bool = False,
        manage: bool = False,
        group: str | None = None,
    ) -> tuple[str, int]:
        manage = (
            manage
            or request.path.startswith("/access/groups")
            or request.args.get("manage") == "1"
        )
        group = (
            group
            or request.args.get("group")
            or json_string((request.view_args or {}).get("team_uuid", ""))
            or None
        )

        try:
            if group:
                group = access.canonical_uuid(group)
        except access.AccessDenied:
            group = None

        if sign_in:
            action_url = groups_url(group, login=True, manage=manage)
            action_label = "Sign in again"
        elif status >= 500:
            action_url = groups_url(group)
            action_label = "Try again"
        else:
            action_url, action_label = "/access", "Groups"

        return page(
            "access_error",
            message=message,
            action_url=action_url,
            action_label=action_label,
        ), status

    def member_check(*, teams: bool = False) -> tuple[str, access.AccessSnapshot]:
        config = oauth_configuration()
        member = member_session(session.get("member"))
        snapshot = validate_member(config, member)

        if teams and not privileged_ready(member["uuid"]):
            raise access.AccessDenied("lead_mfa_required")

        return member["uuid"], snapshot

    def count_event(name: str) -> None:
        try:
            operations.record_event(name)
        except operations.SAFE_FAILURES:
            app.logger.warning("Aggregate group event could not be recorded")

    @app.get("/access/login")
    def access_login() -> ResponseReturnValue:
        selected = request.args.get("group")

        try:
            if selected:
                selected = access.canonical_uuid(selected)
        except access.AccessDenied:
            return failure("This group could not be found.", 404)

        try:
            config = oauth_configuration()
            teams = request.args.get("manage") == "1"
            purpose = request.args.get("purpose", "groups")

            if purpose not in {"groups", "membership"} or (
                teams and purpose == "membership"
            ):
                return failure("Choose Groups or Registration.", 400)

            if teams and session.get("member"):
                try:
                    actor, _ = member_check()
                except access.AccessDenied as error:
                    if str(error) not in SIGN_IN_ERRORS:
                        raise

                    session.pop("member", None)
                else:
                    if not runtime.controller().managed_teams(actor):
                        return failure("You aren't assigned to manage any groups.", 403)

                    if not privileged_ready(actor):
                        raise access.AccessDenied("lead_mfa_required")

            state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            session["member_flow"] = {
                "state": state,
                "nonce": nonce,
                "verifier": verifier,
                "started": time.time(),
                "teams": teams,
                "group": selected,
                "purpose": purpose,
            }
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            parameters = {
                "response_type": "code",
                "client_id": config["client_id"],
                "redirect_uri": runtime.CALLBACK,
                "scope": "openid profile",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            return redirect(
                config["authorization_endpoint"]
                + "?"
                + urllib.parse.urlencode(parameters)
            )
        except access.AccessDenied as error:
            if str(error) == "annual_registration_required":
                return redirect("/membership")

            return failure(
                "Group management requires a manager appointment and MFA.", 403
            )
        except access.AccessUnavailable, OSError, ValueError, urllib.error.URLError:
            return failure()

    @app.get("/access/callback")
    def access_callback() -> ResponseReturnValue:
        flow = _flow(session.pop("member_flow", None))

        if (
            flow is None
            or not 0 <= time.time() - flow["started"] <= FLOW_SECONDS
            or not _same_secret(flow.get("state"), request.args.get("state"))
            or not request.args.get("code")
        ):
            return failure(
                "Sign-in expired. Start again.",
                400,
                sign_in=True,
                manage=flow is not None and flow["teams"],
                group=flow["group"] if flow is not None else None,
            )

        try:
            config = oauth_configuration()
            member = exchange(config, flow, request.args["code"])

            if flow["teams"] and not runtime.controller().managed_teams(member["uuid"]):
                return failure("You aren't assigned to manage any groups.", 403)

            if flow["teams"] and not privileged_ready(member["uuid"]):
                return failure(
                    "Group management requires a manager appointment and MFA.", 403
                )
        except access.AccessUnavailable:
            return failure(manage=flow.get("teams") is True, group=flow.get("group"))
        except access.AccessDenied as error:
            if str(error) == "annual_registration_required":
                return redirect("/access/login?purpose=membership")

            return failure(
                "Sign-in could not be verified. Start again.",
                403,
                sign_in=True,
                manage=flow.get("teams") is True,
                group=flow.get("group"),
            )
        except (
            JoseError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            urllib.error.URLError,
        ):
            return failure(
                "Sign-in could not be verified. Start again.",
                403,
                sign_in=True,
                manage=flow.get("teams") is True,
                group=flow.get("group"),
            )

        rotate_session()
        discard_other_identities(member["uuid"])
        session["csrf"] = secrets.token_urlsafe(32)
        session["member"] = member
        return redirect(
            "/membership"
            if flow.get("purpose") == "membership"
            else groups_url(flow.get("group"))
        )

    @app.get("/access")
    def my_access(
        manage: bool = False,
        *,
        selected: str | None = None,
        form_values: dict[str, str] | None = None,
        errors: list[str] | None = None,
    ) -> PageResponse:
        selected = selected or request.args.get("group")

        try:
            if selected:
                selected = access.canonical_uuid(selected)
        except access.AccessDenied:
            return failure("This group could not be found.", 404)

        cursors: dict[str, int] = {}

        for name in ("activity_before", "activity_after"):
            values = request.args.getlist(name)

            if not values:
                continue

            value = values[0]

            if (
                len(values) != 1
                or not value.isascii()
                or not value.isdecimal()
                or not 1 <= len(value) <= 19
                or value.startswith("0")
                or int(value) > 9223372036854775807
            ):
                return failure("Invalid activity page.", 400)

            cursors[name] = int(value)

        if len(cursors) > 1:
            return failure("Invalid activity page.", 400)

        if not session.get("member"):
            return redirect(groups_url(selected, login=True, manage=manage))

        try:
            actor, snapshot = member_check()
            instance = runtime.controller()
            managed = instance.managed_teams(actor)
            manager_ready = bool(managed) and privileged_ready(actor)

            if manage and not managed:
                return failure("You aren't assigned to manage any groups.", 403)

            if manage and not manager_ready:
                return failure(
                    "Group management requires a manager appointment and MFA.", 403
                )

            memberships: list[GroupCard] = [
                {
                    **group,
                    "manager": False,
                    "management": None,
                    "managed_through": None,
                    "manages": [],
                }
                for group in snapshot["memberships"]
            ]
            indexed = {group["uuid"]: group for group in memberships}

            for group in managed:
                if group["uuid"] not in indexed:
                    attrs = instance.backend.group(group["uuid"])

                    if (
                        attrs is None
                        or attrs.get("uuid") != [group["uuid"]]
                        or len(attrs.get("spn", [])) != 1
                        or len(attrs.get("name", [])) != 1
                    ):
                        raise access.AccessUnavailable("managed_group_identity_invalid")

                    descriptions = attrs.get("description", [])
                    membership: GroupCard = {
                        "uuid": group["uuid"],
                        "name": attrs["name"][0],
                        "spn": attrs["spn"][0],
                        "description": descriptions[0] if descriptions else "",
                        "system": False,
                        "present": False,
                        "grant": None,
                        "managed_through": None,
                        "manages": [],
                    }
                    indexed[group["uuid"]] = membership
                    memberships.append(membership)

                indexed[group["uuid"]]["manager"] = True
                indexed[group["uuid"]]["management"] = group if manager_ready else None

            for group in managed:
                leads = indexed.get(group.get("leads_group_uuid", ""))

                if leads is None:
                    continue

                team = indexed[group["uuid"]]
                team["managed_through"] = {"uuid": leads["uuid"], "name": leads["name"]}
                leads["manages"].append({"uuid": team["uuid"], "name": team["name"]})

            memberships.sort(
                key=lambda group: (
                    not group.get("manager"),
                    group["system"],
                    not group["present"],
                    group["name"].casefold(),
                    group["uuid"],
                )
            )

            if selected and selected not in indexed:
                return failure("This group could not be found.", 404)

            selected_group = (
                indexed[selected] if selected else next(iter(memberships), None)
            )
            activity: list[MemberActivity] = []
            activity_previous_url: str | None = None
            activity_next_url: str | None = None
            management = selected_group.get("management") if selected_group else None

            if management is not None:
                group = management

                if selected_group is not None:
                    group["name"] = selected_group["name"]

                if errors and "expiry_outside_team_limit" in errors:
                    errors = [
                        f"Choose a future expiry within {group['max_days']} days."
                        if error == "expiry_outside_team_limit"
                        else error
                        for error in errors
                    ]

                try:
                    history = instance.member_audit(
                        actor,
                        group["uuid"],
                        before=cursors.get("activity_before"),
                        after=cursors.get("activity_after"),
                    )
                except ValueError:
                    return failure("Invalid activity page.", 400)

                activity = member_activity(
                    history["events"],
                    group["grants"],
                    instance.backend,
                )

                for direction, cursor in (
                    ("after", history["previous"]),
                    ("before", history["next"]),
                ):
                    if cursor is None:
                        continue

                    url = groups_url(group["uuid"])
                    url += f"&activity_{direction}={cursor}#group-activity"

                    if direction == "after":
                        activity_previous_url = url
                    else:
                        activity_next_url = url

                group["request_id"] = str(uuid.uuid4())
                group["default_expiry"] = (
                    (datetime.now(UTC) + timedelta(days=min(30, group["max_days"])))
                    .replace(second=0, microsecond=0)
                    .isoformat()
                )

                for grant in group["grants"]:
                    grant["request_id"] = str(uuid.uuid4())
                group["editing"] = form_values is not None and any(
                    grant.get("present")
                    and grant.get("can_edit")
                    and grant["username"] == form_values.get("editing_username")
                    and grant["username"] == form_values.get("username")
                    for grant in group["grants"]
                )

            return page(
                "access",
                access=snapshot | {"memberships": memberships},
                manager_ready=manager_ready,
                selected_group=selected_group,
                group_activity=activity,
                activity_previous_url=activity_previous_url,
                activity_next_url=activity_next_url,
                activity_paginated=bool(cursors),
                form_values=form_values or {},
                errors=errors or [],
                message=session.pop("team_message", None),
            )
        except access.AccessDenied as error:
            if str(error) == "annual_registration_required":
                return page("access_error", registration_required=True), 403

            if request.method == "GET" and str(error) in SIGN_IN_ERRORS:
                session.pop("member", None)
                return redirect(groups_url(selected, login=True, manage=manage))

            session.pop("member", None)
            return failure("Sign in again to view your groups.", 403, sign_in=True)
        except access.AccessUnavailable, OSError, ValueError, urllib.error.URLError:
            return failure()

    @app.post("/access/logout")
    def access_logout() -> ResponseReturnValue:
        csrf_check()
        session.clear()
        rotate_session()
        return redirect(container.URL + "/ui/logout")

    @app.get("/access/members")
    def search_members() -> ResponseReturnValue:
        try:
            actor, _ = member_check(teams=True)
            members = runtime.controller().search_members(
                actor, request.args.get("group", ""), request.args.get("q", "")
            )
            return jsonify(members=members)
        except access.AccessDenied:
            return jsonify(
                error="Member search requires a current manager sign-in"
            ), 403
        except ValueError:
            return jsonify(error="Enter between 2 and 64 characters"), 400
        except access.AccessUnavailable, OSError, urllib.error.URLError:
            return jsonify(error="Member search is unavailable"), 503

    @app.get("/access/groups")
    def my_teams() -> ResponseReturnValue:
        return my_access(manage=True)

    @app.post("/access/groups/<team_uuid>/<operation>")
    def team_operation(team_uuid: str, operation: str) -> ResponseReturnValue:
        csrf_check()

        if operation not in {"grant", "revoke"}:
            abort(404)

        def input_error(message: str) -> ResponseReturnValue:
            response = my_access(
                selected=team_uuid,
                form_values={
                    key: request.form.get(key, "")[:128]
                    for key in (
                        "username",
                        "expires_at",
                        "expires_at_utc",
                        "editing_username",
                    )
                },
                errors=[message],
            )
            return (response, 400) if not isinstance(response, tuple) else response

        try:
            actor, _ = member_check(teams=True)
            instance = runtime.controller()

            if operation == "grant":
                person = instance.lookup_member(
                    actor, team_uuid, request.form.get("username", "")
                )

                if person is None:
                    raise access.AccessDenied("approved_member_required")

                absolute = request.form.get("expires_at_utc", "")
                expiry = datetime.fromisoformat(
                    absolute or request.form.get("expires_at", "")
                )

                if absolute and (expiry.tzinfo is None or expiry.utcoffset() is None):
                    raise ValueError("An absolute expiry is required")

                expiry = (
                    expiry.replace(tzinfo=UTC)
                    if expiry.tzinfo is None
                    else expiry.astimezone(UTC)
                )
                result = instance.grant(
                    actor,
                    team_uuid,
                    person["uuid"],
                    expiry.isoformat(),
                    request.form.get("request_id", ""),
                )
                count_event("team_granted")
            else:
                result = instance.revoke(
                    actor,
                    team_uuid,
                    request.form.get("person_uuid", ""),
                    request.form.get("request_id", ""),
                )
                count_event("team_revoked")
            session["team_message"] = (
                "Access updated."
                if result["sync_status"] == "synced"
                else "Change saved. Access is still updating."
            )
            return redirect(groups_url(team_uuid), code=303)
        except access.AccessDenied as error:
            corrections = {
                "exact_username_required": "Choose an approved member's username.",
                "approved_member_required": "Choose an approved member's username.",
                "expiry_outside_team_limit": "expiry_outside_team_limit",
                "expiry_after_account_expiry": "Choose an expiry before this member's account expires.",
            }

            if operation == "grant" and str(error) in corrections:
                return input_error(corrections[str(error)])

            return failure(
                "This change is not permitted for this group or member.", 403
            )
        except ValueError, OverflowError:
            return input_error("Enter a valid date and time for the expiry.")
        except access.AccessUnavailable, OSError, TypeError, urllib.error.URLError:
            return failure()
