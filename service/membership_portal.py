import time
import urllib.error
from typing import TypedDict

from flask import Flask, redirect, request, session
from flask.typing import ResponseReturnValue

import access
import access_portal
import enrollment_kanidm as kanidm
import membership
from contracts import (
    CsrfCheck,
    NativeAttrs,
    Page,
    is_object_dict,
    json_number,
)


class Profile(TypedDict):
    uuid: str
    username: str
    name: str
    email: str


def _unexpired(value: object) -> bool:
    if not is_object_dict(value):
        return False

    try:
        return json_number(value.get("expires_at")) > time.time()
    except ValueError:
        return False


def register(
    app: Flask,
    page: Page,
    csrf_check: CsrfCheck,
    store: membership.MembershipStore,
) -> None:
    def failure(
        message: str, status: int = 503, *, sign_in: bool = False
    ) -> tuple[str, int]:
        return page(
            "membership_error",
            message=message,
            action_url="/access/login?purpose=membership" if sign_in else "/membership",
            action_label="Sign in again" if sign_in else "Registration",
        ), status

    def identity(attrs: NativeAttrs, person_uuid: str) -> Profile:
        if attrs.get("uuid") != [person_uuid] or any(
            len(attrs.get(key, [])) != 1 for key in ("name", "displayname")
        ):
            raise access.AccessUnavailable("membership_identity_changed")

        return {
            "uuid": person_uuid,
            "username": attrs["name"][0],
            "name": attrs["displayname"][0],
            "email": next(iter(attrs.get("mail", [])), ""),
        }

    def member() -> tuple[str, Profile]:
        onboarding: object = session.get("membership_onboarding")

        if is_object_dict(onboarding):
            if _unexpired(onboarding):
                person_uuid = access.canonical_uuid(onboarding["uuid"])
                return person_uuid, identity(
                    kanidm.approved_account(person_uuid), person_uuid
                )

            session.pop("membership_onboarding", None)

        saved = access_portal.member_session(session.get("member"))
        access_portal.validate_native_session(
            access_portal.oauth_configuration(), saved
        )
        person_uuid = access.canonical_uuid(saved["uuid"])
        return person_uuid, identity(kanidm.approved_account(person_uuid), person_uuid)

    def member_page(
        person_uuid: str,
        profile: Profile,
        *,
        values: membership.Responses | None = None,
        errors: dict[str, str] | None = None,
        status: int = 200,
    ) -> tuple[str, int]:
        record = store.current(person_uuid)
        period = membership.period(store.clock())

        if record and record["period"] != period["key"]:
            record = None

        return page(
            "membership",
            registration_period=period,
            membership_record=record,
            membership_identity=profile,
            membership_options=membership.OPTIONS,
            membership_student_levels=membership.STUDENT_LEVELS,
            form_values=values or {},
            field_errors=errors or {},
            errors=list((errors or {}).values()),
            message=session.pop("membership_message", None),
            membership_suspended=store.suspended(person_uuid),
        ), status

    @app.get("/membership")
    def my_membership() -> ResponseReturnValue:
        if not session.get("member") and not session.get("membership_onboarding"):
            return redirect("/access/login?purpose=membership")

        try:
            person_uuid, profile = member()
            return member_page(person_uuid, profile)
        except access.AccessDenied as error:
            if str(error) in access_portal.SIGN_IN_ERRORS:
                session.pop("member", None)
                return redirect("/access/login?purpose=membership")

            return failure(
                "Sign in again to view your registration.", 403, sign_in=True
            )
        except access.AccessUnavailable, RuntimeError, OSError, urllib.error.URLError:
            return failure("Registration is unavailable. Try again.")

    @app.post("/membership")
    def submit_membership() -> ResponseReturnValue:
        csrf_check()

        try:
            person_uuid, profile = member()

            try:
                store.submit(
                    person_uuid,
                    request.form.to_dict(flat=False),
                    request.form.get("period", ""),
                )
            except membership.MembershipValidationError as error:
                values: membership.Responses = {
                    key: request.form.getlist(key)
                    if key in {"studies", "ethnicity", "heard_about"}
                    else value
                    for key, value in request.form.items()
                }
                return member_page(
                    person_uuid, profile, values=values, errors=error.errors, status=400
                )

            try:
                kanidm.membership_sync(person_uuid, store.active(person_uuid))
            except RuntimeError, OSError, urllib.error.URLError:
                session["membership_message"] = "Registration saved. Access is pending."

            return redirect("/membership", code=303)
        except membership.AlreadySubmitted:
            return failure("You have already submitted this registration.", 409)
        except access.AccessDenied:
            return failure("Sign in again to complete registration.", 403, sign_in=True)
        except access.AccessUnavailable, RuntimeError, OSError, urllib.error.URLError:
            return failure("Registration is unavailable. Try again.")
