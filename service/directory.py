import math
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from http.client import HTTPException
from typing import Literal, NotRequired, TypedDict, cast

import access
from contracts import (
    NativeAttrs,
    is_list,
    is_object_dict,
    is_str_list,
    json_array,
    json_object,
    json_string,
)

type PasswordMfa = Literal["Enabled", "Not configured", "Unknown"]


class CredentialSummary(TypedDict):
    password_mfa: PasswordMfa
    passkeys: int | Literal["Unknown"]
    checked_at: str | None


class _Credential(TypedDict):
    password_mfa: PasswordMfa
    at: float
    fingerprint: tuple[tuple[str, ...], ...]


class Person(TypedDict):
    uuid: str
    username: str
    name: str
    email: str
    account: Literal["Active", "Expired", "Not yet valid"]
    password_mfa: NotRequired[PasswordMfa]
    passkeys: NotRequired[int | Literal["Unknown"]]
    checked_at: NotRequired[str | None]


class Group(TypedDict):
    uuid: str
    name: str
    description: str
    system: bool


class Membership(TypedDict):
    person_uuid: str
    group_uuid: str
    membership: Literal["Direct", "Inherited"]


class Snapshot(TypedDict):
    people: list[Person]
    groups: list[Group]
    memberships: list[Membership]


def _password_mfa(value: object) -> PasswordMfa:
    if not is_object_dict(value):
        return "Unknown"

    credentials = value.get("creds")

    if not is_list(credentials) or len(credentials) != 1:
        return "Unknown"

    credential = credentials[0]

    if not is_object_dict(credential):
        return "Unknown"

    try:
        access.canonical_uuid(credential.get("uuid"))
    except access.AccessDenied:
        return "Unknown"

    kind = credential.get("type_")

    if kind in ("Password", "GeneratedPassword"):
        return "Not configured"

    if not is_object_dict(kind) or set(kind) != {"PasswordMfa"}:
        return "Unknown"

    factors = kind["PasswordMfa"]

    if (
        not is_list(factors)
        or len(factors) != 3
        or not is_str_list(factors[0])
        or not is_str_list(factors[1])
        or type(factors[2]) is not int
        or factors[2] < 0
    ):
        return "Unknown"

    return "Enabled" if factors[0] or factors[1] else "Not configured"


class CredentialCache:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.lock = threading.Lock()
        self.entries: dict[str, _Credential] = {}
        self.refreshed_at: float | None = None
        self.wall_at: float | None = None

    def summaries(
        self, backend: access.Directory, people: dict[str, NativeAttrs], now: float
    ) -> dict[str, CredentialSummary]:
        with self.lock:
            tick = self.clock()

            if not math.isfinite(now) or not math.isfinite(tick):
                self.entries.clear()
                return {
                    identifier: {
                        "password_mfa": "Unknown",
                        "passkeys": "Unknown",
                        "checked_at": None,
                    }
                    for identifier in people
                }

            if self.wall_at is not None and now < self.wall_at:
                self.entries.clear()

            if self.refreshed_at is not None and tick < self.refreshed_at:
                self.entries.clear()
                self.refreshed_at = tick

            self.wall_at = now
            self.entries = {
                identifier: entry
                for identifier, entry in self.entries.items()
                if identifier in people
            }
            fingerprints = {
                identifier: tuple(
                    tuple(attrs.get(field, []))
                    for field in (
                        "primary_credential",
                        "passkeys",
                        "attested_passkeys",
                    )
                )
                for identifier, attrs in people.items()
            }

            for identifier, cached in self.entries.items():
                if (
                    fingerprints[identifier] != cached["fingerprint"]
                    or now - cached["at"] > 600
                ):
                    cached["password_mfa"] = "Unknown"

            if people and (self.refreshed_at is None or tick - self.refreshed_at >= 15):
                identifier = min(
                    people,
                    key=lambda identifier: (
                        self.entries[identifier]["at"]
                        if identifier in self.entries
                        else -math.inf,
                        identifier,
                    ),
                )
                self.refreshed_at = tick
                password_mfa: PasswordMfa = "Unknown"

                with suppress(
                    RuntimeError, OSError, ValueError, TypeError, HTTPException
                ):
                    password_mfa = _password_mfa(backend.credential_status(identifier))

                self.entries[identifier] = {
                    "password_mfa": password_mfa,
                    "at": now,
                    "fingerprint": fingerprints[identifier],
                }

            result: dict[str, CredentialSummary] = {}

            for identifier, attrs in people.items():
                entry = self.entries.get(identifier)
                fresh = (
                    entry is not None
                    and entry["fingerprint"] == fingerprints[identifier]
                    and 0 <= now - entry["at"] <= 600
                )
                count = len(attrs.get("passkeys", [])) + len(
                    attrs.get("attested_passkeys", [])
                )
                result[identifier] = {
                    "password_mfa": entry["password_mfa"]
                    if entry is not None and fresh
                    else "Unknown",
                    "passkeys": count if count else "Unknown",
                    "checked_at": datetime.fromtimestamp(entry["at"], UTC).isoformat()
                    if entry is not None and fresh
                    else None,
                }

            return result


def read_snapshot(value: object) -> Snapshot:
    data = json_object(value)
    result: Snapshot = {"people": [], "groups": [], "memberships": []}
    people: set[str] = set()
    groups: set[str] = set()

    for item in json_array(data["people"]):
        person = json_object(item)
        identifier = access.canonical_uuid(person["uuid"])
        account = person["account"]

        if identifier in people or account not in {
            "Active",
            "Expired",
            "Not yet valid",
        }:
            raise ValueError("Directory person is invalid")

        people.add(identifier)
        state: Literal["Active", "Expired", "Not yet valid"] = "Active"

        if account == "Expired":
            state = "Expired"
        elif account == "Not yet valid":
            state = "Not yet valid"

        record: Person = {
            "uuid": identifier,
            "username": json_string(person["username"]),
            "name": json_string(person["name"]),
            "email": json_string(person["email"]),
            "account": state,
        }

        if "password_mfa" in person:
            password_mfa = person["password_mfa"]

            if password_mfa == "Enabled":
                record["password_mfa"] = "Enabled"
            elif password_mfa == "Not configured":
                record["password_mfa"] = "Not configured"
            elif password_mfa == "Unknown":
                record["password_mfa"] = "Unknown"
            else:
                raise ValueError("Directory credential state is invalid")

        if "passkeys" in person:
            passkeys = person["passkeys"]

            if passkeys != "Unknown" and not (type(passkeys) is int and passkeys > 0):
                raise ValueError("Directory passkey count is invalid")

            record["passkeys"] = cast(int | Literal["Unknown"], passkeys)

        if "checked_at" in person:
            checked_at = person["checked_at"]

            if checked_at is not None:
                _date(json_string(checked_at))

            record["checked_at"] = cast(str | None, checked_at)

        result["people"].append(record)

    for item in json_array(data["groups"]):
        group = json_object(item)
        identifier = access.canonical_uuid(group["uuid"])
        system = group["system"]

        if identifier in groups or type(system) is not bool:
            raise ValueError("Directory group is invalid")

        groups.add(identifier)
        result["groups"].append(
            {
                "uuid": identifier,
                "name": json_string(group["name"]),
                "description": json_string(group["description"]),
                "system": system,
            }
        )

    edges: set[tuple[str, str]] = set()

    for item in json_array(data["memberships"]):
        entry = json_object(item)
        person_uuid = json_string(entry["person_uuid"])
        group_uuid = json_string(entry["group_uuid"])
        membership = entry["membership"]

        if (
            person_uuid not in people
            or group_uuid not in groups
            or (person_uuid, group_uuid) in edges
            or membership not in {"Direct", "Inherited"}
        ):
            raise ValueError("Directory membership is invalid")

        edges.add((person_uuid, group_uuid))
        result["memberships"].append(
            {
                "person_uuid": person_uuid,
                "group_uuid": group_uuid,
                "membership": "Direct" if membership == "Direct" else "Inherited",
            }
        )

    return result


def _single(attrs: NativeAttrs, field: str) -> str:
    values = attrs.get(field, [])

    if len(values) != 1 or not values[0]:
        raise ValueError("Directory identity is incomplete")

    return values[0]


def _catalog(entries: list[NativeAttrs], kind: str) -> dict[str, NativeAttrs]:
    if len(entries) > 5000:
        raise ValueError("Directory catalog is too large")

    result: dict[str, NativeAttrs] = {}
    references: set[str] = set()
    names: set[str] = set()

    for attrs in entries:
        classes = set(attrs.get("class", []))

        if kind not in classes or classes.intersection({"recycled", "tombstone"}):
            raise ValueError("Directory catalog has an unexpected entry")

        identifier = access.canonical_uuid(_single(attrs, "uuid"))
        spn = _single(attrs, "spn")
        name = _single(attrs, "name")

        if references.intersection({identifier, spn}) or name in names:
            raise ValueError("Directory identity is ambiguous")

        references.update((identifier, spn))
        names.add(name)
        result[identifier] = attrs

    return result


def _date(value: str) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        raise ValueError("Directory dates require a timezone")

    return parsed.timestamp()


def snapshot(
    backend: access.Directory,
    now: float | None = None,
    *,
    credentials: CredentialCache | None = None,
) -> Snapshot:
    now = time.time() if now is None else now
    people = _catalog(backend.person_catalog(), "person")
    groups = _catalog(backend.group_catalog(), "group")
    references = {
        reference: identifier
        for identifier, attrs in groups.items()
        for reference in (identifier, _single(attrs, "spn"))
    }
    result: Snapshot = {"people": [], "groups": [], "memberships": []}
    credential_summaries = (
        credentials.summaries(backend, people, now) if credentials is not None else {}
    )

    for identifier, attrs in sorted(groups.items(), key=lambda item: item[1]["name"]):
        descriptions = attrs.get("description", [])

        if len(descriptions) > 1:
            raise ValueError("Directory group description is ambiguous")

        result["groups"].append(
            {
                "uuid": identifier,
                "name": attrs["name"][0],
                "description": descriptions[0] if descriptions else "",
                "system": uuid.UUID(identifier).int < access.NATIVE_UUID_LIMIT
                or "system" in attrs["class"],
            }
        )

    for identifier, attrs in sorted(people.items(), key=lambda item: item[1]["name"]):
        if "memberof" not in attrs or "directmemberof" not in attrs:
            raise ValueError("Directory membership is unavailable")

        effective = {references[reference] for reference in attrs["memberof"]}
        direct = {references[reference] for reference in attrs["directmemberof"]}

        if not direct.issubset(effective):
            raise ValueError("Directory memberships are inconsistent")

        bounds: dict[str, float | None] = {}

        for field in ("account_expire", "account_valid_from"):
            values = attrs.get(field, [])

            if len(values) > 1:
                raise ValueError("Directory account date is ambiguous")

            bounds[field] = _date(values[0]) if values else None

        expiry, valid_from = bounds["account_expire"], bounds["account_valid_from"]
        account: Literal["Active", "Expired", "Not yet valid"] = "Active"

        if expiry is not None and expiry <= now:
            account = "Expired"
        elif valid_from is not None and valid_from > now:
            account = "Not yet valid"

        person: Person = {
            "uuid": identifier,
            "username": attrs["name"][0],
            "name": _single(attrs, "displayname"),
            "email": next(iter(attrs.get("mail", [])), ""),
            "account": account,
        }

        if identifier in credential_summaries:
            summary = credential_summaries[identifier]
            person["password_mfa"] = summary["password_mfa"]
            person["passkeys"] = summary["passkeys"]
            person["checked_at"] = summary["checked_at"]

        result["people"].append(person)
        result["memberships"].extend(
            {
                "person_uuid": identifier,
                "group_uuid": group,
                "membership": "Direct" if group in direct else "Inherited",
            }
            for group in sorted(effective, key=lambda group: groups[group]["name"])
        )

    return result
