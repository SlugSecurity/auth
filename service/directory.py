import time
import uuid
from datetime import datetime
from typing import Literal, TypedDict

import access
from contracts import NativeAttrs, json_array, json_object, json_string


class Person(TypedDict):
    uuid: str
    username: str
    name: str
    email: str
    account: Literal["Active", "Expired", "Not yet valid"]


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

        result["people"].append(
            {
                "uuid": identifier,
                "username": json_string(person["username"]),
                "name": json_string(person["name"]),
                "email": json_string(person["email"]),
                "account": state,
            }
        )

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


def snapshot(backend: access.Directory, now: float | None = None) -> Snapshot:
    now = time.time() if now is None else now
    people = _catalog(backend.person_catalog(), "person")
    groups = _catalog(backend.group_catalog(), "group")
    references = {
        reference: identifier
        for identifier, attrs in groups.items()
        for reference in (identifier, _single(attrs, "spn"))
    }
    result: Snapshot = {"people": [], "groups": [], "memberships": []}

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

        result["people"].append(
            {
                "uuid": identifier,
                "username": attrs["name"][0],
                "name": _single(attrs, "displayname"),
                "email": next(iter(attrs.get("mail", [])), ""),
                "account": account,
            }
        )
        result["memberships"].extend(
            {
                "person_uuid": identifier,
                "group_uuid": group,
                "membership": "Direct" if group in direct else "Inherited",
            }
            for group in sorted(effective, key=lambda group: groups[group]["name"])
        )

    return result
