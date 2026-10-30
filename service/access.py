import base64
import binascii
import fcntl
import json
import os
import re
import sqlite3
import time
import urllib.error
import uuid
from collections.abc import Callable, Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import NotRequired, Protocol, TypedDict

from contracts import (
    JSONObject,
    NativeAPI,
    NativeAttrs,
    NativeReadAPI,
    is_list,
    is_object_dict,
    is_str_list,
    json_object,
    json_string,
    native_attrs,
)


class GrantRecord(TypedDict):
    team_uuid: str
    person_uuid: str
    username: str
    expires_at: str
    status: str
    version: int
    approved_by: str
    changed_at: str
    sync_status: str
    last_error: str | None
    can_edit: NotRequired[bool]
    request_id: NotRequired[str]


class _GrantRow(TypedDict):
    team_uuid: str
    person_uuid: str
    username: str
    native_spn: str
    expires_at: float
    status: str
    version: int
    approved_by: str
    changed_at: float
    sync_status: str
    last_error: str | None


class MembershipGrant(GrantRecord):
    present: bool
    registration_required: bool
    can_remove: NotRequired[bool]
    display_name: NotRequired[str]
    manager: NotRequired[bool]


class OwnGrant(MembershipGrant):
    name: str
    leads: list[str]


class OwnAccess(TypedDict):
    uuid: str
    username: str
    teams: list[OwnGrant]


class ManagedGroup(TypedDict):
    uuid: str
    name: str
    leads_group_uuid: str
    max_days: int
    grants: list[MembershipGrant]
    default_expiry: NotRequired[str]
    editing: NotRequired[bool]
    request_id: NotRequired[str]


class GroupMembership(TypedDict):
    uuid: str
    name: str
    spn: str
    description: str
    system: bool
    present: bool
    grant: GrantRecord | None


class AccessSnapshot(OwnAccess):
    groups: list[str]
    memberships: list[GroupMembership]


class MemberSuggestion(TypedDict):
    username: str
    display_name: str


class MemberIdentity(TypedDict):
    uuid: str
    username: str


class AuditRecord(TypedDict):
    id: int
    at: str
    actor_uuid: str | None
    team_uuid: str | None
    person_uuid: str | None
    event: str
    reason: str | None
    details: JSONObject


class AuditPage(TypedDict):
    events: list[AuditRecord]
    previous: int | None
    next: int | None


class Directory(Protocol):
    def complete_read(self) -> bool: ...
    def group_catalog(self) -> list[NativeAttrs]: ...
    def person_catalog(self) -> list[NativeAttrs]: ...
    def credential_status(self, person_uuid: str) -> object: ...
    def group(self, group_uuid: str) -> NativeAttrs | None: ...
    def person(self, person_uuid: str) -> NativeAttrs | None: ...
    def person_by_name(self, username: str) -> NativeAttrs | None: ...
    def add_member(self, group_uuid: str, person_uuid: str) -> None: ...
    def remove_member(self, group_uuid: str, member_ref: str) -> None: ...


def entry_attrs(value: object, message: str = "native_read_invalid") -> NativeAttrs:
    if not is_object_dict(value):
        raise AccessUnavailable(message)

    try:
        return native_attrs(value.get("attrs"))
    except ValueError as error:
        raise AccessUnavailable(message) from error


def _column[T](row: sqlite3.Row, key: str, expected: type[T]) -> T:
    value: object = row[key]

    if not isinstance(value, expected):
        raise AccessUnavailable("grant_storage_invalid")

    return value


def _optional_column(row: sqlite3.Row, key: str) -> str | None:
    return None if row[key] is None else _column(row, key, str)


def _grant_row(row: sqlite3.Row) -> _GrantRow:
    return {
        "team_uuid": _column(row, "team_uuid", str),
        "person_uuid": _column(row, "person_uuid", str),
        "username": _column(row, "username", str),
        "native_spn": _column(row, "native_spn", str),
        "expires_at": _column(row, "expires_at", float),
        "status": _column(row, "status", str),
        "version": _column(row, "version", int),
        "approved_by": _column(row, "approved_by", str),
        "changed_at": _column(row, "changed_at", float),
        "sync_status": _column(row, "sync_status", str),
        "last_error": _optional_column(row, "last_error"),
    }


def _grant_rows(
    db: sqlite3.Connection, query: str, parameters: tuple[str, ...]
) -> list[_GrantRow]:
    rows: list[sqlite3.Row] = db.execute(query, parameters).fetchall()
    return [_grant_row(row) for row in rows]


USERNAME = re.compile(r"[a-z][a-z0-9_-]{2,31}\Z")
READ_ROLES = {
    "00000000-0000-0000-0000-000000000013": "idm_people_admins",
    "00000000-0000-0000-0000-000000000011": "idm_access_control_admins",
    "00000000-0000-0000-0000-000000000047": "idm_account_policy_admins",
}
NATIVE_UUID_LIMIT = uuid.UUID("00000000-0000-0000-0001-000000000000").int
HIGH_PRIVILEGE_UUID = "00000000-0000-0000-0000-000000001000"


class AccessDenied(RuntimeError):
    pass


class AccessUnavailable(RuntimeError):
    pass


class _AnnualRegistrationRequired(AccessDenied):
    def __init__(self, identity_refs: Iterable[str]) -> None:
        super().__init__("annual_registration_required")
        self.identity_refs = frozenset(identity_refs)


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise AccessDenied("canonical_uuid_required")

    try:
        result = str(uuid.UUID(value))
    except ValueError as error:
        raise AccessDenied("canonical_uuid_required") from error

    if value != result:
        raise AccessDenied("canonical_uuid_required")

    return result


def _audit_uuid(value: object) -> str | None:
    try:
        return canonical_uuid(value)
    except AccessDenied:
        return None


def _timestamp(value: object) -> float:
    if not isinstance(value, str):
        raise AccessDenied("expiry_with_timezone_required")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            raise ValueError

        return parsed.timestamp()
    except (ValueError, OverflowError) as error:
        raise AccessDenied("expiry_with_timezone_required") from error


def _date(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat()


@dataclass(frozen=True)
class TeamPolicy:
    group_uuid: str
    leads_group_uuid: str
    name: str
    max_days: int = 365
    include_leads: bool = False

    def __post_init__(self) -> None:
        canonical_uuid(self.group_uuid)
        canonical_uuid(self.leads_group_uuid)

        if self.group_uuid == self.leads_group_uuid:
            raise ValueError("Groups cannot manage their own manager appointments")

        if not json_string(self.name).strip():
            raise ValueError("Group display name is required")

        if type(self.max_days) is not int or not 1 <= self.max_days <= 365:
            raise ValueError(
                "Group memberships require a finite maximum of 1 to 365 days"
            )

        if type(self.include_leads) is not bool:
            raise ValueError("Lead membership policy must be a boolean")


class KanidmBackend:
    def __init__(
        self,
        api: NativeAPI,
        *,
        read_api: NativeReadAPI | None = None,
        reader_uuid: str | None = None,
        reader_token: str | None = None,
        domain: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.api = api
        self.read_api = read_api
        self.reader_uuid = reader_uuid
        self.reader_token = reader_token
        self.domain = domain
        self.clock = clock

    def _read(self, path: str) -> object:
        if self.read_api is None or self.reader_token is None:
            raise AccessUnavailable("complete_read_capability_required")

        try:
            return self.read_api(path, self.reader_token)
        except urllib.error.HTTPError as error:
            error.close()

            if error.code == 404:
                return None

            raise AccessUnavailable("native_read_failed") from error
        except (urllib.error.URLError, RuntimeError, OSError) as error:
            raise AccessUnavailable("native_read_failed") from error
        except ValueError as error:
            raise AccessUnavailable("native_read_invalid") from error

    def complete_read(self) -> bool:
        try:
            canonical_uuid(self.reader_uuid)

            if (
                not callable(self.read_api)
                or not isinstance(self.reader_token, str)
                or len(self.reader_token) > 32768
                or self.reader_token.count(".") != 2
                or not isinstance(self.domain, str)
                or not re.fullmatch(r"[a-z0-9.-]+", self.domain)
            ):
                raise ValueError

            encoded = self.reader_token.split(".")[1]
            payload: object = json.loads(
                base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            )

            if (
                not is_object_dict(payload)
                or payload.get("account_id") != self.reader_uuid
                or payload.get("purpose", "readonly") != "readonly"
            ):
                raise ValueError

            expiry = payload.get("expiry")

            if type(expiry) is not int or expiry <= self.clock():
                raise ValueError

            canonical_uuid(payload.get("token_id"))
        except (AccessDenied, ValueError, TypeError, binascii.Error) as error:
            raise AccessUnavailable("complete_read_capability_required") from error

        identity = self._read("/v1/self")  # claims do not prove native access
        youare = identity.get("youare") if is_object_dict(identity) else None
        attrs = entry_attrs(youare, "complete_read_identity_invalid")

        if (
            attrs.get("uuid") != [self.reader_uuid]
            or "service_account" not in attrs.get("class", [])
            or "memberof" not in attrs
        ):
            raise AccessUnavailable("complete_read_identity_invalid")

        memberships = set(attrs["memberof"])
        for role_uuid, role_name in READ_ROLES.items():
            expected_spn = role_name + "@" + json_string(self.domain)
            role = self._read(f"/v1/group/{role_uuid}")
            role = entry_attrs(role, "complete_read_roles_required")

            if (
                role.get("uuid") != [role_uuid]
                or role.get("name") != [role_name]
                or role.get("spn") != [expected_spn]
                or "group" not in role.get("class", [])
                or not memberships.intersection({role_uuid, expected_spn})
            ):
                raise AccessUnavailable("complete_read_roles_required")

        return True

    def _entry(self, kind: str, identifier: str) -> NativeAttrs | None:
        self.complete_read()
        result = self._read(f"/v1/{kind}/{identifier}")

        if result is None:
            return None

        return entry_attrs(result)

    def group_catalog(self) -> list[NativeAttrs]:
        self.complete_read()
        result = self._read("/v1/group")

        if not is_list(result):
            raise AccessUnavailable("complete_group_metadata_required")

        return [
            entry_attrs(entry, "complete_group_metadata_required") for entry in result
        ]

    def person_catalog(self) -> list[NativeAttrs]:
        self.complete_read()
        result = self._read("/v1/person")

        if not is_list(result) or len(result) > 5000:
            raise AccessUnavailable("person_catalog_unavailable")

        return [entry_attrs(entry) for entry in result]

    def credential_status(self, person_uuid: str) -> object:
        person_uuid = canonical_uuid(person_uuid)
        return self._read(f"/v1/person/{person_uuid}/_credential/_status")

    def person(self, person_uuid: str) -> NativeAttrs | None:
        canonical_uuid(person_uuid)
        return self._entry("person", person_uuid)

    def group(self, group_uuid: str) -> NativeAttrs | None:
        canonical_uuid(group_uuid)
        return self._entry("group", group_uuid)

    def person_by_name(self, username: object) -> NativeAttrs | None:
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise AccessDenied("exact_username_required")

        return self._entry("person", username)

    def _member(self, group_uuid: str, member: str, method: str) -> None:
        canonical_uuid(group_uuid)

        try:
            self.api(
                f"/v1/group/{group_uuid}/_attr/member", method=method, body=[member]
            )
        except urllib.error.HTTPError as error:
            error.close()
            raise AccessUnavailable("native_write_failed") from error
        except (urllib.error.URLError, RuntimeError, OSError) as error:
            raise AccessUnavailable("native_write_failed") from error

    def add_member(self, group_uuid: str, person_uuid: str) -> None:
        self._member(group_uuid, canonical_uuid(person_uuid), "POST")

    def remove_member(self, group_uuid: str, member_ref: str) -> None:
        self._member(group_uuid, member_ref, "DELETE")


@dataclass
class _MembershipCandidates:
    people: dict[str, NativeAttrs]
    editable: dict[str, NativeAttrs]
    removable: dict[str, NativeAttrs]
    registration_required: set[str]


class Controller:
    def __init__(
        self,
        database: str | Path,
        backend: Directory,
        policies: Iterable[TeamPolicy],
        admission_group_uuid: str,
        controller_group_uuid: str,
        *,
        clock: Callable[[], float] = time.time,
        protected_group_uuids: Iterable[str] = (),
        membership_active: Callable[[str], bool] | None = None,
        approval_group_uuid: str | None = None,
    ) -> None:
        self.database = Path(database)
        self.backend = backend
        self.admission_group_uuid = canonical_uuid(admission_group_uuid)
        self.controller_group_uuid = canonical_uuid(controller_group_uuid)
        self.clock = clock

        if membership_active is not None and not callable(membership_active):
            raise ValueError("Annual membership eligibility must be callable")

        self.membership_active = membership_active
        self.approval_group_uuid = (
            canonical_uuid(approval_group_uuid)
            if approval_group_uuid is not None
            else None
        )
        policies = tuple(policies)
        self.policies = {policy.group_uuid: policy for policy in policies}

        if len(self.policies) != len(policies):
            raise ValueError("Each managed group must have one policy")

        protected = {self.admission_group_uuid, self.controller_group_uuid}

        if self.approval_group_uuid is not None:
            protected.add(self.approval_group_uuid)
        protected.update(canonical_uuid(value) for value in protected_group_uuids)
        protected.update(policy.leads_group_uuid for policy in policies)

        if protected.intersection(self.policies):
            raise ValueError(
                "Membership, controller and manager groups cannot be managed groups"
            )

        self.protected_group_uuids = frozenset(protected)
        self.database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        if self.database.is_symlink():
            raise ValueError("Grant storage cannot be a symlink")

        descriptor = os.open(self.database, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        self.database.chmod(0o600)
        with self._db() as db:
            schema = {
                row["name"]: row["type"]
                for row in db.execute(
                    "SELECT name,type FROM sqlite_schema WHERE name IN "
                    "('team_grants','team_operations','team_activation','team_audit',"
                    "'team_grants_person','team_audit_membership','team_member_audit')"
                )
            }

            if schema == {
                "team_grants": "table",
                "team_operations": "table",
                "team_activation": "table",
                "team_audit": "table",
                "team_grants_person": "index",
                "team_audit_membership": "index",
                "team_member_audit": "view",
            }:
                self._validate_tracked_policies(db)
                return
        with self._locked(), self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS team_grants (
                    team_uuid TEXT NOT NULL, person_uuid TEXT NOT NULL,
                    username TEXT NOT NULL, native_spn TEXT NOT NULL,
                    expires_at REAL NOT NULL, status TEXT NOT NULL
                      CHECK(status IN ('granted','revoked','expired','ineligible')),
                    version INTEGER NOT NULL, approved_by TEXT NOT NULL,
                    changed_at REAL NOT NULL, sync_status TEXT NOT NULL,
                    last_error TEXT,
                    PRIMARY KEY(team_uuid,person_uuid)
                );
                CREATE TABLE IF NOT EXISTS team_operations (
                    request_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS team_activation (
                    team_uuid TEXT PRIMARY KEY, activated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS team_audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL,
                    actor_uuid TEXT, team_uuid TEXT, person_uuid TEXT,
                    event TEXT NOT NULL, reason TEXT, details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS team_grants_person
                  ON team_grants(person_uuid);
                CREATE INDEX IF NOT EXISTS team_audit_membership
                  ON team_audit(team_uuid,id) WHERE person_uuid IS NOT NULL
                  AND event IN ('imported','granted','renewed','revoked','expired',
                    'ineligible','registration_paused','registration_resumed');
                CREATE VIEW IF NOT EXISTS team_member_audit AS
                  SELECT * FROM team_audit WHERE person_uuid IS NOT NULL
                  AND event IN ('imported','granted','renewed','revoked','expired',
                    'ineligible','registration_paused','registration_resumed');
            """)
            self._validate_tracked_policies(db)

    def _validate_tracked_policies(self, db: sqlite3.Connection) -> None:
        tracked = {
            row[0] for row in db.execute("SELECT DISTINCT team_uuid FROM team_grants")
        }

        if tracked.difference(self.policies):
            raise ValueError(
                "Recorded groups require an explicit decommission before removal"
            )

    @contextmanager
    def _locked(self) -> Generator[None]:
        path = self.database.with_suffix(self.database.suffix + ".lock")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.chmod(path, 0o600)
        with os.fdopen(descriptor, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @contextmanager
    def _db(self) -> Generator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA journal_mode=WAL")
            with db:
                yield db
        finally:
            db.close()

    def _audit(
        self,
        db: sqlite3.Connection,
        event: str,
        *,
        actor: str | None = None,
        team: str | None = None,
        person: str | None = None,
        reason: str | None = None,
        details: JSONObject | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO team_audit(at,actor_uuid,team_uuid,person_uuid,event,reason,details) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                self.clock(),
                actor,
                team,
                person,
                event,
                reason,
                json.dumps(details or {}, separators=(",", ":")),
            ),
        )

    def _policy(self, team_uuid: str) -> TeamPolicy:
        canonical_uuid(team_uuid)

        if team_uuid not in self.policies:
            raise AccessDenied("team_outside_scope")

        return self.policies[team_uuid]

    @staticmethod
    def refs(attrs: Mapping[str, object], field: str) -> set[str]:
        values = attrs.get(field, [])

        if not is_str_list(values) or any(
            not value or len(value) > 512 for value in values
        ):
            raise AccessUnavailable("native_references_invalid")

        return set(values)

    def _group(self, group_uuid: str) -> NativeAttrs:
        self._complete_read()
        attrs = self.backend.group(group_uuid)
        return self._group_attrs(attrs, group_uuid)

    def _complete_read(self) -> None:
        verifier = getattr(self.backend, "complete_read", None)

        if not callable(verifier) or verifier() is not True:
            raise AccessUnavailable("complete_read_capability_required")

    def _group_attrs(self, attrs: NativeAttrs | None, group_uuid: str) -> NativeAttrs:
        if attrs is None or attrs.get("uuid") != [group_uuid]:
            raise AccessUnavailable("configured_group_missing")

        classes = self.refs(attrs, "class")

        if "group" not in classes or classes.intersection({"recycled", "tombstone"}):
            raise AccessUnavailable("configured_group_invalid")

        if (
            "dyngroup" in classes
            or attrs.get("dynmember")
            or attrs.get("dyngroup_filter")
        ):
            raise AccessUnavailable("configured_group_must_be_static")

        return attrs

    def _person(self, person_uuid: str) -> NativeAttrs:
        canonical_uuid(person_uuid)
        self._complete_read()
        attrs = self.backend.person(person_uuid)

        if attrs is None:
            raise AccessDenied("person_missing")

        return self._person_attrs(attrs, person_uuid)

    def _person_attrs(self, attrs: NativeAttrs | None, person_uuid: str) -> NativeAttrs:
        if attrs is None or attrs.get("uuid") != [person_uuid]:
            raise AccessUnavailable("person_identity_mismatch")

        classes = self.refs(attrs, "class")

        if not {"person", "account"}.issubset(classes) or classes.intersection(
            {"service_account", "group", "recycled", "tombstone"}
        ):
            raise AccessDenied("person_required")

        if len(self.refs(attrs, "spn")) != 1 or len(self.refs(attrs, "name")) != 1:
            raise AccessUnavailable("person_identity_incomplete")

        return attrs

    @staticmethod
    def _identity_refs(attrs: NativeAttrs) -> set[str]:
        return {attrs["uuid"][0], attrs["spn"][0]}

    def _eligible(self, person_uuid: str) -> NativeAttrs:
        attrs = self._person(person_uuid)
        return self._eligible_attrs(attrs, self._group(self.admission_group_uuid))

    def _eligible_attrs(
        self,
        attrs: NativeAttrs,
        admission: NativeAttrs,
        approval: set[str] | None = None,
    ) -> NativeAttrs:
        now = self.clock()

        for value in self.refs(attrs, "account_expire"):
            if _timestamp(value) <= now:
                raise AccessDenied("person_expired")

        for value in self.refs(attrs, "account_valid_from"):
            if _timestamp(value) > now:
                raise AccessDenied("person_not_yet_valid")

        if self.approval_group_uuid is not None:
            if approval is None:
                approval = self.refs(self._group(self.approval_group_uuid), "member")

            if not self._identity_refs(attrs).intersection(approval):
                raise AccessDenied("person_not_approved")

        if self.membership_active is not None:
            try:
                active = self.membership_active(attrs["uuid"][0])
            except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
                raise AccessUnavailable("annual_registration_unavailable") from error

            if active is not True:
                raise _AnnualRegistrationRequired(self._identity_refs(attrs))

        if not self.refs(attrs, "memberof").intersection(
            self.refs(admission, "uuid") | self.refs(admission, "spn")
        ):
            if self.membership_active is not None:
                raise AccessUnavailable("annual_admission_projection_pending")

            raise AccessDenied("person_not_admitted")

        return attrs

    def _protected_member_refs(self) -> set[str]:
        protected = (
            self.protected_group_uuids
            - {self.admission_group_uuid, self.approval_group_uuid}
        ) | {HIGH_PRIVILEGE_UUID}
        protected_refs = set(protected)
        resolved: set[str] = set()

        for entry in self.backend.group_catalog():
            identifiers = self.refs(entry, "uuid")

            if identifiers.intersection(protected):
                if len(identifiers) != 1 or len(self.refs(entry, "spn")) != 1:
                    raise AccessUnavailable("protected_group_identity_invalid")

                resolved.update(identifiers)
                protected_refs.update(identifiers)
                protected_refs.update(self.refs(entry, "spn"))

        if not protected.issubset(resolved):
            raise AccessUnavailable("protected_group_metadata_missing")

        return protected_refs

    @classmethod
    def _member_editable(cls, person: NativeAttrs, protected_refs: set[str]) -> bool:
        return (
            uuid.UUID(person["uuid"][0]).int >= NATIVE_UUID_LIMIT
            and "system" not in cls.refs(person, "class")
            and USERNAME.fullmatch(person["name"][0]) is not None
            and "memberof" in person
            and not cls.refs(person, "memberof").intersection(protected_refs)
        )

    def _managed_person(
        self, person_uuid: str, *, include_unregistered: bool = False
    ) -> NativeAttrs:
        person = self._person(person_uuid)

        try:
            self._eligible_attrs(person, self._group(self.admission_group_uuid))
        except _AnnualRegistrationRequired:
            if not include_unregistered:
                raise

        if not self._member_editable(person, self._protected_member_refs()):
            raise AccessDenied("protected_member")

        return person

    def _membership_candidates(
        self, person_uuids: set[str] | None = None
    ) -> _MembershipCandidates:
        admission = self._group(self.admission_group_uuid)
        approval = (
            self.refs(self._group(self.approval_group_uuid), "member")
            if self.approval_group_uuid is not None
            else None
        )
        protected_refs = self._protected_member_refs()
        people: dict[str, NativeAttrs] = {}
        editable: dict[str, NativeAttrs] = {}
        removable: dict[str, NativeAttrs] = {}
        registration_required: set[str] = set()
        seen: set[str] = set()

        for attrs in self.backend.person_catalog():
            identifiers = self.refs(attrs, "uuid")

            if len(identifiers) != 1:
                raise AccessUnavailable("person_catalog_identity_invalid")

            person_uuid = canonical_uuid(next(iter(identifiers)))

            if person_uuid in seen:
                raise AccessUnavailable("person_catalog_identity_ambiguous")

            seen.add(person_uuid)
            registered = True
            try:
                person = self._person_attrs(attrs, person_uuid)
            except AccessDenied:
                continue

            if person_uuids is not None and person_uuid not in person_uuids:
                continue

            people[person_uuid] = person

            try:
                self._eligible_attrs(person, admission, approval)
            except _AnnualRegistrationRequired:
                registered = False
                registration_required.add(person_uuid)
            except AccessDenied:
                continue

            if not self._member_editable(person, protected_refs):
                continue

            removable[person_uuid] = person

            if registered:
                editable[person_uuid] = person

        return _MembershipCandidates(people, editable, removable, registration_required)

    def _editable_people(
        self, *, include_unregistered: bool = False
    ) -> dict[str, NativeAttrs]:
        candidates = self._membership_candidates()
        return candidates.removable if include_unregistered else candidates.editable

    def _team_scope(
        self, policy: TeamPolicy
    ) -> tuple[NativeAttrs, dict[str, NativeAttrs]]:
        self._complete_read()
        entries = self.backend.group_catalog()
        groups: dict[str, NativeAttrs] = {}
        by_ref: dict[str, str] = {}

        for entry in entries:
            identifiers = self.refs(entry, "uuid")
            spns = self.refs(entry, "spn")

            if (
                len(identifiers) != 1
                or len(spns) != 1
                or "group" not in self.refs(entry, "class")
            ):
                raise AccessUnavailable("complete_group_metadata_invalid")

            group_uuid = next(iter(identifiers))
            try:
                canonical_uuid(group_uuid)
            except AccessDenied as error:
                raise AccessUnavailable("complete_group_metadata_invalid") from error

            group_spn = next(iter(spns))

            if group_uuid in groups or group_spn in by_ref:
                raise AccessUnavailable("complete_group_metadata_invalid")

            groups[group_uuid] = entry
            by_ref[group_uuid] = group_uuid
            by_ref[group_spn] = group_uuid

        if not (self.protected_group_uuids | set(self.policies)).issubset(groups):
            raise AccessUnavailable("configured_group_metadata_missing")

        attrs = self._group_attrs(groups[policy.group_uuid], policy.group_uuid)
        names = self.refs(attrs, "name")

        if (
            len(names) != 1
            or any(name.startswith(("idm_", "system_")) for name in names)
            or {"system", "account_policy"}.intersection(self.refs(attrs, "class"))
            or uuid.UUID(policy.group_uuid).int < NATIVE_UUID_LIMIT
        ):
            raise AccessUnavailable("reserved_group_cannot_be_team")

        pending = list(self.refs(attrs, "memberof"))
        seen: set[str] = set()

        while pending:
            reference = pending.pop()
            parent_uuid = by_ref.get(reference)

            if parent_uuid is None:
                raise AccessUnavailable("team_ancestry_unavailable")

            if parent_uuid == policy.group_uuid:
                raise AccessUnavailable("cyclic_team_ancestry")

            if parent_uuid in seen:
                continue

            seen.add(parent_uuid)
            parent = groups[parent_uuid]
            parent_names = self.refs(parent, "name")

            if (
                parent_uuid in self.protected_group_uuids
                or uuid.UUID(parent_uuid).int < NATIVE_UUID_LIMIT
                or {"system", "account_policy"}.intersection(self.refs(parent, "class"))
                or any(name.startswith(("idm_", "system_")) for name in parent_names)
            ):
                raise AccessUnavailable("protected_team_ancestry")

            pending.extend(self.refs(parent, "memberof"))

        return attrs, groups

    def _team(self, policy: TeamPolicy) -> NativeAttrs:
        attrs, groups = self._team_scope(policy)
        manager = self._group_attrs(
            groups[self.controller_group_uuid], self.controller_group_uuid
        )
        manager_spns = self.refs(manager, "spn")

        if len(manager_spns) != 1:
            raise AccessUnavailable("controller_group_identity_incomplete")

        if self.refs(attrs, "entry_managed_by") not in (
            {self.controller_group_uuid},
            manager_spns,
        ):
            raise AccessUnavailable("team_controller_delegation_required")

        return attrs

    def authorize(self, actor_uuid: str, policy: TeamPolicy) -> None:
        actor = self._eligible(canonical_uuid(actor_uuid))
        leads = self._group(policy.leads_group_uuid)

        if not self.refs(actor, "memberof").intersection(
            self.refs(leads, "uuid") | self.refs(leads, "spn")
        ):
            raise AccessDenied("team_lead_required")

        self._team(policy)

    def _candidate(
        self, person_uuid: str, expiry: float, policy: TeamPolicy
    ) -> NativeAttrs:
        person = self._managed_person(person_uuid)
        now = self.clock()

        if not now < expiry <= now + policy.max_days * 86400:
            raise AccessDenied("expiry_outside_team_limit")

        if any(
            expiry > _timestamp(value) for value in person.get("account_expire", [])
        ):
            raise AccessDenied("expiry_after_account_expiry")

        return person

    @staticmethod
    def _row(
        db: sqlite3.Connection, team_uuid: str, person_uuid: str
    ) -> _GrantRow | None:
        row: sqlite3.Row | None = db.execute(
            "SELECT * FROM team_grants WHERE team_uuid=? AND person_uuid=?",
            (team_uuid, person_uuid),
        ).fetchone()
        return None if row is None else _grant_row(row)

    @staticmethod
    def _activated(db: sqlite3.Connection, team_uuid: str) -> None:
        if not db.execute(
            "SELECT 1 FROM team_activation WHERE team_uuid=?", (team_uuid,)
        ).fetchone():
            raise AccessUnavailable("team_requires_explicit_activation")

    def _record(self, row: _GrantRow | None) -> GrantRecord:
        if row is None:
            raise AccessUnavailable("grant_storage_missing")

        result: GrantRecord = {
            "team_uuid": row["team_uuid"],
            "person_uuid": row["person_uuid"],
            "username": row["username"],
            "expires_at": _date(row["expires_at"]),
            "status": row["status"],
            "version": row["version"],
            "approved_by": row["approved_by"],
            "changed_at": _date(row["changed_at"]),
            "sync_status": row["sync_status"],
            "last_error": row["last_error"],
        }

        if (
            result["status"] == "granted"
            and _timestamp(result["expires_at"]) <= self.clock()
        ):
            result["status"] = "expired"
            result["sync_status"] = "pending"

        return result

    def _operate(
        self,
        actor_uuid: str,
        team_uuid: str,
        person_uuid: str,
        request_id: str,
        expires_at: str | None,
        *,
        granting: bool,
    ) -> GrantRecord:
        with self._locked(), self._db() as db:
            try:
                canonical_uuid(actor_uuid)
                canonical_uuid(person_uuid)
                canonical_uuid(request_id)
                policy = self._policy(team_uuid)
                expiry = _timestamp(expires_at) if granting else None
                payload = json.dumps(
                    [actor_uuid, team_uuid, person_uuid, expiry], separators=(",", ":")
                )

                self.authorize(actor_uuid, policy)
                self._activated(db, team_uuid)
                operation = db.execute(
                    "SELECT payload FROM team_operations WHERE request_id=?",
                    (request_id,),
                ).fetchone()

                if operation:
                    if operation["payload"] != payload:
                        raise AccessDenied("request_id_reused")

                    return self._record(self._row(db, team_uuid, person_uuid))

                row = self._row(db, team_uuid, person_uuid)

                if not granting:
                    if row is None:
                        raise AccessDenied("grant_not_found")

                    self._managed_person(person_uuid, include_unregistered=True)
                    db.execute(
                        "UPDATE team_grants SET status='revoked',version=version+1,"
                        "changed_at=?,sync_status='pending',last_error=NULL "
                        "WHERE team_uuid=? AND person_uuid=?",
                        (self.clock(), team_uuid, person_uuid),
                    )
                    event = "revoked"
                else:
                    if expiry is None:
                        raise AccessDenied("expiry_with_timezone_required")

                    person = self._candidate(person_uuid, expiry, policy)
                    now = self.clock()
                    db.execute(
                        "INSERT INTO team_grants VALUES(?,?,?,?,?,'granted',1,?,?,'pending',NULL) "
                        "ON CONFLICT(team_uuid,person_uuid) DO UPDATE SET "
                        "username=excluded.username,native_spn=excluded.native_spn,"
                        "expires_at=excluded.expires_at,status='granted',"
                        "version=team_grants.version+1,approved_by=excluded.approved_by,"
                        "changed_at=excluded.changed_at,sync_status='pending',last_error=NULL",
                        (
                            team_uuid,
                            person_uuid,
                            person["name"][0],
                            person["spn"][0],
                            expiry,
                            actor_uuid,
                            now,
                        ),
                    )
                    event = "renewed" if row is not None else "granted"

                db.execute(
                    "INSERT INTO team_operations VALUES(?,?,?)",
                    (request_id, payload, self.clock()),
                )
                updated = self._row(db, team_uuid, person_uuid)

                if updated is None:
                    raise AccessUnavailable("grant_storage_missing")

                self._audit(
                    db,
                    event,
                    actor=actor_uuid,
                    team=team_uuid,
                    person=person_uuid,
                    details={
                        "request_id": request_id,
                        "version": updated["version"],
                        "expires_at": _date(updated["expires_at"]),
                    },
                )
                db.commit()
            except (AccessDenied, AccessUnavailable) as error:
                self._audit(
                    db,
                    "denied",
                    actor=_audit_uuid(actor_uuid),
                    team=_audit_uuid(team_uuid),
                    person=_audit_uuid(person_uuid),
                    reason=str(error),
                )
                db.commit()
                raise

            self._reconcile_team(db, policy)
            return self._record(self._row(db, team_uuid, person_uuid))

    def grant(
        self,
        actor_uuid: str,
        team_uuid: str,
        person_uuid: str,
        expires_at: str,
        request_id: str,
    ) -> GrantRecord:
        return self._operate(
            actor_uuid, team_uuid, person_uuid, request_id, expires_at, granting=True
        )

    def revoke(
        self, actor_uuid: str, team_uuid: str, person_uuid: str, request_id: str
    ) -> GrantRecord:
        return self._operate(
            actor_uuid, team_uuid, person_uuid, request_id, None, granting=False
        )

    def activate(self, actor_uuid: str, team_uuid: str) -> bool:
        with self._locked(), self._db() as db:
            policy = self._policy(team_uuid)
            self.authorize(actor_uuid, policy)

            if db.execute(
                "SELECT 1 FROM team_activation WHERE team_uuid=?", (team_uuid,)
            ).fetchone():
                return False

            if self.refs(self._team(policy), "member"):
                raise AccessDenied("activation_requires_empty_group")

            if db.execute(
                "SELECT 1 FROM team_grants WHERE team_uuid=?", (team_uuid,)
            ).fetchone():
                raise AccessDenied("activation_requires_unrecorded_group")

            db.execute(
                "INSERT INTO team_activation VALUES(?,?)", (team_uuid, self.clock())
            )

            self._audit(db, "activated", actor=actor_uuid, team=team_uuid)
            return True

    def _terminal(
        self,
        db: sqlite3.Connection,
        row: _GrantRow,
        status: str,
        reason: str | None = None,
    ) -> None:
        db.execute(
            "UPDATE team_grants SET status=?,version=version+1,changed_at=?,"
            "sync_status='pending',last_error=NULL WHERE team_uuid=? AND person_uuid=?",
            (status, self.clock(), row["team_uuid"], row["person_uuid"]),
        )
        self._audit(
            db, status, team=row["team_uuid"], person=row["person_uuid"], reason=reason
        )
        db.commit()

    def _include_leads(self, db: sqlite3.Connection, policy: TeamPolicy) -> None:
        if not policy.include_leads:
            return

        leads = self._group(policy.leads_group_uuid)
        lead_refs = self.refs(leads, "uuid") | self.refs(leads, "spn")
        admission = self._group(self.admission_group_uuid)
        approval = (
            self.refs(self._group(self.approval_group_uuid), "member")
            if self.approval_group_uuid is not None
            else None
        )
        seen: set[str] = set()

        for attrs in self.backend.person_catalog():
            if not self.refs(attrs, "memberof").intersection(lead_refs):
                continue

            identifiers = self.refs(attrs, "uuid")

            if len(identifiers) != 1:
                raise AccessUnavailable("person_catalog_identity_invalid")

            try:
                person_uuid = canonical_uuid(next(iter(identifiers)))
            except AccessDenied as error:
                raise AccessUnavailable("person_catalog_identity_invalid") from error

            if person_uuid in seen:
                raise AccessUnavailable("person_catalog_identity_ambiguous")

            seen.add(person_uuid)

            try:
                person = self._eligible_attrs(
                    self._person_attrs(attrs, person_uuid), admission, approval
                )
            except AccessDenied:
                continue

            if (
                uuid.UUID(person_uuid).int < NATIVE_UUID_LIMIT
                or "system" in self.refs(person, "class")
                or not USERNAME.fullmatch(person["name"][0])
            ):
                continue

            row = self._row(db, policy.group_uuid, person_uuid)
            now = self.clock()

            if (
                row is not None
                and row["status"] == "granted"
                and row["expires_at"] > now
            ):
                continue

            expiry = min(
                [now + policy.max_days * 86400]
                + [_timestamp(value) for value in self.refs(person, "account_expire")]
            )
            db.execute(
                "INSERT INTO team_grants VALUES(?,?,?,?,?,'granted',1,'system',?,'pending',NULL) "
                "ON CONFLICT(team_uuid,person_uuid) DO UPDATE SET "
                "username=excluded.username,native_spn=excluded.native_spn,"
                "expires_at=excluded.expires_at,status='granted',"
                "version=team_grants.version+1,approved_by=excluded.approved_by,"
                "changed_at=excluded.changed_at,sync_status='pending',last_error=NULL",
                (
                    policy.group_uuid,
                    person_uuid,
                    person["name"][0],
                    person["spn"][0],
                    expiry,
                    now,
                ),
            )
            self._audit(
                db,
                "renewed" if row is not None else "granted",
                team=policy.group_uuid,
                person=person_uuid,
                reason="lead_membership",
                details={
                    "version": 1 if row is None else row["version"] + 1,
                    "expires_at": _date(expiry),
                },
            )

    def _reconcile_team(
        self, db: sqlite3.Connection, policy: TeamPolicy
    ) -> dict[str, int]:
        result: dict[str, int] = dict.fromkeys(
            ("added", "removed", "expired", "ineligible", "failed"), 0
        )

        try:
            self._activated(db, policy.group_uuid)
            group = self._team(policy)

            if policy.include_leads:
                db.execute("SAVEPOINT lead_membership")
                try:
                    self._include_leads(db, policy)
                except AccessUnavailable:
                    db.execute("ROLLBACK TO lead_membership")
                    result["failed"] += 1
                finally:
                    db.execute("RELEASE lead_membership")

            rows = _grant_rows(
                db, "SELECT * FROM team_grants WHERE team_uuid=?", (policy.group_uuid,)
            )
            desired: dict[str, NativeAttrs] = {}
            deferred: set[str] = set()
            paused: set[str] = set()
            paused_refs: set[str] = set()
            paused_people: dict[str, set[str]] = {}

            for row in rows:
                if row["status"] != "granted":
                    continue

                if row["expires_at"] <= self.clock():
                    self._terminal(db, row, "expired")
                    result["expired"] += 1
                    continue

                try:
                    person = self._eligible(row["person_uuid"])
                except AccessDenied as error:
                    if isinstance(error, _AnnualRegistrationRequired):
                        paused.add(row["person_uuid"])
                        paused_refs.update(error.identity_refs)
                        paused_people[row["person_uuid"]] = {
                            row["person_uuid"],
                            row["native_spn"],
                            *error.identity_refs,
                        }
                        continue

                    self._terminal(db, row, "ineligible", str(error))
                    result["ineligible"] += 1
                    continue
                except AccessUnavailable:
                    deferred.update({row["person_uuid"], row["native_spn"]})
                    result["failed"] += 1
                    continue

                db.execute(
                    "UPDATE team_grants SET native_spn=?,username=? "
                    "WHERE team_uuid=? AND person_uuid=?",
                    (
                        person["spn"][0],
                        person["name"][0],
                        policy.group_uuid,
                        row["person_uuid"],
                    ),
                )
                desired[row["person_uuid"]] = person

            allowed = deferred.copy()
            for person in desired.values():
                allowed.update(self._identity_refs(person))

            actual = self.refs(group, "member")
            removals = actual - allowed
            uncertain_terminal: set[str] = set()

            if deferred:
                proven_terminal = paused_refs.copy()
                _, native_groups = self._team_scope(policy)
                for group_uuid, native_group in native_groups.items():
                    proven_terminal.add(group_uuid)
                    proven_terminal.update(self.refs(native_group, "spn"))
                for row in _grant_rows(
                    db,
                    "SELECT * FROM team_grants WHERE team_uuid=? AND status!='granted'",
                    (policy.group_uuid,),
                ):
                    proven_terminal.add(row["person_uuid"])

                    try:
                        terminal_person = self._person(row["person_uuid"])
                    except AccessDenied:
                        continue
                    except AccessUnavailable:
                        uncertain_terminal.add(row["person_uuid"])
                        result["failed"] += 1
                        continue

                    proven_terminal.update(self._identity_refs(terminal_person))
                    db.execute(
                        "UPDATE team_grants SET native_spn=?,username=? "
                        "WHERE team_uuid=? AND person_uuid=?",
                        (
                            terminal_person["spn"][0],
                            terminal_person["name"][0],
                            policy.group_uuid,
                            row["person_uuid"],
                        ),
                    )
                removals.intersection_update(
                    proven_terminal
                )  # unresolved accounts may have new spns

            for member_ref in sorted(removals):
                self._team(policy)
                self.backend.remove_member(policy.group_uuid, member_ref)
                after = self.refs(self._team(policy), "member")

                if member_ref in after:
                    raise AccessUnavailable("membership_readback_failed")

                result["removed"] += 1
                registration_paused = False
                for person_uuid, refs in paused_people.items():
                    if member_ref in refs and not after.intersection(refs):
                        self._audit(
                            db,
                            "registration_paused",
                            team=policy.group_uuid,
                            person=person_uuid,
                        )
                        registration_paused = True

                if not registration_paused:
                    self._audit(db, "native_removed", team=policy.group_uuid)
                db.commit()
                actual = after

            for person_uuid, person in desired.items():
                if actual.intersection(self._identity_refs(person)):
                    continue

                current_row = self._row(db, policy.group_uuid, person_uuid)

                if current_row is None:
                    raise AccessUnavailable("grant_storage_missing")

                row = current_row

                if row["expires_at"] <= self.clock():
                    self._terminal(db, row, "expired")
                    result["expired"] += 1
                    continue

                try:
                    person = self._eligible(person_uuid)
                except AccessDenied as error:
                    if isinstance(error, _AnnualRegistrationRequired):
                        paused.add(person_uuid)
                        paused_refs.update(error.identity_refs)
                        continue

                    self._terminal(db, row, "ineligible", str(error))
                    result["ineligible"] += 1
                    continue

                self._team(policy)
                self.backend.add_member(policy.group_uuid, person_uuid)
                after = self.refs(self._team(policy), "member")

                if not after.intersection(self._identity_refs(person)):
                    raise AccessUnavailable("membership_readback_failed")

                result["added"] += 1
                self._audit(
                    db,
                    "registration_resumed"
                    if self._registration_paused(db, policy.group_uuid, person_uuid)
                    else "native_added",
                    team=policy.group_uuid,
                    person=person_uuid,
                )
                db.commit()
                actual = after

            for row in _grant_rows(
                db, "SELECT * FROM team_grants WHERE team_uuid=?", (policy.group_uuid,)
            ):
                present = bool(
                    actual.intersection({row["person_uuid"], row["native_spn"]})
                )
                uncertain = (
                    row["person_uuid"] in deferred
                    or row["person_uuid"] in uncertain_terminal
                )
                synced = not uncertain and present == (
                    row["status"] == "granted" and row["person_uuid"] not in paused
                )
                db.execute(
                    "UPDATE team_grants SET sync_status=?,last_error=? "
                    "WHERE team_uuid=? AND person_uuid=?",
                    (
                        "synced" if synced else "error",
                        None if synced else "native_sync_incomplete",
                        policy.group_uuid,
                        row["person_uuid"],
                    ),
                )
            db.commit()
        except AccessUnavailable as error:
            result["failed"] += 1
            db.execute(
                "UPDATE team_grants SET sync_status='error',last_error=? WHERE team_uuid=?",
                (str(error), policy.group_uuid),
            )
            self._audit(db, "sync_failed", team=policy.group_uuid, reason=str(error))
            db.commit()

        return result

    def reconcile(self) -> dict[str, int]:
        result: dict[str, int] = dict.fromkeys(
            (
                "checked",
                "added",
                "removed",
                "expired",
                "ineligible",
                "failed",
            ),
            0,
        )

        with self._locked(), self._db() as db:
            for policy in self.policies.values():
                result["checked"] += 1
                for key, count in self._reconcile_team(db, policy).items():
                    result[key] += count

        return result

    def _membership_record(
        self,
        row: _GrantRow,
        members: set[str],
        *,
        person: NativeAttrs | None = None,
        registration_required: bool | None = None,
    ) -> MembershipGrant:
        record = self._record(row)
        references = (
            self._identity_refs(person)
            if person is not None
            else {row["person_uuid"], row["native_spn"]}
        )
        check_person = (
            record["status"] == "granted"
            and person is None
            and registration_required is None
        )
        registration_required = (
            record["status"] == "granted" and registration_required is True
        )

        if check_person:
            try:
                current = self._eligible(row["person_uuid"])
            except _AnnualRegistrationRequired as error:
                references = set(error.identity_refs)
                registration_required = True
            except AccessDenied:
                pass
            else:
                references = self._identity_refs(current)

        present = bool(members.intersection(references))

        if present == (record["status"] == "granted" and not registration_required):
            record["sync_status"] = "synced"
            record["last_error"] = None
        elif record["sync_status"] != "error":
            record["sync_status"] = "pending"

        return {
            **record,
            "present": present,
            "registration_required": registration_required,
            "can_remove": False,
            "display_name": record["username"],
            "manager": False,
        }

    def own_access(self, person_uuid: str) -> OwnAccess:
        person = self._eligible(canonical_uuid(person_uuid))
        with self._db() as db:
            rows = _grant_rows(
                db,
                "SELECT * FROM team_grants WHERE person_uuid=? ORDER BY team_uuid",
                (person_uuid,),
            )
        teams: list[OwnGrant] = []

        for row in rows:
            policy = self.policies.get(row["team_uuid"])

            if policy is None:
                continue

            leads = self._group(policy.leads_group_uuid)
            actual = self.refs(self._team(policy), "member")
            record = self._membership_record(row, actual, person=person)
            teams.append(
                OwnGrant(
                    **record,
                    name=policy.name,
                    leads=sorted(self.refs(leads, "member")),
                )
            )

        return {"uuid": person_uuid, "username": person["name"][0], "teams": teams}

    def managed_teams(self, actor_uuid: str) -> list[ManagedGroup]:
        actor = self._eligible(canonical_uuid(actor_uuid))
        rosters: list[tuple[TeamPolicy, NativeAttrs, set[str], list[_GrantRow]]] = []

        with self._db() as db:
            for policy in self.policies.values():
                leads = self._group(policy.leads_group_uuid)

                if not self.refs(actor, "memberof").intersection(
                    self.refs(leads, "uuid") | self.refs(leads, "spn")
                ):
                    continue

                actual = self.refs(self._team(policy), "member")
                rows = _grant_rows(
                    db,
                    "SELECT * FROM team_grants WHERE team_uuid=? ORDER BY username,person_uuid",
                    (policy.group_uuid,),
                )
                rosters.append((policy, leads, actual, rows))

        person_uuids = {
            row["person_uuid"]
            for _policy, _leads, _actual, rows in rosters
            for row in rows
        }
        candidates = self._membership_candidates(person_uuids) if person_uuids else None
        teams: list[ManagedGroup] = []

        for policy, leads, actual, rows in rosters:
            grants = [
                self._membership_record(
                    row,
                    actual,
                    person=candidates.people.get(row["person_uuid"])
                    if candidates is not None
                    else None,
                    registration_required=candidates is not None
                    and row["person_uuid"] in candidates.registration_required,
                )
                for row in rows
            ]
            lead_refs = self.refs(leads, "uuid") | self.refs(leads, "spn")
            for grant in grants:
                person = (
                    candidates.people.get(grant["person_uuid"])
                    if candidates is not None
                    else None
                )
                names: set[str] = self.refs(person, "displayname") if person else set()
                grant["display_name"] = min(names) if names else grant["username"]
                grant["manager"] = bool(
                    person and self.refs(person, "memberof").intersection(lead_refs)
                )
                grant["can_edit"] = (
                    candidates is not None
                    and grant["person_uuid"] in candidates.editable
                )
                grant["can_remove"] = (
                    candidates is not None
                    and grant["person_uuid"] in candidates.removable
                )
            teams.append(
                {
                    "uuid": policy.group_uuid,
                    "name": policy.name,
                    "leads_group_uuid": policy.leads_group_uuid,
                    "max_days": policy.max_days,
                    "grants": grants,
                }
            )

        return teams

    def search_members(
        self, actor_uuid: str, team_uuid: str, query: object
    ) -> list[MemberSuggestion]:
        self.authorize(actor_uuid, self._policy(team_uuid))

        if not isinstance(query, str) or not 2 <= len(query.strip()) <= 64:
            raise ValueError("Enter between 2 and 64 characters")

        query = query.strip().casefold()
        matches: list[tuple[tuple[int, float], str, str]] = []

        for person in self._editable_people().values():
            username = person["name"][0]
            names = sorted(self.refs(person, "displayname"))
            display_name = names[0] if names else username
            fields = [username.casefold(), display_name.casefold()]
            fields.extend(value.casefold() for value in self.refs(person, "mail"))
            rank: tuple[int, float]

            if query == fields[0]:
                rank = (0, 0)
            elif fields[0].startswith(query):
                rank = (1, 0)
            elif any(value.startswith(query) for value in fields[1:]):
                rank = (2, 0)
            elif any(query in value for value in fields):
                rank = (3, 0)
            else:
                similarity = SequenceMatcher(None, query, fields[0]).ratio()

                if len(query) < 3 or similarity < 0.75:
                    continue

                rank = (4, -similarity)
            matches.append((rank, username, display_name))

        matches.sort()
        return [
            {"username": username, "display_name": display_name}
            for _, username, display_name in matches[:10]
        ]

    def lookup_member(
        self, actor_uuid: str, team_uuid: str, username: object
    ) -> MemberIdentity | None:
        self.authorize(actor_uuid, self._policy(team_uuid))

        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise AccessDenied("exact_username_required")

        found = self.backend.person_by_name(username)

        if found is None:
            return None

        if found.get("name") != [username]:
            raise AccessUnavailable("person_identity_mismatch")

        identifiers = self.refs(found, "uuid")

        if len(identifiers) != 1:
            raise AccessUnavailable("person_identity_mismatch")

        try:
            person_uuid = canonical_uuid(next(iter(identifiers)))
            person = self._managed_person(person_uuid)
        except AccessDenied:
            return None

        if person["name"] != [username]:
            raise AccessUnavailable("person_identity_mismatch")

        return {"uuid": person_uuid, "username": username}

    def audit(
        self, actor_uuid: str, team_uuid: str, *, limit: int = 100
    ) -> list[AuditRecord]:
        policy = self._policy(team_uuid)
        self.authorize(actor_uuid, policy)

        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("Audit limit must be between 1 and 500")

        with self._db() as db:
            rows: list[sqlite3.Row] = db.execute(
                "SELECT * FROM team_audit WHERE team_uuid=? ORDER BY id DESC LIMIT ?",
                (team_uuid, limit),
            ).fetchall()

        return self._audit_records(rows)

    @staticmethod
    def _audit_records(rows: list[sqlite3.Row]) -> list[AuditRecord]:
        return [
            AuditRecord(
                id=_column(row, "id", int),
                at=_date(_column(row, "at", float)),
                actor_uuid=_optional_column(row, "actor_uuid"),
                team_uuid=_optional_column(row, "team_uuid"),
                person_uuid=_optional_column(row, "person_uuid"),
                event=_column(row, "event", str),
                reason=_optional_column(row, "reason"),
                details=json_object(json.loads(_column(row, "details", str))),
            )
            for row in rows
        ]

    def member_audit(
        self,
        actor_uuid: str,
        team_uuid: str,
        *,
        before: int | None = None,
        after: int | None = None,
    ) -> AuditPage:
        self.authorize(actor_uuid, self._policy(team_uuid))

        if before is not None and after is not None:
            raise ValueError("Choose one activity cursor")

        cursor = before if before is not None else after

        if cursor is not None and (
            type(cursor) is not int or not 1 <= cursor <= 9223372036854775807
        ):
            raise ValueError("Invalid activity cursor")

        with self._db() as db:
            if (
                cursor is not None
                and not db.execute(
                    "SELECT 1 FROM team_member_audit WHERE team_uuid=? AND id=?",
                    (team_uuid, cursor),
                ).fetchone()
            ):
                raise ValueError("Invalid activity cursor")

            if before is not None:
                query = (
                    "SELECT * FROM team_member_audit WHERE team_uuid=? "
                    "AND id<? ORDER BY id DESC LIMIT 25"
                )
                parameters: tuple[str | int, ...] = (team_uuid, before)
            elif after is not None:
                query = (
                    "SELECT * FROM team_member_audit WHERE team_uuid=? "
                    "AND id>? ORDER BY id ASC LIMIT 25"
                )
                parameters = (team_uuid, after)
            else:
                query = (
                    "SELECT * FROM team_member_audit WHERE team_uuid=? "
                    "ORDER BY id DESC LIMIT 25"
                )
                parameters = (team_uuid,)
            rows: list[sqlite3.Row] = db.execute(query, parameters).fetchall()

            if after is not None:
                rows.reverse()

            if not rows:
                return {"events": [], "previous": None, "next": None}

            first = _column(rows[0], "id", int)
            last = _column(rows[-1], "id", int)
            newer = db.execute(
                "SELECT 1 FROM team_member_audit WHERE team_uuid=? AND id>? LIMIT 1",
                (team_uuid, first),
            ).fetchone()
            older = db.execute(
                "SELECT 1 FROM team_member_audit WHERE team_uuid=? AND id<? LIMIT 1",
                (team_uuid, last),
            ).fetchone()

        return {
            "events": self._audit_records(rows),
            "previous": first if newer else None,
            "next": last if older else None,
        }

    @staticmethod
    def _registration_paused(
        db: sqlite3.Connection, team_uuid: str, person_uuid: str
    ) -> bool:
        latest: sqlite3.Row | None = db.execute(
            "SELECT event FROM team_member_audit WHERE team_uuid=? AND person_uuid=? "
            "ORDER BY id DESC LIMIT 1",
            (team_uuid, person_uuid),
        ).fetchone()
        return latest is not None and latest["event"] == "registration_paused"
