#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from datetime import datetime
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal, TypedDict
from zoneinfo import ZoneInfo

import access
import directory
from contracts import (
    JSONObject,
    JSONValue,
    json_array,
    json_number,
    json_object,
    json_string,
    native_attrs,
)

REGISTRATION_FIELDS = (
    ("person_uuid", "Person ID"),
    ("username", "Username"),
    ("name", "Name"),
    ("email", "Email"),
    ("status", "Registration"),
    ("submitted_at", "Submitted"),
    ("expires_at", "Expires"),
    ("preferred_name", "Preferred name"),
    ("school_level", "Level in school"),
    ("studies", "Field of study"),
    ("shirt_size", "T-shirt size"),
    ("heard_about", "How you heard about SlugSec"),
    ("referral_details", "Referral details"),
)
DASHBOARDS = Path(__file__).resolve().parents[1] / "monitoring"
MAX_USAGE_METRICS_BYTES = 8 * 1024 * 1024
LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class GroupSuccess(TypedDict):
    success: Literal[True]
    members: list[str]


class GroupFailure(TypedDict):
    success: Literal[False]


type GroupResult = GroupSuccess | GroupFailure


class Snapshot(TypedDict):
    probe_success: bool
    probe_duration: float
    timestamp: float
    groups: dict[str, GroupResult]


class AppLogin(TypedDict):
    at: int
    app: str


class PersonActivity(TypedDict):
    last_at: int
    recent: list[AppLogin]


class Options(argparse.Namespace):
    credentials: Path
    service_account: str
    url: str | None
    ca: str | None
    group: list[str]
    dashboard_output: Path | None
    lookup_dashboard_output: Path | None
    operations_url: str | None
    usage_metrics: Path | None
    bind: str
    port: int
    interval: float
    once: bool


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


class MetricsHTTPServer(ThreadingHTTPServer):
    request_queue_size = 128


def read_group(value: object, expected_name: str) -> list[str]:
    entry = json_object(value)
    classes = [json_string(value) for value in json_array(entry.get("class", []))]

    if entry.get("name") != expected_name or "group" not in classes:
        raise ValueError("Unexpected group entry")

    search = json_object(entry.get("extAccessCheck", {})).get("search")

    if search != "Grant":
        allowed = json_object(search)

        if set(allowed) != {"Allow"} or "member" not in [
            json_string(value) for value in json_array(allowed["Allow"])
        ]:
            raise ValueError("Group membership is not visible")

    members = {
        json_string(json_object(member).get("value"))
        for member in json_array(entry.get("member", []))
    }

    if "" in members:
        raise ValueError("Unexpected empty member name")

    return sorted(members)


def write_dashboard(path: Path, dashboard: JSONObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(dashboard, indent=2) + "\n"

    if path.is_file() and path.read_text() == content:
        return

    temporary = path.with_suffix(".tmp")
    temporary.write_text(content)
    temporary.chmod(0o640)
    temporary.replace(path)


def registration_members(value: object) -> list[dict[str, str]]:
    members: list[dict[str, str]] = []
    identities: set[str] = set()

    for item in json_array(json_object(value)["members"]):
        entry = json_object(item)
        entry.setdefault("referral_details", "")
        member = {key: json_string(entry[key]) for key, _label in REGISTRATION_FIELDS}
        identifier = access.canonical_uuid(member["person_uuid"])

        if identifier in identities:
            raise ValueError("Registration identity is ambiguous")

        identities.add(identifier)

        for key in ("submitted_at", "expires_at"):
            if member[key] and datetime.fromisoformat(member[key]).tzinfo is None:
                raise ValueError("Registration dates must include a timezone")

        members.append(member)

    return members


def first_registrations(report: object) -> dict[str, str]:
    result: dict[str, str] = {}

    for identifier, value in json_object(
        json_object(report)["first_registered"]
    ).items():
        identifier = access.canonical_uuid(identifier)
        instant = json_string(value)

        if datetime.fromisoformat(instant).tzinfo is None:
            raise ValueError("Registration dates must include a timezone")

        result[identifier] = instant

    return result


def _private_data(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())

        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o027:
            raise ValueError("Person activity requires a private regular file")

        data = stream.read(limit + 1)

    if len(data) > limit:
        raise ValueError("Person activity export is too large")

    return data


def _unique_fields(pairs: list[tuple[str, JSONValue]]) -> JSONObject:
    result: JSONObject = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate person activity field")

        result[key] = value

    return result


def person_activity(
    path: Path, snapshot: directory.Snapshot, now: float
) -> dict[str, PersonActivity]:
    key = _private_data(path.with_name("lookup.key"), 32)

    if len(key) != 32:
        raise ValueError("Person activity key is invalid")

    try:
        data = json_object(
            json.loads(
                _private_data(path, MAX_USAGE_METRICS_BYTES),
                object_pairs_hook=_unique_fields,
            )
        )
    except RecursionError as error:
        raise ValueError("Person activity export is nested too deeply") from error

    timestamp = json_number(data["timestamp"])

    if (
        not math.isfinite(timestamp)
        or not 0 <= now - timestamp <= 90
        or data["connected"] is not True
        or data["key_fingerprint"] != hashlib.sha256(key).hexdigest()
    ):
        raise ValueError("Person activity export is unavailable")

    subjects: dict[str, PersonActivity] = {}
    for subject, value in json_object(data["subjects"]).items():
        if re.fullmatch(r"[0-9a-f]{64}", subject) is None:
            raise ValueError("Person activity identifier is invalid")

        entry = json_object(value)
        last_at = entry["last_at"]
        recent = json_array(entry["recent"])

        if (
            type(last_at) is not int
            or not 0 <= last_at <= timestamp
            or len(recent) > 10
        ):
            raise ValueError("Person activity time is invalid")

        logins: list[AppLogin] = []
        previous = last_at

        for item in recent:
            login = json_object(item)
            at, app = login["at"], json_string(login["app"])

            if (
                type(at) is not int
                or not timestamp - 30 * 86400 <= at <= previous
                or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", app) is None
            ):
                raise ValueError("Recent app sign in is invalid")

            previous = at

            if at >= now - 30 * 86400:
                logins.append({"at": at, "app": app})

        subjects[subject] = {"last_at": last_at, "recent": logins}

    result: dict[str, PersonActivity] = {}
    for person in snapshot["people"]:
        digest = hmac.digest(key, person["uuid"].encode(), "sha256").hex()

        if digest in subjects:
            result[person["uuid"]] = subjects[digest]

    return result


def _display_time(value: str | int) -> str:
    zone = ZoneInfo("America/Los_Angeles")
    instant = (
        datetime.fromtimestamp(value, zone)
        if isinstance(value, int)
        else datetime.fromisoformat(value).astimezone(zone)
    )
    return instant.strftime("%B %-d, %Y, %-I:%M %p %Z")


def directory_dashboard(
    snapshot: directory.Snapshot | None,
    members: list[dict[str, str]] | None,
    first: dict[str, str] | None = None,
    activity: dict[str, PersonActivity] | None = None,
) -> JSONObject:
    dashboard = json_object(
        json.loads((DASHBOARDS / "templates/directory.json").read_text())
    )
    spec = json_object(dashboard["spec"])
    data: directory.Snapshot = snapshot or {
        "people": [],
        "groups": [],
        "memberships": [],
    }
    people = {person["uuid"]: person for person in data["people"]}
    groups = {group["uuid"]: group for group in data["groups"]}
    registrations = {member["person_uuid"]: member for member in members or []}
    names = {
        identifier: person["name"] + " (" + person["username"] + ")"
        for identifier, person in people.items()
    }

    choices: list[JSONValue] = [
        {
            "text": "Choose a person or group"
            if snapshot is not None
            else "Lookup unavailable",
            "value": "none",
        }
    ]
    choices.extend(
        {"text": "Person " + names[identifier], "value": "person:" + identifier}
        for identifier in people
    )
    choices.extend(
        {"text": "Group " + group["name"], "value": "group:" + identifier}
        for identifier, group in groups.items()
    )

    variable = json_object(json_object(json_array(spec["variables"])[0])["spec"])
    variable["query"] = json.dumps(choices)
    variable["current"] = choices[0]

    rows: dict[int, list[list[JSONValue]]] = {1: [], 2: [], 3: [], 4: [], 5: []}
    sizes: dict[str, str] = {}
    missing = "Not provided" if members is not None else "Unavailable"

    for identifier, person in people.items():
        registration = registrations.get(identifier, {})
        heard = "\n".join(
            value
            for key in ("heard_about", "referral_details")
            if (value := registration.get(key, ""))
        )
        first_at = first.get(identifier) if first is not None else None
        person_logins = activity.get(identifier) if activity is not None else None
        first_label = "Unavailable" if first is None else "Not recorded"
        last_label = "Unavailable" if activity is None else "No recorded sign ins"
        checked_at = person.get("checked_at")

        profile = [
            ("Name", person["name"] or "Not provided"),
            ("Preferred name", registration.get("preferred_name") or missing),
            ("Email", person["email"] or "Not provided"),
            ("Password MFA", person.get("password_mfa", "Unknown")),
            ("Passkeys", str(person.get("passkeys", "Unknown"))),
            (
                "Credentials checked",
                _display_time(checked_at) if checked_at else "Unknown",
            ),
            ("T shirt size", registration.get("shirt_size") or missing),
            ("Major", registration.get("studies") or missing),
            ("First registered", _display_time(first_at) if first_at else first_label),
            (
                "Last app sign in",
                _display_time(person_logins["last_at"])
                if person_logins
                else last_label,
            ),
            ("Heard from", heard or missing),
        ]
        rows[1].extend(
            ["person:" + identifier, field, value] for field, value in profile
        )

        if person_logins:
            rows[5].extend(
                ["person:" + identifier, login["at"] * 1000, login["app"]]
                for login in person_logins["recent"]
            )

        size = registration.get("shirt_size", "")
        sizes[identifier] = (
            (size if size in {"XS", "S", "M", "L", "XL", "XXL"} else "Other")
            if size
            else missing
        )

    size_counts: dict[str, dict[str, int]] = {identifier: {} for identifier in groups}
    for edge in data["memberships"]:
        person_uuid, group_uuid = edge["person_uuid"], edge["group_uuid"]
        rows[2].append(
            ["person:" + person_uuid, groups[group_uuid]["name"], edge["membership"]]
        )
        rows[3].append(
            [
                "group:" + group_uuid,
                names[person_uuid],
                people[person_uuid]["account"],
                edge["membership"],
            ]
        )

        size = sizes[person_uuid]
        size_counts[group_uuid][size] = size_counts[group_uuid].get(size, 0) + 1

    for group, counts in size_counts.items():
        rows[4].extend(
            ["group:" + group, size, counts[size]]
            for size in (
                "XS",
                "S",
                "M",
                "L",
                "XL",
                "XXL",
                "Other",
                "Not provided",
                "Unavailable",
            )
            if size in counts
        )

    fields: dict[int, list[tuple[str, str]]] = {
        1: [("Selection", "string"), ("Field", "string"), ("Value", "string")],
        2: [("Selection", "string"), ("Group", "string"), ("Membership", "string")],
        3: [
            ("Selection", "string"),
            ("Member", "string"),
            ("Account", "string"),
            ("Membership", "string"),
        ],
        4: [("Selection", "string"), ("Size", "string"), ("People", "number")],
        5: [("Selection", "string"), ("Time", "time"), ("App", "string")],
    }

    for element in json_object(spec["elements"]).values():
        panel = json_object(json_object(element)["spec"])
        panel_id = int(json_number(panel["id"]))
        query_group = json_object(json_object(panel["data"])["spec"])
        query = json_object(json_object(json_array(query_group["queries"])[0])["spec"])
        target = json_object(json_object(query["query"])["spec"])
        target["snapshot"] = [
            {
                "schema": {
                    "name": panel["title"],
                    "refId": "A",
                    "fields": [
                        {"name": name, "type": kind} for name, kind in fields[panel_id]
                    ],
                },
                "data": {
                    "values": [
                        [row[index] for row in rows[panel_id]]
                        for index in range(len(fields[panel_id]))
                    ]
                },
            }
        ]

        if snapshot is None:
            panel["title"] = "Lookup unavailable"
        elif panel_id == 5 and activity is None:
            panel["title"] = "Recent app sign ins unavailable"

    return dashboard


def write_lookup_dashboard(
    path: Path,
    snapshot: directory.Snapshot | None,
    members: list[dict[str, str]] | None,
    first: dict[str, str] | None = None,
    activity: dict[str, PersonActivity] | None = None,
) -> None:
    write_dashboard(
        path.with_name("directory.json"),
        directory_dashboard(snapshot, members, first, activity),
    )


def render_metrics(
    snapshot: Snapshot,
    probe_failures: int,
    group_failures: dict[str, int],
    started: float,
) -> str:
    lines: list[str] = []

    def metric(
        name: str, help_text: str, kind: str, values: Sequence[tuple[str, int | float]]
    ) -> None:
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"])
        lines.extend(f"{name}{labels} {value}" for labels, value in values)

    metric(
        "kanidm_observer_start_time_seconds",
        "Observer start time, counters reset on restart",
        "gauge",
        [("", started)],
    )
    metric(
        "kanidm_observer_poll_timestamp_seconds",
        "Time of the latest completed poll.",
        "gauge",
        [("", snapshot["timestamp"])],
    )
    metric(
        "kanidm_probe_success",
        "One when HTTPS status returns JSON true, does not verify database health",
        "gauge",
        [("", int(snapshot["probe_success"]))],
    )
    metric(
        "kanidm_probe_duration_seconds",
        "Elapsed time of the most recent status request, including failures.",
        "gauge",
        [("", snapshot["probe_duration"])],
    )
    metric(
        "kanidm_probe_failures_total",
        "Failed status probes observed since observer start.",
        "counter",
        [("", probe_failures)],
    )

    labels = {group: '{group="' + group + '"}' for group in snapshot["groups"]}
    metric(
        "kanidm_group_read_success",
        "One when this configured group's authenticated read succeeds.",
        "gauge",
        [
            (labels[group], int(result["success"]))
            for group, result in snapshot["groups"].items()
        ],
    )
    metric(
        "kanidm_group_members",
        "Direct members of configured groups, omitted on failed reads, never converted to zero",
        "gauge",
        [
            (labels[group], len(result["members"]))
            for group, result in snapshot["groups"].items()
            if result["success"] is True
        ],
    )
    metric(
        "kanidm_group_read_failures_total",
        "Failed configured-group reads observed since observer start.",
        "counter",
        [(labels[group], group_failures[group]) for group in snapshot["groups"]],
    )

    return "\n".join(lines) + "\n"


def credential_token(config: object) -> str:
    config = json_object(config)
    source = config if config.get("token") else config.get("monitoring")

    if not isinstance(source, dict):
        raise ValueError("Observer credentials are missing a token")

    token = json_object(source).get("token")

    if not isinstance(token, str) or not token:
        raise ValueError("Observer token must be a nonempty string")

    return token


class Observer:
    def __init__(
        self,
        url: str,
        token: str | None,
        ca: str | None,
        groups: list[str],
        credentials: Path | None = None,
        operations_url: str | None = None,
        include_members: bool = False,
        usage_metrics: Path | None = None,
        service_account: str = "directory_reader",
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", service_account):
            raise ValueError("Unknown observer service account")

        self.url = url.rstrip("/")
        self.service_account = service_account
        self.token = token
        self.groups = groups
        self.credentials = credentials
        self.operations_url = operations_url
        self.include_members = include_members
        self.usage_metrics = usage_metrics
        self.token_id: str | None = None
        self.credential_verified = False

        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
            NoRedirect(),
        )

        self.started = time.time()
        self.probe_failures = 0
        self.group_failures = dict.fromkeys(groups, 0)
        self.lock = threading.Lock()
        self.metrics = ""
        self.members: list[dict[str, str]] | None = None
        self.directory: directory.Snapshot | None = None
        self.first_registered: dict[str, str] | None = None
        self.activity: dict[str, PersonActivity] | None = None
        self.latencies: dict[str, list[float]] = {}

    def latency(self, name: str, elapsed: float, group: str | None = None) -> None:
        key = name + (f'{{group="{group}"}}' if group is not None else "")
        counts = self.latencies.setdefault(key, [0.0] * (len(LATENCY_BUCKETS) + 2))

        for index, bound in enumerate(LATENCY_BUCKETS):
            counts[index] += elapsed <= bound

        counts[-2] += 1
        counts[-1] += elapsed

    def latency_metrics(self) -> str:
        lines: list[str] = []
        families: set[str] = set()

        for key, counts in self.latencies.items():
            name, _, labels = key.partition("{")

            if name not in families:
                lines.extend(
                    [
                        f"# HELP {name} Observer request duration including failures",
                        f"# TYPE {name} histogram",
                    ]
                )
                families.add(name)

            labels = labels.removesuffix("}")
            prefix = labels + "," if labels else ""

            for index, bound in enumerate(LATENCY_BUCKETS):
                lines.append(f'{name}_bucket{{{prefix}le="{bound}"}} {counts[index]}')

            lines.append(f'{name}_bucket{{{prefix}le="+Inf"}} {counts[-2]}')
            suffix = "{" + labels + "}" if labels else ""
            lines.extend(
                [
                    f"{name}_count{suffix} {counts[-2]}",
                    f"{name}_sum{suffix} {counts[-1]}",
                ]
            )

        return "\n".join(lines) + "\n"

    def get(self, path: str, authenticated: bool = False) -> object:
        headers = {"Accept": "application/json"}

        if authenticated:
            if self.token is None:
                raise ValueError("Observer credential is unavailable")

            headers["Authorization"] = "Bearer " + self.token

        request = urllib.request.Request(self.url + path, headers=headers)
        with self.opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise ValueError("Unexpected response status")

            return json.load(response)

    def private_report(self, name: str) -> object:
        if (
            not self.credential_verified
            or self.token is None
            or self.operations_url is None
        ):
            raise ValueError("Observer credential is unavailable")

        request = urllib.request.Request(
            self.operations_url.removesuffix("/metrics") + "/" + name,
            headers={"Authorization": "Bearer " + self.token},
        )

        with self.opener.open(request, timeout=10) as response:
            payload = response.read(2 * 1024 * 1024 + 1)

            if response.status != 200 or len(payload) > 2 * 1024 * 1024:
                raise ValueError("Unexpected private report response")

            return json.loads(payload)

    def poll(self) -> Snapshot:
        snapshot: Snapshot = {
            "probe_success": False,
            "probe_duration": 0.0,
            "timestamp": 0.0,
            "groups": {},
        }
        self.credential_verified = False

        try:
            if self.credentials:
                config = json.loads(self.credentials.read_text())
                token = credential_token(config)
                attrs = self.get_identity(token)  # decoded metadata is not proof
                encoded = token.split(".")[1]
                metadata = json_object(
                    json.loads(
                        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                    )
                )

                if (
                    attrs.get("name") != [self.service_account]
                    or attrs.get("uuid") != [metadata["account_id"]]
                    or "service_account" not in attrs.get("class", [])
                ):
                    raise ValueError("Unexpected observer identity")

                if metadata.get("purpose", "readonly") != "readonly":
                    raise ValueError("Observer requires a read-only native API token")

                self.token = token
                self.token_id = json_string(metadata["token_id"])
                self.credential_verified = True
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RuntimeError,
            IndexError,
            HTTPException,
        ):
            self.token = None

        beginning = time.monotonic()
        with suppress(OSError, ValueError, urllib.error.URLError, HTTPException):
            snapshot["probe_success"] = self.get("/status") is True
        snapshot["probe_duration"] = time.monotonic() - beginning
        self.latency(
            "kanidm_probe_request_duration_seconds", snapshot["probe_duration"]
        )

        if not snapshot["probe_success"]:
            self.probe_failures += 1

        for group in self.groups:
            beginning = time.monotonic()
            try:
                if self.credentials and not self.credential_verified:
                    raise ValueError("Observer credential reload failed")

                members = read_group(
                    self.get(
                        "/scim/v1/Entry/"
                        + urllib.parse.quote(group, safe="")
                        + "?extAccessCheck=true&attributes=name,class,member",
                        True,
                    ),
                    group,
                )
                snapshot["groups"][group] = {"success": True, "members": members}
            except OSError, ValueError, TypeError, urllib.error.URLError, HTTPException:
                self.group_failures[group] += 1
                snapshot["groups"][group] = {"success": False}
            finally:
                self.latency(
                    "kanidm_group_read_duration_seconds",
                    time.monotonic() - beginning,
                    group,
                )

        snapshot["timestamp"] = time.time()
        metrics = render_metrics(
            snapshot, self.probe_failures, self.group_failures, self.started
        )
        metrics += self.latency_metrics()

        if self.usage_metrics is not None:
            try:
                if self.usage_metrics.is_symlink():
                    raise ValueError("Unexpected SSO metrics link")

                with self.usage_metrics.open("rb") as stream:
                    usage_encoded = stream.read(MAX_USAGE_METRICS_BYTES + 1)

                if len(usage_encoded) > MAX_USAGE_METRICS_BYTES:
                    raise ValueError("Oversized SSO metrics")

                usage = usage_encoded.decode("utf-8")
                timestamps = re.findall(
                    r"^identity_sso_export_timestamp_seconds ([0-9.]+)$",
                    usage,
                    re.MULTILINE,
                )

                if (
                    len(timestamps) != 1
                    or not 0 <= time.time() - float(timestamps[0]) <= 90
                ):
                    raise ValueError("SSO metrics are stale")

                connected = re.findall(
                    r"^identity_sso_collector_connected ([01](?:\.0+)?)$",
                    usage,
                    re.MULTILINE,
                )

                if len(connected) != 1:
                    raise ValueError("SSO collection state is unavailable")

                if any(
                    line
                    and not line.startswith(("identity_sso_", "identity_unix_", "# "))
                    for line in usage.splitlines()
                ):
                    raise ValueError("Unexpected SSO metrics")

                metrics += usage + "\nidentity_sso_metrics_read_success 1\n"
            except OSError, ValueError, UnicodeError:
                metrics += "identity_sso_metrics_read_success 0\n"

        if self.operations_url:
            try:
                request = urllib.request.Request(self.operations_url)
                with self.opener.open(request, timeout=10) as response:
                    extra = response.read(128 * 1024 + 1)
                    content_length = response.headers.get("Content-Length")

                    if (
                        response.status != 200
                        or len(extra) > 128 * 1024
                        or (
                            content_length is not None
                            and int(content_length) != len(extra)
                        )
                    ):
                        raise ValueError("Unexpected operations metrics response")

                    metrics += extra.decode("utf-8")
                metrics += "identity_operations_metrics_fetch_success 1\n"
            except OSError, ValueError, urllib.error.URLError, HTTPException:
                metrics += "identity_operations_metrics_fetch_success 0\n"

        if self.operations_url and self.include_members:
            self.members = None
            self.first_registered = None

            try:
                report = self.private_report("registrations")
                registration_rows = registration_members(report)
                first = first_registrations(report)

                self.members = registration_rows
                self.first_registered = first
                metrics += "identity_registration_export_success 1\n"
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                RuntimeError,
                urllib.error.URLError,
                HTTPException,
            ):
                self.members = None
                metrics += "identity_registration_export_success 0\n"

            self.directory = None
            try:
                self.directory = directory.read_snapshot(
                    self.private_report("directory")
                )
                metrics += "identity_directory_export_success 1\n"
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                RuntimeError,
                urllib.error.URLError,
                HTTPException,
            ):
                metrics += "identity_directory_export_success 0\n"

        self.activity = None

        if self.include_members and self.usage_metrics and self.directory is not None:
            try:
                self.activity = person_activity(
                    self.usage_metrics.with_name("people.json"),
                    self.directory,
                    time.time(),
                )
                metrics += "identity_person_activity_export_success 1\n"
            except OSError, ValueError, TypeError, KeyError:
                metrics += "identity_person_activity_export_success 0\n"

        with self.lock:
            self.metrics = metrics

        return snapshot

    def get_identity(self, token: str) -> dict[str, list[str]]:
        request = urllib.request.Request(
            self.url + "/v1/self",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + token,
            },
        )

        with self.opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise ValueError("Unexpected observer identity response")

            root = json_object(json.load(response))
            return native_attrs(json_object(root["youare"])["attrs"])


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        description="Read-only Kanidm metrics and Grafana registration reports"
    )
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--service-account", default="directory_reader")
    parser.add_argument("--url", help="Override credentials URL")
    parser.add_argument("--ca", help="Trusted CA path, overrides credentials ca_path")
    parser.add_argument(
        "--group",
        action="append",
        required=True,
        help="Read this exact group, repeat, at most 32",
    )
    parser.add_argument("--dashboard-output", type=Path)
    parser.add_argument(
        "--lookup-dashboard-output", "--member-dashboard-output", type=Path
    )
    parser.add_argument("--usage-metrics", type=Path)
    parser.add_argument(
        "--operations-url",
        help="CA-verified aggregate metrics from the local enrollment service",
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19101)
    parser.add_argument("--interval", type=float, default=15)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll, print aggregate metrics, write dashboard, then exit",
    )

    args = parser.parse_args(namespace=Options())
    groups = list(dict.fromkeys(args.group))

    if len(groups) > 32 or any(
        not re.fullmatch(r"[a-z0-9_.-]{1,100}", group) for group in groups
    ):
        parser.error(
            "Use at most 32 explicitly configured group names containing a-z, 0-9, _, ., or -"
        )

    if not math.isfinite(args.interval) or args.interval < 1:
        parser.error("--interval must be a finite value of at least one second")

    if args.lookup_dashboard_output:
        if not args.operations_url or not args.dashboard_output:
            parser.error(
                "Kanidm lookup requires the operations URL and public dashboard output"
            )

        public = args.dashboard_output.resolve().parent
        private = args.lookup_dashboard_output.resolve().parent

        if public == private or public in private.parents or private in public.parents:
            parser.error("Kanidm lookup must use a separate dashboard directory")

    try:
        credentials = json_object(json.loads(args.credentials.read_text()))
        token = credential_token(credentials)
    except (ValueError, OSError) as error:
        parser.error(str(error))

    url = args.url or credentials.get("url")

    if not isinstance(url, str):
        parser.error("Observer URL must be an HTTPS URL")

    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        parser.error("Observer URL must be an HTTPS URL")

    if (
        not token
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        parser.error("Credentials must contain a read-only token and an HTTPS URL")

    if args.operations_url and args.operations_url not in {
        "https://localhost:18643/operations/metrics",
        "https://portal:9443/operations/metrics",
    }:
        parser.error("Use the configured local or production operations metrics URL")

    ca = args.ca or credentials.get("ca_path")

    if ca is not None and not isinstance(ca, str):
        parser.error("Observer CA path must be a string")

    observer = Observer(
        url,
        token,
        ca,
        groups,
        args.credentials,
        args.operations_url,
        args.lookup_dashboard_output is not None,
        args.usage_metrics,
        args.service_account,
    )

    def poll() -> None:
        snapshot = observer.poll()

        if args.dashboard_output:
            for name in ("identity", "demographics", "usage"):
                write_dashboard(
                    args.dashboard_output.with_name(name + ".json"),
                    json_object(
                        json.loads(
                            (DASHBOARDS / "dashboards" / (name + ".json")).read_text()
                        )
                    ),
                )

            status = {
                "token_id": observer.token_id,
                "credential_verified": observer.credential_verified,
                "timestamp": snapshot["timestamp"],
            }
            path = args.dashboard_output.parent / "observer-status"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(status) + "\n")
            temporary.chmod(0o600)
            temporary.replace(path)

        if args.lookup_dashboard_output:
            write_lookup_dashboard(
                args.lookup_dashboard_output,
                observer.directory,
                observer.members,
                observer.first_registered,
                observer.activity,
            )

    poll()

    if args.once:
        print(observer.metrics, end="")
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/metrics":
                self.send_error(404)
                return

            with observer.lock:
                data = observer.metrics.encode()

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object, **_kwargs: object) -> None:
            pass

    server = MetricsHTTPServer((args.bind, args.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(
        f"Read-only observer listening on http://{args.bind}:{args.port}/metrics",
        flush=True,
    )

    while True:
        time.sleep(args.interval)
        poll()


if __name__ == "__main__":
    main()
