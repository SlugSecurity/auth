#!/usr/bin/env python3

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import selectors
import signal
import sqlite3
import ssl
import stat
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from bisect import bisect_right
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import FrameType
from typing import NoReturn, TypedDict, TypeGuard
from zoneinfo import ZoneInfo

import unix_usage

UTC = timezone.utc
ZONE = ZoneInfo("America/Los_Angeles")
MARKER = "IDENTITY_SSO_V1 "
RECORD_LIMIT = 4096
PROBE_INTERVAL = 15
PROBE_TIMEOUT = 10
APP = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
CONTAINER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
JOURNAL_UNIT = re.compile(r"[a-zA-Z0-9_.@-]+\.service\Z")
DOCKER_TIME = re.compile(r"\A(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z) ")
NATIVE_INFO = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} )?"
    r"INFO[ \t│├└┕┖┗┃━─┌┐┬┤┘┴┼╰╭╷╵]*\uff49 \[info\]: \Z"
)


class Event(TypedDict):
    event_id: str
    at: int
    subject: str
    app_id: str
    app: str


class AppLogin(TypedDict):
    at: int
    app: str


class SubjectActivity(TypedDict):
    last_at: int
    recent: list[AppLogin]


class PeopleActivity(TypedDict):
    timestamp: float
    connected: bool
    key_fingerprint: str
    subjects: dict[str, SubjectActivity]


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid SSO identifier")

    return value


def _dictionary(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def event(value: object, now: float) -> Event:
    if not _dictionary(value) or set(value) != {
        "event_id",
        "at",
        "subject",
        "app_id",
        "app",
    }:
        raise ValueError("Invalid SSO event fields")

    at = value["at"]
    app = value["app"]

    if type(at) is not int or at < 0 or at > now + 300:
        raise ValueError("Invalid SSO event time")

    if not isinstance(app, str) or APP.fullmatch(app) is None:
        raise ValueError("Invalid SSO application")

    return {
        "event_id": canonical_uuid(value["event_id"]),
        "at": at,
        "subject": canonical_uuid(value["subject"]),
        "app_id": canonical_uuid(value["app_id"]),
        "app": app,
    }


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate SSO event field")

        result[key] = value

    return result


def _json(value: str | bytes) -> object:
    try:
        return json.loads(value, object_pairs_hook=_unique_fields)
    except RecursionError as error:
        raise ValueError("Invalid SSO JSON depth") from error


def read_line(
    line: bytes, now: float
) -> tuple[float, Event | unix_usage.Event | None] | None:
    if len(line) > RECORD_LIMIT + 1024:
        if MARKER.encode() in line or unix_usage.MARKER.encode() in line:
            raise ValueError("Oversized SSO log line")

        return None

    text = line.decode("utf-8", errors="strict").rstrip("\r\n")
    timestamp = DOCKER_TIME.match(text)

    if timestamp is None:
        return None

    whole, separator, fraction = timestamp[1][:-1].partition(".")
    normalized = whole + ("." + fraction[:6].ljust(6, "0") if separator else "")
    at = datetime.fromisoformat(normalized + "+00:00").timestamp()

    if not math.isfinite(at) or at < 0 or at > now + 300:
        raise ValueError("Invalid Docker log time")

    markers = [marker for marker in (MARKER, unix_usage.MARKER) if marker in text]

    if not markers:
        return at, None

    if len(markers) != 1:
        raise ValueError("Conflicting native event markers")

    marker = markers[0]
    prefix, payload = text.split(marker, 1)

    if (
        marker in payload
        or len(payload.encode()) > RECORD_LIMIT
        or NATIVE_INFO.fullmatch(prefix[timestamp.end() :]) is None
    ):
        raise ValueError("Invalid SSO log framing")

    value = _json(payload)
    return at, (
        unix_usage.event(value, now)
        if marker == unix_usage.MARKER
        else event(value, now)
    )


def _journal_line(line: bytes) -> bytes:
    if len(line) > 65536:
        raise ValueError("Oversized journal record")

    value = _json(line)

    if not _dictionary(value):
        raise ValueError("Invalid journal record")

    message = value.get("MESSAGE")
    timestamp = value.get("__REALTIME_TIMESTAMP")

    if not isinstance(message, str) or not isinstance(timestamp, str):
        raise ValueError("Invalid journal message")

    if re.fullmatch(r"[0-9]{1,20}", timestamp) is None:
        raise ValueError("Invalid journal time")

    instant = datetime.fromtimestamp(int(timestamp) / 1_000_000, UTC)
    prefix = instant.isoformat().replace("+00:00", "Z")
    return (prefix + " " + message).encode()


def read_journal_line(
    line: bytes, now: float
) -> tuple[float, Event | unix_usage.Event | None] | None:
    return read_line(_journal_line(line), now)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _native_get(url: str, ca: Path, path: str) -> tuple[bytes, str | None]:
    origin = urllib.parse.urlsplit(url)

    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path not in {"", "/"}
        or origin.query
        or origin.fragment
    ):
        raise ValueError("SSO collector requires a native HTTPS origin")

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
    )
    request = urllib.request.Request(
        url.rstrip("/") + path, headers={"Cache-Control": "no-cache, no-store"}
    )

    with opener.open(request, timeout=5) as response:
        data = response.read(RECORD_LIMIT + 1)
        identifier = response.headers.get("x-kanidm-opid")

    if len(data) > RECORD_LIMIT:
        raise ValueError("Oversized native probe response")

    return data, identifier


def verify_capability(url: str, ca: Path) -> bool:
    data, _identifier = _native_get(url, ca, "/v1/identity/_capabilities")
    value = _json(data)

    if (
        not _dictionary(value)
        or type(value.get("usage_events")) is not int
        or value["usage_events"] != 1
    ):
        raise ValueError("Native SSO events are unavailable")

    return (
        type(value.get("unix_usage_events")) is int and value["unix_usage_events"] == 1
    )


def probe_source(url: str, ca: Path, client: str) -> str:
    if APP.fullmatch(client) is None:
        raise ValueError("Invalid native probe client")

    data, identifier = _native_get(
        url, ca, f"/oauth2/openid/{client}/.well-known/openid-configuration"
    )
    value = _json(data)

    if not _dictionary(value) or not isinstance(value.get("issuer"), str):
        raise ValueError("Native discovery probe is unavailable")

    return canonical_uuid(identifier)


def probe_seen(line: bytes, identifier: str, client: str) -> bool:
    text = line.decode("utf-8", errors="strict").rstrip("\r\n")
    timestamp = DOCKER_TIME.match(text)

    if timestamp is None:
        return False

    message = text[timestamp.end() :]
    uri = f"/oauth2/openid/{client}/.well-known/openid-configuration"
    pattern = (
        re.escape(identifier)
        + r" INFO +request \[[^\]\r\n]{1,128}\] method: GET \| uri: "
        + re.escape(uri)
        + r' \| version: HTTP/(?:1\.0|1\.1|2\.0|3\.0) \| connection_address: "[^"\r\n]*"'
        + r' \| client_address: "[^"\r\n]*" \| status_code: 200 \| latency: [0-9]+'
        + r' \| kopid: "'
        + re.escape(identifier)
        + r'"\Z'
    )
    return re.fullmatch(pattern, message) is not None


def month_start(value: datetime) -> datetime:
    return value.astimezone(ZONE).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )


def shift_month(value: datetime, count: int) -> datetime:
    index = value.year * 12 + value.month - 1 + count
    return value.replace(year=index // 12, month=index % 12 + 1)


def week_start(value: datetime) -> datetime:
    day = value.astimezone(ZONE).replace(hour=0, minute=0, second=0, microsecond=0)
    return day - timedelta(days=day.weekday())


def week_name(start: datetime) -> str:
    last = start + timedelta(days=6)

    if start.year != last.year:
        return (
            f"{start:%b} {start.day}, {start.year} - {last:%b} {last.day}, {last.year}"
        )

    if start.month != last.month:
        return f"{start:%b} {start.day} - {last:%b} {last.day}, {last.year}"

    return f"{start:%b} {start.day} - {last.day}, {last.year}"


def _private(path: Path, mode: int) -> None:
    metadata = path.lstat()

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise ValueError("SSO state must be a private owned regular file")


def _directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or path.resolve() != path.absolute()
    ):
        raise ValueError("SSO state requires a private owned directory")


class _Coverage:
    def __init__(self, rows: list[tuple[float, float]]):
        intervals: list[tuple[float, float]] = []

        for start, end in sorted(rows):
            if not math.isfinite(start) or not math.isfinite(end) or end < start:
                raise ValueError("Invalid SSO coverage interval")

            if end == start:
                continue

            if intervals and start <= intervals[-1][1]:
                intervals[-1] = (intervals[-1][0], max(intervals[-1][1], end))
            else:
                intervals.append((start, end))

        self.starts = [start for start, _end in intervals]
        self.ends = [end for _start, end in intervals]
        self.totals = [0.0]

        for start, end in intervals:
            self.totals.append(self.totals[-1] + (end - start))

    def _before(self, value: float) -> float:
        index = bisect_right(self.starts, value) - 1

        if index < 0:
            return 0.0

        return self.totals[index] + (min(value, self.ends[index]) - self.starts[index])

    def seconds(self, start: float, end: float) -> float:
        if end <= start:
            return 0.0

        return self._before(end) - self._before(start)


class Store:
    def __init__(self, directory: Path):
        _directory(directory)
        self.directory = directory
        database = directory / "usage.sqlite3"
        key_path = directory / "subject.key"

        if not key_path.exists():
            if database.exists():
                raise ValueError("SSO subject key is missing")

            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())

        _private(key_path, 0o600)
        self.key = key_path.read_bytes()

        if len(self.key) != 32:
            raise ValueError("Invalid SSO subject key")

        if not database.exists():
            descriptor = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)

        _private(database, 0o600)
        self.db = sqlite3.connect(database, timeout=10)
        self.db.executescript(
            "PRAGMA synchronous=FULL;"
            "PRAGMA secure_delete=ON;"
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS events ("
            "id TEXT PRIMARY KEY, at INTEGER NOT NULL, subject TEXT NOT NULL,"
            "app_id TEXT NOT NULL, app TEXT NOT NULL, month TEXT NOT NULL,"
            "day TEXT NOT NULL, weekday INTEGER NOT NULL, hour INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS events_month ON events(month);"
            "CREATE INDEX IF NOT EXISTS events_app ON events(app_id,at DESC,id DESC);"
            "CREATE TABLE IF NOT EXISTS coverage (start REAL NOT NULL, end REAL NOT NULL);"
        )

        fingerprint = hashlib.sha256(self.key).hexdigest()
        current = self._get("key_fingerprint")

        if current is not None and current != fingerprint:
            self.db.close()
            raise ValueError("SSO subject key does not match the database")

        with self.db:
            self._set("key_fingerprint", fingerprint)

        self.unix = unix_usage.UnixUsage(self.db, self.key)

    def close(self) -> None:
        self.db.close()

    def _get(self, key: str) -> str | None:
        row = self.db.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchone()
        value: object = row[0] if row else None

        if value is not None and not isinstance(value, str):
            raise ValueError("Invalid SSO storage metadata")

        return value

    def _number(self, key: str) -> float:
        return float(self._get(key) or "0")

    def _set(self, key: str, value: str | int | float) -> None:
        self.db.execute(
            "INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def count_failure(self, key: str) -> None:
        if key not in {"failures", "rejected"}:
            raise ValueError("Invalid SSO collector counter")

        with self.db:
            self._set(key, self._number(key) + 1)

    def ingest(self, record: Event, now: float) -> bool:
        record = event(record, now)
        instant = datetime.fromtimestamp(record["at"], ZONE)
        cutoff = shift_month(month_start(datetime.fromtimestamp(now, ZONE)), -12)
        digest = hmac.digest(self.key, record["subject"].encode(), "sha256").hex()
        values = (
            record["event_id"],
            record["at"],
            digest,
            record["app_id"],
            record["app"],
            instant.strftime("%Y-%m"),
            instant.strftime("%Y-%m-%d"),
            instant.weekday(),
            instant.hour,
        )

        existing = self.db.execute(
            "SELECT * FROM events WHERE id=?", (values[0],)
        ).fetchone()

        if existing is not None:
            if existing != values:
                raise ValueError("Conflicting SSO event identifier")

            return False

        if instant < cutoff:
            return False

        with self.db:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)", values)
            self._set("last_event", max(self._number("last_event"), record["at"]))

        return True

    def checkpoint(self, timestamp: float) -> None:
        with self.db:
            self._set("checkpoint", max(timestamp, self._number("checkpoint")))

    def probe(self, identifier: str) -> None:
        canonical_uuid(identifier)

        if identifier == self._get("last_probe"):
            raise ValueError("Native probe operation identifier was reused")

        with self.db:
            self._set("last_probe", identifier)

    def heartbeat(self, now: float, connected: bool) -> None:
        previous = self._number("heartbeat")
        was_connected = self._get("connected") == "1"

        with self.db:
            if connected and self._get("started") is None:
                self._set("started", now)

            if was_connected and connected and 0 < now - previous <= 30:
                latest = self.db.execute(
                    "SELECT rowid, end FROM coverage ORDER BY rowid DESC LIMIT 1"
                ).fetchone()

                if latest and latest[1] == previous:
                    self.db.execute(
                        "UPDATE coverage SET end=? WHERE rowid=?", (now, latest[0])
                    )
                else:
                    self.db.execute(
                        "INSERT INTO coverage VALUES (?,?)", (previous, now)
                    )

            self._set("heartbeat", now)
            self._set("connected", int(connected))

            if connected:
                self._set("last_read", now)

        self.unix.heartbeat(now, connected)

    def resume(self, now: float) -> str:
        earliest = shift_month(
            month_start(datetime.fromtimestamp(now, ZONE)), -12
        ).timestamp()
        checkpoint = self._number("checkpoint")
        value = max(earliest, min(checkpoint, now) - 60) if checkpoint else earliest
        return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")

    def people(self, now: float) -> PeopleActivity:
        cutoff = shift_month(
            month_start(datetime.fromtimestamp(now, ZONE)), -12
        ).timestamp()
        subjects: dict[str, SubjectActivity] = {
            str(subject): {"last_at": int(last_at), "recent": []}
            for subject, last_at in self.db.execute(
                "SELECT subject,max(at) FROM events WHERE at>=? AND at<=? GROUP BY subject",
                (cutoff, now),
            )
        }

        for subject, at, app in self.db.execute(
            "SELECT subject,at,app FROM ("
            "SELECT subject,at,app,id,row_number() OVER ("
            "PARTITION BY subject ORDER BY at DESC,id DESC) AS position "
            "FROM events WHERE at>=? AND at<=?) "
            "WHERE position<=10 ORDER BY subject,at DESC,id DESC",
            (now - 30 * 86400, now),
        ):
            subjects[str(subject)]["recent"].append({"at": int(at), "app": str(app)})

        return {
            "timestamp": now,
            "connected": self._get("connected") == "1"
            and 0 <= now - self._number("heartbeat") <= 30,
            "key_fingerprint": hashlib.sha256(self.key).hexdigest(),
            "subjects": subjects,
        }

    def metrics(self, now: float) -> str:
        local_now = datetime.fromtimestamp(now, ZONE)
        current = month_start(local_now)
        cutoff = shift_month(current, -12)

        with self.db:
            self.db.execute(
                "DELETE FROM events WHERE month<?", (cutoff.strftime("%Y-%m"),)
            )
            self.db.execute("DELETE FROM coverage WHERE end<=?", (cutoff.timestamp(),))

        lines: list[str] = []

        def sample(name: str, value: int | float, **labels: str) -> None:
            suffix = (
                "{"
                + ",".join(f'{key}="{value}"' for key, value in labels.items())
                + "}"
                if labels
                else ""
            )
            number = "NaN" if math.isnan(value) else str(value)
            lines.append(f"identity_sso_{name}{suffix} {number}")

        for name, key in (
            ("collection_started_timestamp_seconds", "started"),
            ("collector_last_read_timestamp_seconds", "last_read"),
            ("collector_last_event_timestamp_seconds", "last_event"),
            ("collector_checkpoint_timestamp_seconds", "checkpoint"),
            ("collector_connected", "connected"),
            ("collector_failures_total", "failures"),
            ("collector_rejected_total", "rejected"),
        ):
            sample(name, self._number(key))

        sample("export_timestamp_seconds", now)

        for weekday in range(7):
            for hour in range(24):
                sample(
                    "period_weekday_hour_grid",
                    math.nan,
                    weekday=str(weekday),
                    hour=f"{hour:02}",
                )

        started = self._number("started")
        coverage = _Coverage(
            [
                (float(start), float(end))
                for start, end in self.db.execute("SELECT start,end FROM coverage")
            ]
        )
        apps = {
            str(app_id): str(
                self.db.execute(
                    "SELECT app FROM events WHERE app_id=? AND at<=? ORDER BY at DESC,id DESC LIMIT 1",
                    (app_id, now),
                ).fetchone()[0]
            )
            for (app_id,) in self.db.execute(
                "SELECT DISTINCT app_id FROM events WHERE at<=?", (now,)
            )
        }
        months = {
            str(row[0])
            for row in self.db.execute(
                "SELECT DISTINCT month FROM events WHERE at<=?", (now,)
            )
        }

        if started:
            beginning = max(month_start(datetime.fromtimestamp(started, ZONE)), cutoff)
            while beginning <= current:
                months.add(beginning.strftime("%Y-%m"))
                beginning = shift_month(beginning, 1)

        for month in sorted(months):
            start = datetime.strptime(month, "%Y-%m").replace(tzinfo=ZONE)
            end = min(shift_month(start, 1).timestamp(), now)

            if end < start.timestamp():
                continue

            signins, users = self.db.execute(
                "SELECT count(*), count(DISTINCT subject) FROM events WHERE month=? AND at<=?",
                (month, now),
            ).fetchone()

            last_day = min(
                local_now.date(), (shift_month(start, 1) - timedelta(days=1)).date()
            )
            elapsed_days = (last_day - start.date()).days + 1
            covered = coverage.seconds(start.timestamp(), end)
            duration = end - start.timestamp()

            sample(
                "month_coverage_ratio",
                min(covered / duration, 1) if duration > 0 else 0,
                month=month,
            )

            if signins == 0 and covered == 0:
                continue

            sample(
                "month_start_timestamp_seconds",
                start.timestamp(),
                month=month,
                month_name=start.strftime("%B %Y"),
            )
            sample(
                "period_start_timestamp_seconds",
                start.timestamp(),
                kind="month",
                period=month,
                period_name=start.strftime("%B %Y"),
                time_from="now/M",
                time_shift=f"{(current.year - start.year) * 12 + current.month - start.month}M/M",
            )
            sample("month_signins", signins, month=month)
            sample("month_users", users, month=month)
            sample("month_signins_per_day", signins / elapsed_days, month=month)

            days = {
                str(day): (int(count), int(daily_users))
                for day, count, daily_users in self.db.execute(
                    "SELECT day,count(*),count(DISTINCT subject) FROM events WHERE month=? AND at<=? GROUP BY day",
                    (month, now),
                )
            }
            app_days = {
                (str(day), str(app_id)): int(count)
                for day, app_id, count in self.db.execute(
                    "SELECT day,app_id,count(*) FROM events WHERE month=? AND at<=? GROUP BY day,app_id",
                    (month, now),
                )
            }

            day = start
            for _ in range(elapsed_days):
                label = day.strftime("%Y-%m-%d")
                day_end = min((day + timedelta(days=1)).timestamp(), now)
                day_coverage = coverage.seconds(day.timestamp(), day_end)
                day_duration = day_end - day.timestamp()
                ratio = min(day_coverage / day_duration, 1) if day_duration > 0 else 0

                if label in days or ratio >= 1:
                    count, daily_users = days.get(label, (0, 0))
                    sample("day_signins", count, month=month, day=label)
                    sample("day_users", daily_users, month=month, day=label)
                    sample("day_coverage_ratio", ratio, month=month, day=label)

                for app_id, app in apps.items():
                    count = app_days.get((label, app_id), 0)

                    if count or ratio >= 1:
                        sample(
                            "app_day_signins",
                            count,
                            month=month,
                            week=week_start(day).strftime("%Y-%m-%d"),
                            day=label,
                            app=app,
                            app_id=app_id,
                        )

                day += timedelta(days=1)

            for app_id, count, app_users in self.db.execute(
                "SELECT app_id,count(*),count(DISTINCT subject) FROM events WHERE month=? AND at<=? GROUP BY app_id",
                (month, now),
            ):
                app = apps[app_id]
                sample("app_month_signins", count, month=month, app=app, app_id=app_id)
                sample(
                    "app_month_users", app_users, month=month, app=app, app_id=app_id
                )

            bins = {
                (int(day), int(hour)): int(count)
                for day, hour, count in self.db.execute(
                    "SELECT weekday,hour,count(*) FROM events WHERE month=? AND at<=? GROUP BY weekday,hour",
                    (month, now),
                )
            }
            exposure: dict[tuple[int, int], float] = {}
            observed: dict[tuple[int, int], float] = {}
            cursor = start.timestamp()

            while cursor < end:
                next_hour = min(cursor + 3600, end)
                local = datetime.fromtimestamp(cursor, ZONE)
                slot = local.weekday(), local.hour
                exposure[slot] = exposure.get(slot, 0.0) + (next_hour - cursor)
                observed[slot] = observed.get(slot, 0.0) + coverage.seconds(
                    cursor, next_hour
                )
                cursor = next_hour

            for weekday in range(7):
                for hour in range(24):
                    slot = weekday, hour
                    count = bins.get(slot, 0)

                    if count == 0 and (
                        exposure.get(slot, 0.0) == 0
                        or observed.get(slot, 0.0) < exposure[slot]
                    ):
                        continue

                    sample(
                        "weekday_hour_signins",
                        count,
                        month=month,
                        weekday=str(weekday),
                        hour=f"{hour:02}",
                    )

        first_event = self.db.execute(
            "SELECT min(at) FROM events WHERE at<=?", (now,)
        ).fetchone()[0]
        beginnings = [value for value in (started, first_event) if value]

        if not beginnings:
            return "\n".join(lines) + "\n" + self.unix.metrics(now)

        weekly_totals = {
            str(key): (int(signins), int(users))
            for key, signins, users in self.db.execute(
                "SELECT date(day,'-6 days','weekday 1'),count(*),count(DISTINCT subject) "
                "FROM events WHERE at<=? GROUP BY 1",
                (now,),
            )
        }

        weekly_apps: dict[str, list[tuple[str, int, int]]] = {}
        for key, app_id, count, app_users in self.db.execute(
            "SELECT date(day,'-6 days','weekday 1'),app_id,count(*),count(DISTINCT subject) "
            "FROM events WHERE at<=? GROUP BY 1,app_id",
            (now,),
        ):
            weekly_apps.setdefault(str(key), []).append(
                (str(app_id), int(count), int(app_users))
            )

        weekly_days = dict(
            self.db.execute(
                "SELECT day,count(*) FROM events WHERE at<=? GROUP BY day", (now,)
            )
        )
        weekly_hours = {
            (str(key), int(hour)): int(count)
            for key, hour, count in self.db.execute(
                "SELECT date(day,'-6 days','weekday 1'),hour,count(*) "
                "FROM events WHERE at<=? GROUP BY 1,hour",
                (now,),
            )
        }
        weekly_bins = {
            (str(key), int(weekday), int(hour)): int(count)
            for key, weekday, hour, count in self.db.execute(
                "SELECT date(day,'-6 days','weekday 1'),weekday,hour,count(*) "
                "FROM events WHERE at<=? GROUP BY 1,weekday,hour",
                (now,),
            )
        }
        week = week_start(
            datetime.fromtimestamp(max(min(beginnings), cutoff.timestamp()), ZONE)
        )

        if week < cutoff:
            week += timedelta(days=7)

        current_week = week_start(local_now)

        while week <= current_week:
            end = min((week + timedelta(days=7)).timestamp(), now)

            if end < week.timestamp():
                break

            label = week.strftime("%Y-%m-%d")
            last_day = min(local_now.date(), (week + timedelta(days=6)).date())
            signins, users = weekly_totals.get(label, (0, 0))
            covered = coverage.seconds(week.timestamp(), end)
            duration = end - week.timestamp()

            sample(
                "week_coverage_ratio",
                min(covered / duration, 1) if duration > 0 else 0,
                week=label,
            )

            if not signins and not covered:
                week += timedelta(days=7)
                continue

            sample(
                "period_start_timestamp_seconds",
                week.timestamp(),
                kind="week",
                period=label,
                period_name=week_name(week),
                time_from="now/w",
                time_shift=f"{(current_week.date() - week.date()).days // 7}w/w",
            )
            sample("week_signins", signins, week=label)
            sample("week_users", users, week=label)
            elapsed_days = (last_day - week.date()).days + 1
            sample("week_signins_per_day", signins / elapsed_days, week=label)

            for offset in range(elapsed_days):
                day = week + timedelta(days=offset)
                day_end = min((day + timedelta(days=1)).timestamp(), now)
                day_label = day.strftime("%Y-%m-%d")

                if day_label in weekly_days or (
                    day_end > day.timestamp()
                    and coverage.seconds(day.timestamp(), day_end)
                    >= day_end - day.timestamp()
                ):
                    sample(
                        "week_day_signins",
                        weekly_days.get(day_label, 0),
                        week=label,
                        day=day_label,
                    )

            for app_id, count, app_users in weekly_apps.get(label, []):
                sample(
                    "app_week_signins",
                    count,
                    week=label,
                    app=apps[app_id],
                    app_id=app_id,
                )
                sample(
                    "app_week_users",
                    app_users,
                    week=label,
                    app=apps[app_id],
                    app_id=app_id,
                )

            hour_exposure = [0.0] * 24
            hour_observed = [0.0] * 24
            slot_exposure: dict[tuple[int, int], float] = {}
            slot_observed: dict[tuple[int, int], float] = {}
            cursor = week.timestamp()

            while cursor < end:
                next_hour = min(cursor + 3600, end)
                local = datetime.fromtimestamp(cursor, ZONE)
                slot = local.weekday(), local.hour
                duration = next_hour - cursor
                observed_seconds = coverage.seconds(cursor, next_hour)
                hour_exposure[local.hour] += duration
                hour_observed[local.hour] += observed_seconds
                slot_exposure[slot] = slot_exposure.get(slot, 0.0) + duration
                slot_observed[slot] = slot_observed.get(slot, 0.0) + observed_seconds
                cursor = next_hour

            for hour in range(24):
                count = weekly_hours.get((label, hour), 0)

                if count or (
                    hour_exposure[hour] > 0
                    and hour_observed[hour] >= hour_exposure[hour]
                ):
                    sample("week_hour_signins", count, week=label, hour=f"{hour:02}")

            for weekday in range(7):
                for hour in range(24):
                    slot = weekday, hour
                    count = weekly_bins.get((label, weekday, hour), 0)
                    known = count > 0 or (
                        slot_exposure.get(slot, 0.0) > 0
                        and slot_observed.get(slot, 0.0) >= slot_exposure[slot]
                    )

                    if not known:
                        continue

                    sample(
                        "week_weekday_hour_signins",
                        count,
                        week=label,
                        weekday=str(weekday),
                        hour=f"{hour:02}",
                    )

            week += timedelta(days=7)

        return "\n".join(lines) + "\n" + self.unix.metrics(now)


def _write_export(output: Path, data: bytes, *, keep_unchanged: bool = False) -> None:
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    metadata = output.parent.lstat()

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or output.parent.resolve() != output.parent.absolute()
    ):
        raise ValueError("SSO metrics require an owned directory without write sharing")

    if output.exists() or output.is_symlink():
        _private(output, 0o640)

        if keep_unchanged and output.read_bytes() == data:
            return

    temporary = output.with_name(output.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)

    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def export(store: Store, output: Path, now: float) -> None:
    _write_export(output, store.metrics(now).encode())
    _write_export(output.with_name("lookup.key"), store.key, keep_unchanged=True)
    _write_export(
        output.with_name("people.json"),
        (json.dumps(store.people(now), separators=(",", ":")) + "\n").encode(),
    )


@contextlib.contextmanager
def collector_lock(directory: Path) -> Generator[None, None, None]:
    path = directory / "collector.lock"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        _private(path, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def follow(
    store: Store,
    container: str | None,
    output: Path,
    journal_unit: str | None = None,
    *,
    native_url: str,
    ca: Path,
    probe_client: str,
) -> None:
    if (container is None) == (journal_unit is None):
        raise ValueError("Exactly one Kanidm log source is required")

    resume = store.resume(time.time())

    if container is not None:
        if CONTAINER.fullmatch(container) is None:
            raise ValueError("Invalid Kanidm container name")

        command = [
            "docker",
            "logs",
            "--follow",
            "--timestamps",
            "--since",
            resume,
            container,
        ]
    else:
        if journal_unit is None or JOURNAL_UNIT.fullmatch(journal_unit) is None:
            raise ValueError("Invalid Kanidm journal unit")

        command = [
            "journalctl",
            "--unit",
            journal_unit,
            "--output=json",
            "--follow",
            "--no-tail",
            "--since",
            resume,
            "--no-pager",
        ]

    store.unix.capability(verify_capability(native_url, ca), time.time())

    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as process:
        if process.stdout is None:
            raise RuntimeError("Kanidm log stream is unavailable")

        os.set_blocking(process.stdout.fileno(), False)
        buffer = bytearray()
        dropping = False
        last_export = 0.0
        next_probe = 0.0
        pending_probe: str | None = None
        pending_since = 0.0
        pending_after = 0.0

        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while True:
                    clock = time.monotonic()

                    if pending_probe is None and clock >= next_probe:
                        store.unix.capability(
                            verify_capability(native_url, ca), time.time()
                        )
                        pending_after = time.time() - 1
                        pending_probe = probe_source(native_url, ca, probe_client)
                        store.probe(pending_probe)
                        pending_since = time.monotonic()
                        next_probe = pending_since + PROBE_INTERVAL

                    ready = selector.select(timeout=1)
                    now = time.time()

                    if ready:
                        chunk = os.read(process.stdout.fileno(), 65536)

                        if not chunk:
                            break

                        buffer.extend(chunk)
                        checkpoint = 0.0

                        while b"\n" in buffer:
                            newline = buffer.index(b"\n")
                            line = bytes(buffer[:newline])
                            del buffer[: newline + 1]

                            if dropping:
                                dropping = False
                                continue

                            try:
                                transport = (
                                    _journal_line(line) if journal_unit else line
                                )
                                parsed = read_line(transport, now)

                                if parsed is None:
                                    continue

                                timestamp, record = parsed

                                if record:
                                    if unix_usage.is_event(record):
                                        store.unix.ingest(record, now)
                                    else:
                                        store.ingest(event(record, now), now)
                                checkpoint = max(timestamp, checkpoint)

                                if (
                                    pending_probe
                                    and timestamp >= pending_after
                                    and probe_seen(
                                        transport, pending_probe, probe_client
                                    )
                                ):
                                    store.heartbeat(now, True)
                                    pending_probe = None
                                    export(store, output, now)
                                    last_export = time.monotonic()
                            except (ValueError, UnicodeError, OverflowError):
                                store.count_failure("rejected")

                        if checkpoint:
                            store.checkpoint(checkpoint)

                        if len(buffer) > (
                            65536 if journal_unit else RECORD_LIMIT + 1024
                        ):
                            store.count_failure("rejected")
                            buffer.clear()
                            dropping = True

                    clock = time.monotonic()

                    if pending_probe and clock - pending_since > PROBE_TIMEOUT:
                        raise OSError("Native log transport probe was not observed")

                    if clock - last_export >= 15:
                        export(store, output, now)
                        last_export = clock
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

                store.heartbeat(time.time(), False)
                export(store, output, time.time())


class Options(argparse.Namespace):
    state: Path
    output: Path
    container: str | None
    journal_unit: str | None
    native_url: str
    ca: Path
    probe_client: str


def stop(_signum: int, _frame: FrameType | None) -> NoReturn:
    raise SystemExit(0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-url", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--probe-client", required=True)

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--container")
    source.add_argument("--journal-unit")

    options = parser.parse_args(namespace=Options())

    signal.signal(signal.SIGTERM, stop)
    store = Store(options.state)
    try:
        with collector_lock(options.state):
            store.heartbeat(time.time(), False)

            while True:
                with contextlib.suppress(
                    OSError, subprocess.SubprocessError, ValueError
                ):
                    follow(
                        store,
                        options.container,
                        options.output,
                        options.journal_unit,
                        native_url=options.native_url,
                        ca=options.ca,
                        probe_client=options.probe_client,
                    )

                store.count_failure("failures")
                export(store, options.output, time.time())
                time.sleep(5)
    finally:
        store.close()


if __name__ == "__main__":
    main()
