import hmac
import sqlite3
import uuid
from typing import TypedDict, TypeGuard

from contracts import is_object_dict

MARKER = "IDENTITY_UNIX_V1 "
WINDOWS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
DYNAMIC_UUID_MINIMUM = uuid.UUID("00000000-0000-0000-0001-000000000000")


class Event(TypedDict):
    event_id: str
    at: int
    subject: str
    client_id: str
    verified: bool


class Status(TypedDict):
    available: bool
    connected: bool
    capability_checked_at: float
    collection_started_at: float
    retained_since: float
    window_start_at: float
    window_end_at: float
    covered_seconds: float
    coverage_ratio: float | None


def is_event(value: object) -> TypeGuard[Event]:
    return is_object_dict(value) and "client_id" in value


def _uuid(value: object, *, dynamic: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid Unix event identifier")

    parsed = uuid.UUID(value)

    if str(parsed) != value or (dynamic and parsed < DYNAMIC_UUID_MINIMUM):
        raise ValueError("Invalid Unix event identifier")

    return value


def event(value: object, now: float) -> Event:
    if not is_object_dict(value) or set(value) != {
        "event_id",
        "at",
        "subject",
        "client_id",
        "verified",
    }:
        raise ValueError("Invalid Unix event fields")

    at = value["at"]

    if type(at) is not int or at < 0 or at > now + 300:
        raise ValueError("Invalid Unix event time")

    verified = value["verified"]

    if type(verified) is not bool:
        raise ValueError("Invalid Unix verification outcome")

    return {
        "event_id": _uuid(value["event_id"]),
        "at": at,
        "subject": _uuid(value["subject"], dynamic=True),
        "client_id": _uuid(value["client_id"], dynamic=True),
        "verified": verified,
    }


class UnixUsage:
    def __init__(self, database: sqlite3.Connection, key: bytes):
        self.db = database
        self.key = key
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS unix_events ("
            "id TEXT PRIMARY KEY, at INTEGER NOT NULL, subject TEXT NOT NULL,"
            "client_id TEXT NOT NULL, verified INTEGER NOT NULL CHECK(verified IN (0,1)));"
            "CREATE INDEX IF NOT EXISTS unix_events_at ON unix_events(at);"
            "CREATE INDEX IF NOT EXISTS unix_events_recent ON unix_events(at DESC,id DESC);"
            "CREATE INDEX IF NOT EXISTS unix_events_verified_recent "
            "ON unix_events(at DESC,id DESC) WHERE verified=1;"
            "CREATE INDEX IF NOT EXISTS unix_events_verified_subject_recent "
            "ON unix_events(subject,at DESC,id DESC) WHERE verified=1;"
            "CREATE TABLE IF NOT EXISTS unix_coverage (start REAL NOT NULL, end REAL NOT NULL);"
        )

        with self.db:
            self._set("connected", 0)
            self._set("available", 0)

    def _get(self, name: str) -> float:
        row = self.db.execute(
            "SELECT value FROM metadata WHERE key=?", ("unix_" + name,)
        ).fetchone()
        return float(row[0]) if row else 0.0

    def _set(self, name: str, value: float) -> None:
        self.db.execute(
            "INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("unix_" + name, str(value)),
        )

    def ingest(self, record: Event, now: float) -> bool:
        record = event(record, now)
        values = (
            record["event_id"],
            record["at"],
            hmac.digest(self.key, record["subject"].encode(), "sha256").hex(),
            record["client_id"],
            int(record["verified"]),
        )
        existing = self.db.execute(
            "SELECT * FROM unix_events WHERE id=?", (values[0],)
        ).fetchone()

        if existing is not None:
            if existing != values:
                raise ValueError("Conflicting Unix event identifier")

            return False

        if record["at"] < now - 31 * 86400:
            return False

        with self.db:
            self.db.execute("INSERT INTO unix_events VALUES (?,?,?,?,?)", values)
            self._set("last_event", max(self._get("last_event"), record["at"]))

        return True

    def capability(self, available: bool, now: float) -> None:
        with self.db:
            self._set("available", int(available))
            self._set("capability_checked", now)

            if not available:
                self._set("connected", 0)

    def heartbeat(self, now: float, connected: bool) -> None:
        connected = (
            connected
            and self._get("available") == 1
            and 0 <= now - self._get("capability_checked") <= 30
        )
        previous = self._get("heartbeat")
        was_connected = self._get("connected") == 1

        with self.db:
            if connected and not self._get("started"):
                self._set("started", now)

            if was_connected and connected and 0 < now - previous <= 30:
                latest = self.db.execute(
                    "SELECT rowid,end FROM unix_coverage ORDER BY rowid DESC LIMIT 1"
                ).fetchone()

                if latest and latest[1] == previous:
                    self.db.execute(
                        "UPDATE unix_coverage SET end=? WHERE rowid=?", (now, latest[0])
                    )
                else:
                    self.db.execute(
                        "INSERT INTO unix_coverage VALUES (?,?)", (previous, now)
                    )

            self._set("heartbeat", now)
            self._set("connected", int(connected))

    def _coverage(self, begin: float, now: float) -> tuple[float, float]:
        started = self._get("started")
        covered = 0.0
        through = max(begin, started)

        for start, end in self.db.execute(
            "SELECT start,end FROM unix_coverage WHERE start<? AND end>? ORDER BY start,end",
            (now, begin),
        ):
            lower = max(through, begin, start)
            upper = min(now, end)

            if upper > lower:
                covered += upper - lower
                through = upper

        return covered, max(0.0, now - max(begin, started))

    def status(self, now: float) -> Status:
        covered, elapsed = self._coverage(now - 30 * 86400, now)
        return {
            "available": self._get("available") == 1
            and 0 <= now - self._get("capability_checked") <= 30,
            "connected": self.connected(now),
            "capability_checked_at": self._get("capability_checked"),
            "collection_started_at": self._get("started"),
            "retained_since": now - 31 * 86400,
            "window_start_at": now - 30 * 86400,
            "window_end_at": now,
            "covered_seconds": covered,
            "coverage_ratio": min(1.0, covered / elapsed)
            if elapsed and self._get("started")
            else None,
        }

    def connected(self, now: float) -> bool:
        return (
            self._get("available") == 1
            and 0 <= now - self._get("capability_checked") <= 30
            and self._get("connected") == 1
            and 0 <= now - self._get("heartbeat") <= 30
        )

    def metrics(self, now: float) -> str:
        with self.db:
            self.db.execute("DELETE FROM unix_events WHERE at<?", (now - 31 * 86400,))
            self.db.execute(
                "DELETE FROM unix_coverage WHERE end<=?", (now - 31 * 86400,)
            )

        available = (
            self._get("available") == 1
            and 0 <= now - self._get("capability_checked") <= 30
        )
        connected = self.connected(now)
        started = self._get("started")
        lines = [
            f"identity_unix_events_available {int(available)}",
            f"identity_unix_collector_connected {int(connected)}",
            f"identity_unix_collection_started_timestamp_seconds {started}",
            f"identity_unix_collector_last_event_timestamp_seconds {self._get('last_event')}",
        ]

        if not started:
            return "\n".join(lines) + "\n"

        for window, seconds in WINDOWS.items():
            begin = now - seconds
            rows = self.db.execute(
                "SELECT verified,count(*) FROM unix_events WHERE at>=? AND at<=? GROUP BY verified",
                (begin, now),
            ).fetchall()
            counts = {int(verified): int(count) for verified, count in rows}

            for verified, label in ((1, "verified"), (0, "not_verified")):
                lines.append(
                    f'identity_unix_checks{{window="{window}",result="{label}"}} {counts.get(verified, 0)}'
                )

            accounts, readers = self.db.execute(
                "SELECT count(DISTINCT CASE WHEN verified=1 THEN subject END),"
                "count(DISTINCT client_id) FROM unix_events WHERE at>=? AND at<=?",
                (begin, now),
            ).fetchone()
            covered, elapsed = self._coverage(begin, now)
            ratio = str(min(1.0, covered / elapsed)) if elapsed else "NaN"
            lines.extend(
                [
                    f'identity_unix_verified_accounts{{window="{window}"}} {accounts}',
                    f'identity_unix_readers{{window="{window}"}} {readers}',
                    f'identity_unix_covered_seconds{{window="{window}"}} {covered}',
                    f'identity_unix_coverage_ratio{{window="{window}"}} {ratio}',
                ]
            )

        return "\n".join(lines) + "\n"
