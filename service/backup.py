#!/usr/bin/env python3

import argparse
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import tomllib
import uuid
from collections.abc import Generator, Sequence
from contextlib import AbstractContextManager, closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import NotRequired, Protocol, TypedDict

from contracts import (
    JSONObject,
    JSONValue,
    is_json_object,
    json_array,
    json_object,
    json_string,
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.11.2"
SERVICES = ("portal", "access", "posix", "kanidm")
TRANSIENT = (".lock", ".pid", ".log", "-wal", "-shm", "-journal", ".klock")
COMPONENTS = {
    "portal",
    "posix",
    "configuration",
    "pki",
    "branding",
    "portal-ui",
}
OPTIONAL_COMPONENTS = {"usage"}


type PathValue = str | Path


class NativeConfig(TypedDict):
    data: str
    server_config: str
    image: NotRequired[str]
    tls: NotRequired[str | None]
    uid: NotRequired[int]
    gid: NotRequired[int]


class BackupPlan(TypedDict):
    environment: str
    compose: str
    lock: str
    roots: dict[str, str]
    recipients: str
    destination: str
    native: NativeConfig
    files: NotRequired[dict[str, str]]
    offsite: NotRequired[str | None]


class NativeBackend(Protocol):
    def run(
        self,
        operation: str,
        data: PathValue,
        config: PathValue,
        export: PathValue | None = None,
        tls: PathValue | None = None,
    ) -> None: ...


class Command(Protocol):
    def __call__(
        self, *arguments: PathValue, timeout: int = 300, combined: bool = False
    ) -> bytes: ...


class Quiescer(Protocol):
    def stopped(self) -> AbstractContextManager[dict[str, str]]: ...


class Options(argparse.Namespace):
    operation: str
    env: str
    recipients: str
    destination: str
    output: str
    offsite: str | None
    config: str
    archive: str
    identity: str
    native_binary: str | None
    sha256: str


class BackupError(RuntimeError):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise BackupError(message)


def command(*arguments: PathValue, timeout: int = 300, combined: bool = False) -> bytes:
    result = subprocess.run(
        list(map(str, arguments)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    require(
        result.returncode == 0,
        f"{Path(str(arguments[0])).name} operation failed, output withheld",
    )

    return result.stdout + result.stderr if combined else result.stdout


def private_path(value: PathValue) -> Path:
    path = Path(value).expanduser().absolute()
    require(
        ".." not in path.parts
        and path.resolve() != ROOT
        and ROOT not in path.resolve().parents,
        "Private state and backup keys must stay outside the checkout",
    )
    require(not path.is_symlink(), "Private roots must not be symlinks")

    return path


def relative(value: object) -> Path:
    require(
        isinstance(value, str) and value and "\\" not in value and "\0" not in value,
        "Invalid archive path",
    )

    value = json_string(value)
    path = PurePosixPath(value)

    require(
        not path.is_absolute()
        and ".." not in path.parts
        and "." not in path.parts
        and path.as_posix() == value
        and value != ".",
        "Unsafe archive path",
    )

    return Path(*path.parts)


def digest(path: PathValue) -> str:
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path: PathValue, value: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
        temporary = Path(output.name)

    temporary.replace(path)


def durable(path: PathValue) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remote_mount(path: Path) -> bool:
    remote = {
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "ceph",
        "glusterfs",
        "fuse.s3fs",
        "fuse.rclone",
        "fuse.gcsfuse",
        "fuse.goofys",
        "fuse.blobfuse2",
    }

    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields, _, filesystem = line.partition(" - ")

        if fields.split()[4] == str(path.resolve()):
            return filesystem.split()[0] in remote

    return False


def load_export(path: PathValue) -> tuple[JSONObject, JSONObject]:
    with Path(path).open("rb") as source:
        compressed = source.read(2) == b"\x1f\x8b"

    opener = gzip.open if compressed else open
    with opener(path, "rt") as source:
        raw: object = json.load(source)

    if not is_json_object(raw):
        raise BackupError("Invalid native export")

    data = raw
    require(
        all(
            key in data
            for key in ("version", "db_s_uuid", "db_d_uuid", "keyhandles", "entries")
        ),
        "Invalid native export",
    )

    entries: JSONObject = {}
    for entry in json_array(data["entries"]):
        attrs = json_object(
            json_object(json_object(json_object(entry)["ent"])["V3"])["attrs"]
        )
        identity = [
            json_string(item) for item in json_array(json_object(attrs["uuid"])["UU"])
        ]
        require(
            len(identity) == 1
            and str(uuid.UUID(identity[0])) == identity[0]
            and identity[0] not in entries,
            "Invalid native entry identity",
        )
        entries[identity[0]] = attrs

    return data, entries


def _normalized(value: JSONValue, path: tuple[str, ...] = ()) -> JSONValue:
    if isinstance(value, dict):
        return {
            key: _normalized(item, (*path, key))
            for key, item in value.items()
            if not (len(path) == 1 and key == "last_modified_cid")
        }

    if isinstance(value, list):
        result: list[JSONValue] = [
            _normalized(item, (*path, str(index))) for index, item in enumerate(value)
        ]

        if path[-2:] == ("backup_code", "code_set"):
            result.sort(key=json_string)

        return result

    return value


def compare_exports(before: PathValue, after: PathValue) -> int:
    original, original_entries = load_export(before)
    restored, restored_entries = load_export(after)

    for field in ("version", "db_s_uuid", "db_d_uuid", "keyhandles"):
        require(original[field] == restored[field], f"Native restore changed {field}")

    require(
        _normalized(original_entries) == _normalized(restored_entries),
        "Native restore changed identity, credentials, membership or policy",
    )

    return len(original_entries)


def sqlite_check(path: PathValue) -> None:
    with closing(
        sqlite3.connect(f"{Path(path).absolute().as_uri()}?mode=ro", uri=True)
    ) as db:
        require(
            db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
            "SQLite integrity check failed",
        )
        require(
            not db.execute("PRAGMA foreign_key_check").fetchall(),
            "SQLite foreign key check failed",
        )


def snapshot_sqlite(source: PathValue, destination: Path) -> None:
    require(
        Path(source).is_file() and not Path(source).is_symlink(),
        "Required SQLite state is missing",
    )

    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (
        closing(
            sqlite3.connect(f"{Path(source).absolute().as_uri()}?mode=ro", uri=True)
        ) as original,
        closing(sqlite3.connect(destination)) as saved,
    ):
        original.backup(saved)

    destination.chmod(0o600)
    sqlite_check(destination)


def check_usage(directory: Path) -> None:
    database, key = directory / "usage.sqlite3", directory / "subject.key"
    require(
        all(path.is_file() and not path.is_symlink() for path in (database, key))
        and key.stat().st_size == 32,
        "SSO history requires its database and subject key together",
    )

    sqlite_check(database)
    with closing(
        sqlite3.connect(f"{database.absolute().as_uri()}?mode=ro", uri=True)
    ) as db:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        require(
            {"metadata", "events", "coverage"} <= tables,
            "SSO history schema is incomplete",
        )

        schemas = {
            "metadata": [("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)],
            "events": [
                ("id", "TEXT", 0, 1),
                ("at", "INTEGER", 1, 0),
                ("subject", "TEXT", 1, 0),
                ("app_id", "TEXT", 1, 0),
                ("app", "TEXT", 1, 0),
                ("month", "TEXT", 1, 0),
                ("day", "TEXT", 1, 0),
                ("weekday", "INTEGER", 1, 0),
                ("hour", "INTEGER", 1, 0),
            ],
            "coverage": [("start", "REAL", 1, 0), ("end", "REAL", 1, 0)],
        }

        unix_tables = {"unix_events", "unix_coverage"}
        require(
            not tables.intersection(unix_tables) or unix_tables <= tables,
            "Unix history schema is incomplete",
        )

        if unix_tables <= tables:
            schemas.update(
                unix_events=[
                    ("id", "TEXT", 0, 1),
                    ("at", "INTEGER", 1, 0),
                    ("subject", "TEXT", 1, 0),
                    ("client_id", "TEXT", 1, 0),
                    ("verified", "INTEGER", 1, 0),
                ],
                unix_coverage=[("start", "REAL", 1, 0), ("end", "REAL", 1, 0)],
            )

        for table, expected in schemas.items():
            actual = [
                (name, kind, not_null, primary_key)
                for _, name, kind, not_null, _, primary_key in db.execute(
                    f"PRAGMA table_info({table})"
                )
            ]
            require(actual == expected, "SSO history schema is incompatible")

        require(
            db.execute(
                "SELECT value FROM metadata WHERE key='key_fingerprint'"
            ).fetchone()
            == (digest(key),),
            "SSO history subject key does not match its database",
        )


def check_registry(
    registry: PathValue,
    ledger: PathValue,
    native_entries: JSONObject,
    *,
    clear_sessions: bool = False,
) -> dict[str, int]:
    def has_class(identifier: str, value: str) -> bool:
        items = json_object(
            json_object(native_entries.get(identifier, {})).get("class", {})
        ).get("I8")
        return isinstance(items, list) and value in items

    for path in (registry, ledger):
        sqlite_check(path)

    with closing(sqlite3.connect(registry)) as db:
        tables = {
            json_string(row[0])
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        require(
            {"applications", "sessions", "audit", "recovery_authorizations"} <= tables,
            "Portal identity registry schema is incomplete",
        )

        people: set[str] = set()
        google: set[tuple[str, str]] = set()
        registry_row: tuple[object, ...]
        for registry_row in db.execute(
            "SELECT person_uuid,issuer,subject,status FROM applications"
        ):
            person = json_string(registry_row[0])
            issuer = registry_row[1]
            subject = registry_row[2]
            status = json_string(registry_row[3])

            require(
                str(uuid.UUID(person)) == person and person not in people,
                "Portal identity mapping is invalid",
            )
            people.add(person)

            require(
                issuer == "https://accounts.google.com"
                and isinstance(subject, str)
                and subject
                and (issuer, subject) not in google,
                "Google identity provenance is invalid",
            )
            google.add((json_string(issuer), json_string(subject)))

            require(
                status
                in {"creating", "provisioning_error", "setup_required", "active"},
                "Portal enrollment status is invalid",
            )

            if person in native_entries or status in {"setup_required", "active"}:
                require(
                    has_class(person, "person"),
                    "Active portal person is absent from the native snapshot",
                )

        require(
            not db.execute(
                "SELECT 1 FROM (SELECT application_id FROM audit UNION ALL "
                "SELECT application_id FROM recovery_authorizations) a "
                "LEFT JOIN applications p ON a.application_id=p.id "
                "WHERE p.id IS NULL LIMIT 1"
            ).fetchone(),
            "Portal audit or recovery identity is orphaned",
        )

        if clear_sessions:
            db.execute("DELETE FROM sessions")
            db.execute("DELETE FROM recovery_authorizations")
            db.commit()
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with closing(sqlite3.connect(ledger)) as db:
        tables = {
            json_string(row[0])
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        require(
            {"team_grants", "team_operations", "team_activation", "team_audit"}
            <= tables,
            "Timed-grant ledger schema is incomplete",
        )

        count = 0
        grant_row: tuple[object, ...]
        for grant_row in db.execute(
            "SELECT team_uuid,person_uuid,status FROM team_grants"
        ):
            team = json_string(grant_row[0])
            person = json_string(grant_row[1])
            status = json_string(grant_row[2])

            require(
                str(uuid.UUID(team)) == team and str(uuid.UUID(person)) == person,
                "Grant identity is invalid",
            )

            if status == "granted":
                require(
                    has_class(team, "group") and has_class(person, "person"),
                    "Active grant group or person is absent from native snapshot",
                )

            count += 1

    return {
        "portal_identities": len(people),
        "google_identities": len(google),
        "grant_records": count,
    }


def copy_tree(
    source: PathValue,
    destination: Path,
    archive_prefix: str,
    links: dict[str, str],
    *,
    sqlite_paths: Sequence[str] = (),
    native: bool = False,
) -> None:
    source = Path(source)
    require(
        source.is_dir() and not source.is_symlink(),
        "A paired state component is missing",
    )

    for item in sorted(source.rglob("*")):
        name = item.relative_to(source)

        if (
            any(
                part in {"operator-session", "__pycache__", "backups"}
                for part in name.parts
            )
            or item.name.startswith(("tokens-", "tokens_"))
            or item.name.endswith(TRANSIENT)
        ):
            continue

        if item.is_symlink():
            link_target = os.readlink(item)
            relative(link_target)
            resolved = item.resolve(strict=True)
            require(
                source == resolved or source in resolved.parents,
                "A source symlink leaves its state component",
            )
            links[(Path(archive_prefix) / name).as_posix()] = link_target
            continue

        if item.is_dir():
            (destination / name).mkdir(parents=True, mode=0o700, exist_ok=True)
            continue

        require(item.is_file(), "Special files cannot enter an identity backup")

        if item.name.endswith((".sqlite3", ".sqlite", ".db")):
            require(
                native or name.as_posix() in sqlite_paths,
                "An unregistered database requires an explicit snapshot",
            )
            continue

        with item.open("rb") as incoming:
            require(
                b"AGE-SECRET-KEY-" not in incoming.read(1024),
                "Keep age private identities outside archived roots",
            )

        target = destination / name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        before = digest(item)
        shutil.copyfile(item, target)
        target.chmod(0o600)

        require(
            digest(target) == before == digest(item),
            "A state file changed while snapshotting",
        )


def bind_mounts(
    value: object, target_key: str, source_key: str, type_key: str
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for raw in json_array(value):
        item = json_object(raw)

        if item[type_key] == "bind":
            result.add(
                (
                    json_string(item[target_key]),
                    str(Path(json_string(item[source_key])).resolve()),
                )
            )

    return result


def backup_plan(value: object) -> BackupPlan:
    obj = json_object(value)
    native = json_object(obj["native"])
    native_config: NativeConfig = {
        "data": json_string(native["data"]),
        "server_config": json_string(native["server_config"]),
    }

    if "image" in native:
        native_config["image"] = json_string(native["image"])

    if "tls" in native:
        tls = native["tls"]
        native_config["tls"] = None if tls is None else json_string(tls)

    for field in ("uid", "gid"):
        if field in native:
            number = native[field]

            if not isinstance(number, int) or isinstance(number, bool):
                raise BackupError("Native container ownership must use integer IDs")

            if field == "uid":
                native_config["uid"] = number
            else:
                native_config["gid"] = number

    offsite = obj.get("offsite")
    return {
        "environment": json_string(obj["environment"]),
        "compose": json_string(obj["compose"]),
        "lock": json_string(obj["lock"]),
        "roots": {
            key: json_string(item) for key, item in json_object(obj["roots"]).items()
        },
        "recipients": json_string(obj["recipients"]),
        "destination": json_string(obj["destination"]),
        "native": native_config,
        "files": {
            key: json_string(item)
            for key, item in json_object(obj.get("files", {})).items()
        },
        "offsite": None if offsite is None else json_string(offsite),
    }


class NativeBinary:
    def __init__(self, executable: PathValue) -> None:
        self.executable = str(Path(executable).absolute())
        version = command(self.executable, "version", combined=True).decode().split()
        require(
            version[:2] == ["kanidmd", VERSION],
            "Restore must use the same native server version",
        )

    def run(
        self,
        operation: str,
        data: PathValue,
        config: PathValue,
        export: PathValue | None = None,
        tls: PathValue | None = None,
    ) -> None:
        settings: dict[str, object] = tomllib.loads(Path(config).read_text())
        temporary = Path(data) / ".backup-offline.toml"
        temporary.write_text(
            "\n".join(
                [
                    'version = "2"',
                    f"domain = {json.dumps(settings['domain'])}",
                    f"origin = {json.dumps(settings['origin'])}",
                    f"db_path = {json.dumps(str(Path(data) / 'kanidm.db'))}",
                    f"tls_chain = {json.dumps(str(Path(data) / 'offline-chain.pem'))}",
                    f"tls_key = {json.dumps(str(Path(data) / 'offline-key.pem'))}",
                    'role = "WriteReplicaNoUI"',
                ]
            )
            + "\n"
        )
        temporary.chmod(0o600)
        try:
            result = command(
                self.executable,
                "database",
                operation,
                "-c",
                temporary,
                *([export] if export is not None else []),
                combined=True,
            )
            require(
                {
                    "backup": b"Backup success!",
                    "restore": b"Restore Success!",
                    "verify": b"Verification passed!",
                }[operation]
                in result,
                f"Native {operation} did not report success",
            )
        finally:
            temporary.unlink(missing_ok=True)


class NativeDocker:
    def __init__(self, config: NativeConfig) -> None:
        self.image = json_string(config.get("image"))
        self.uid, self.gid = config.get("uid", 10001), config.get("gid", 10001)

        require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", self.image),
            "Native image must use an immutable loaded ID",
        )

        metadata = json_object(
            json_array(json.loads(command("docker", "image", "inspect", self.image)))[0]
        )
        labels = json_object(
            json_object(metadata.get("Config", {})).get("Labels", {}) or {}
        )

        require(
            metadata.get("Id") == self.image
            and labels.get("com.kanidm.version") == VERSION
            and labels.get("identity.credential-update-compare.version") == "1",
            "Native image does not match the guarded backup version",
        )

    def run(
        self,
        operation: str,
        data: PathValue,
        config: PathValue,
        export: PathValue | None = None,
        tls: PathValue | None = None,
    ) -> None:
        require(
            tomllib.loads(Path(config).read_text()).get("db_path") == "/data/kanidm.db",
            "Native offline Docker commands require the audited database path",
        )

        with tempfile.TemporaryDirectory(
            prefix="identity-native-offline-"
        ) as directory:
            scratch = Path(directory)
            os.chown(scratch, self.uid, self.gid)
            copied = scratch / "server.toml"
            shutil.copyfile(config, copied)
            os.chown(copied, self.uid, self.gid)
            copied.chmod(0o600)

            if operation == "restore":
                if export is None:
                    raise BackupError("Restore requires a native export")

                shutil.copyfile(export, scratch / "directory.json.gz")
                os.chown(scratch / "directory.json.gz", self.uid, self.gid)
                (scratch / "directory.json.gz").chmod(0o600)

            arguments = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                f"{self.uid}:{self.gid}",
                "--tmpfs",
                f"/run/kanidm:rw,noexec,nosuid,size=1m,uid={self.uid},gid={self.gid},mode=0700",
                "--mount",
                f"type=bind,src={Path(data).absolute()},dst=/data",
                "--mount",
                f"type=bind,src={copied},dst=/data/server.toml,readonly",
                "--mount",
                f"type=bind,src={scratch},dst=/backup",
            ]

            if tls:
                arguments += [
                    "--mount",
                    f"type=bind,src={Path(tls).absolute()},dst=/data/tls,readonly",
                ]

            arguments += [
                self.image,
                "/sbin/kanidmd",
                "database",
                operation,
                "-c",
                "/data/server.toml",
            ]

            if export is not None:
                arguments += ["/backup/directory.json.gz"]

            output = command(*arguments, combined=True)
            require(
                {
                    "backup": b"Backup success!",
                    "restore": b"Restore Success!",
                    "verify": b"Verification passed!",
                }[operation]
                in output,
                f"Native {operation} did not report success",
            )

            if operation == "backup":
                if export is None:
                    raise BackupError("Backup requires a native export destination")

                shutil.copyfile(scratch / "directory.json.gz", export)
                Path(export).chmod(0o600)


class ComposeQuiesce:
    def __init__(self, config: BackupPlan, runner: Command = command) -> None:
        self.config, self.runner = config, runner

    def compose(self, *arguments: str) -> bytes:
        return self.runner(
            "docker",
            "compose",
            "--env-file",
            self.config["environment"],
            "--file",
            self.config["compose"],
            "--project-name",
            "identity",
            *arguments,
        )

    @contextmanager
    def stopped(self) -> Generator[dict[str, str]]:
        model = json_object(json.loads(self.compose("config", "--format", "json")))
        services = json_object(model["services"])

        require(
            model.get("name") == "identity",
            "Only the owned identity Compose project can be quiesced",
        )
        require(
            set(services) <= {*SERVICES, "operator", "observer"},
            "Untracked services may write paired state",
        )

        state_binds = {
            "portal": ("/state", self.config["roots"]["portal"]),
            "access": ("/state", self.config["roots"]["portal"]),
            "posix": ("/state/posix-defaults", self.config["roots"]["posix"]),
            "kanidm": ("/data", self.config["native"]["data"]),
        }
        owned: list[tuple[str, str, bool]] = []
        inspected_services = (
            ("observer", *SERVICES) if "observer" in services else SERVICES
        )

        for service in inspected_services:
            identifiers = (
                self.compose("ps", "--all", "--quiet", service).decode().split()
            )
            require(
                len(identifiers) == 1,
                f"Owned {service} container is missing or ambiguous",
            )

            entry = json_object(
                json_array(
                    json.loads(self.runner("docker", "inspect", identifiers[0]))
                )[0]
            )
            service_model = json_object(services[service])
            labels = json_object(json_object(entry["Config"]).get("Labels", {}))

            require(
                labels.get("com.docker.compose.project") == "identity"
                and labels.get("com.docker.compose.service") == service
                and entry["Image"] == service_model["image"],
                "Container ownership or image identity changed",
            )

            expected_binds = bind_mounts(
                service_model.get("volumes", []), "target", "source", "type"
            )
            actual_binds = bind_mounts(
                entry.get("Mounts", []), "Destination", "Source", "Type"
            )

            require(
                actual_binds == expected_binds,
                "Running container bind mounts differ from the backup deployment",
            )

            running = json_object(entry["State"])["Running"]

            if not isinstance(running, bool):
                raise BackupError("Container running status must be a boolean")

            owned.append((service, json_string(entry["Id"]), running))

            if service == "observer":
                continue

            target, source = state_binds[service]
            require(
                (target, str(Path(source).resolve())) in actual_binds,
                "Backup state differs from the quiesced container bind mount",
            )

            if service == "kanidm":
                require(
                    service_model["image"] == self.config["native"].get("image"),
                    "Backup native image differs from the quiesced directory",
                )

        require(
            not self.compose(
                "ps", "--quiet", "--status", "running", "operator"
            ).strip(),
            "Finish the operator operation before starting a paired backup",
        )

        stopped: list[str] = []
        try:
            for _, identifier, running in owned:
                if not running:
                    continue

                stopped.append(identifier)
                self.runner("docker", "stop", "--time", "60", identifier)
                stopped_entry = json_object(
                    json_array(
                        json.loads(self.runner("docker", "inspect", identifier))
                    )[0]
                )
                require(
                    json_object(stopped_entry["State"])["Running"] is False,
                    "An owned writer did not quiesce",
                )

            yield {
                service: json_string(json_object(services[service])["image"])
                for service in SERVICES
            }
        finally:
            errors: list[str] = []
            for identifier in reversed(stopped):
                try:
                    self.runner("docker", "start", identifier)
                except BackupError, OSError, subprocess.SubprocessError:
                    errors.append(identifier)

            require(
                not errors,
                "One or more previously running containers could not restart",
            )


@contextmanager
def maintenance(config: BackupPlan) -> Generator[None]:
    lock = private_path(config["lock"])
    lock.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

    with os.fdopen(descriptor, "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def create(
    config: BackupPlan,
    *,
    native: NativeBackend | None = None,
    quiescer: Quiescer | None = None,
) -> JSONObject:
    native = native or NativeDocker(config["native"])
    quiescer = quiescer or ComposeQuiesce(config)
    output = private_path(config["destination"])
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    output.chmod(0o700)

    recipient = private_path(config["recipients"])
    recipients = [
        line
        for line in recipient.read_text().splitlines()
        if line and not line.startswith("#")
    ]

    require(
        recipients and all(re.fullmatch(r"age1[0-9a-z]+", item) for item in recipients),
        "Use explicit age X25519 recipients",
    )

    roots = {name: Path(value) for name, value in config["roots"].items()}
    require(
        COMPONENTS <= set(roots) <= COMPONENTS | OPTIONAL_COMPONENTS,
        "Paired component roots are incomplete or unsupported",
    )

    for name, path in roots.items():
        if name not in {"branding", "portal-ui"}:
            private_path(path)

        require(
            output != path.resolve() and path.resolve() not in output.parents,
            "Backup destination cannot be inside a source component",
        )

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    archive = output / f"identity-paired-{stamp}.tar.age"
    report: JSONObject = {
        "created_at": datetime.now(UTC).isoformat(),
        "archive": archive.name,
        "offsite_configured": bool(config.get("offsite")),
        "offsite_verified": False,
    }

    with (
        maintenance(config),
        tempfile.TemporaryDirectory(prefix=".paired-", dir=output) as temporary,
    ):
        payload = Path(temporary) / "payload"
        payload.mkdir(mode=0o700)
        links: dict[str, str] = {}

        with quiescer.stopped() as images:
            if isinstance(native, NativeDocker):
                require(
                    images.get("kanidm") == native.image,
                    "Backup requires the quiesced immutable native image",
                )

            registry = payload / "components/portal/enrollment/enrollment.sqlite3"
            ledger = payload / "components/portal/access/grants.sqlite3"
            sqlite_paths = {
                "portal": ("enrollment/enrollment.sqlite3", "access/grants.sqlite3"),
                "usage": ("usage.sqlite3",),
            }
            for name, source in roots.items():
                copy_tree(
                    source,
                    payload / "components" / name,
                    f"components/{name}",
                    links,
                    sqlite_paths=sqlite_paths.get(name, ()),
                )

            for name, source_value in config.get("files", {}).items():
                target = payload / "external" / relative(name)
                external_source = private_path(source_value)
                require(
                    external_source.is_file(),
                    "A required external configuration or secret is missing",
                )

                with external_source.open("rb") as incoming:
                    require(
                        b"AGE-SECRET-KEY-" not in incoming.read(1024),
                        "Age identities cannot enter a backup",
                    )

                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                before = digest(external_source)
                shutil.copyfile(external_source, target)
                target.chmod(0o600)

                require(
                    before == digest(external_source) == digest(target),
                    "External state changed during snapshot",
                )

            snapshot_sqlite(roots["portal"] / "enrollment/enrollment.sqlite3", registry)
            snapshot_sqlite(roots["portal"] / "access/grants.sqlite3", ledger)

            if "usage" in roots:
                usage = payload / "components/usage"
                snapshot_sqlite(
                    roots["usage"] / "usage.sqlite3", usage / "usage.sqlite3"
                )
                check_usage(usage)

            data = private_path(config["native"]["data"])
            copy_tree(data, payload / "native/data", "native/data", links, native=True)
            native_config = payload / "native/server.toml"
            native_config.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            shutil.copyfile(config["native"]["server_config"], native_config)
            native_config.chmod(0o600)

            native.run(
                "backup",
                data,
                config["native"]["server_config"],
                payload / "native/directory.json.gz",
                config["native"].get("tls"),
            )

            _, entries = load_export(payload / "native/directory.json.gz")
            counts = check_registry(registry, ledger, entries)

            files = {
                path.relative_to(payload).as_posix(): digest(path)
                for path in payload.rglob("*")
                if path.is_file()
            }

            manifest: JSONObject = {
                "format": 1,
                "native_version": VERSION,
                "created_at": report["created_at"],
                "files": json_object(files),
                "links": json_object(links),
                "images": json_object(images),
                "roots": json_object(
                    {name: str(path.absolute()) for name, path in roots.items()}
                ),
                "counts": json_object(counts),
                "native_entries": len(entries),
            }
            write_json(payload / "manifest.json", manifest)

        plain = Path(temporary) / "paired.tar"
        with tarfile.open(plain, "w") as tar:
            for path in sorted(payload.rglob("*")):
                tar.add(
                    path, arcname=path.relative_to(payload).as_posix(), recursive=False
                )

        plain.chmod(0o600)
        encrypted = Path(temporary) / "paired.tar.age"
        command("age", "--recipients-file", recipient, "--output", encrypted, plain)
        encrypted.chmod(0o600)
        durable(encrypted)
        encrypted.replace(archive)
        durable(output)

        report.update(
            cipher_sha256=digest(archive), native_entries=len(entries), **counts
        )
        write_json(archive.with_suffix(archive.suffix + ".json"), report)
        write_json(output / "status.json", report)

        offsite = config.get("offsite")

        if offsite:
            remote = private_path(offsite)
            require(
                remote.is_dir() and remote.is_mount() and remote_mount(remote),
                "Offsite destination must be an existing remote filesystem mount",
            )
            require(
                remote.stat().st_dev != output.stat().st_dev,
                "Offsite destination shares the local backup device",
            )

            partial = remote / (archive.name + ".partial")
            require(
                not partial.exists() and not partial.is_symlink(),
                "Offsite partial path already exists",
            )

            try:
                with partial.open("xb") as outbound, archive.open("rb") as inbound:
                    os.fchmod(outbound.fileno(), 0o600)
                    shutil.copyfileobj(inbound, outbound)
                    outbound.flush()
                    os.fsync(outbound.fileno())

                require(
                    digest(partial) == report["cipher_sha256"],
                    "Offsite ciphertext verification failed",
                )

                partial.replace(remote / archive.name)
                durable(remote)
                report["offsite_verified"] = True
                write_json(archive.with_suffix(archive.suffix + ".json"), report)
                write_json(output / "status.json", report)
            finally:
                partial.unlink(missing_ok=True)

    return report


def unpack(plain: PathValue, payload: Path) -> JSONObject:
    seen: set[Path] = set()
    size = 0

    with tarfile.open(plain) as tar:
        for member in tar:
            name = relative(member.name.rstrip("/"))
            require(
                name not in seen and (member.isdir() or member.isfile()),
                "Archive links, duplicate or special entries are refused",
            )

            seen.add(name)
            size += member.size
            require(
                len(seen) <= 200000 and size <= 16 * 1024**3,
                "Backup exceeds restore limits",
            )

            target = payload / name

            if member.isdir():
                target.mkdir(parents=True, mode=0o700, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            source = tar.extractfile(member)

            if source is None:
                raise BackupError("Archive entry has no regular file data")

            with target.open("xb") as destination, source:
                os.fchmod(destination.fileno(), 0o600)
                shutil.copyfileobj(source, destination)

    raw_manifest: object = json.loads((payload / "manifest.json").read_text())

    if not is_json_object(raw_manifest):
        raise BackupError("Restore format or native version is unsupported")

    manifest = raw_manifest
    require(
        type(manifest.get("format")) is int
        and manifest["format"] == 1
        and manifest.get("native_version") == VERSION,
        "Restore format or native version is unsupported",
    )

    files = {
        path.relative_to(payload).as_posix(): digest(path)
        for path in payload.rglob("*")
        if path.is_file() and path != payload / "manifest.json"
    }
    require(
        files == manifest.get("files"),
        "Paired manifest file inventory or hashes differ",
    )

    raw_links = manifest.get("links", {})

    if not is_json_object(raw_links):
        raise BackupError("Archive links must be an object")

    links = raw_links
    for link_name, link_target in links.items():
        path = payload / relative(link_name)
        link = relative(link_target)
        require(
            not path.exists()
            and path.parent.exists()
            and (path.parent / link).exists(),
            "Archive link target is missing or conflicting",
        )
        path.symlink_to(link)

    return manifest


def restore(
    config: BackupPlan,
    archive: PathValue,
    destination: PathValue,
    identity: PathValue,
    *,
    native: NativeBackend | None = None,
    expected_sha256: str | None = None,
) -> JSONObject:
    destination = private_path(destination)
    require(
        not destination.exists()
        or (destination.is_dir() and not any(destination.iterdir())),
        "Restore destination must be absent or empty",
    )

    identity = private_path(identity)
    require(
        identity.is_file() and not identity.stat().st_mode & 0o077,
        "Age identity must be a private file",
    )

    archive = private_path(archive)

    if expected_sha256 is None:
        sidecar = archive.with_suffix(archive.suffix + ".json")
        require(
            sidecar.is_file()
            and not sidecar.is_symlink()
            and sidecar.stat().st_uid == os.geteuid()
            and not sidecar.stat().st_mode & 0o077,
            "Supply a trusted ciphertext SHA-256 or a private local backup receipt",
        )
        expected_sha256 = json_string(
            json_object(json.loads(sidecar.read_text()))["cipher_sha256"]
        )

    require(
        re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        and digest(archive) == expected_sha256,
        "Ciphertext differs from the trusted backup receipt",
    )

    native = native or NativeDocker(config["native"])
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    with tempfile.TemporaryDirectory(
        prefix=".identity-restore-", dir=destination.parent
    ) as temporary:
        root = Path(temporary)
        plain, payload = root / "paired.tar", root / "payload"
        payload.mkdir(mode=0o700)

        command("age", "--decrypt", "--identity", identity, "--output", plain, archive)
        plain.chmod(0o600)
        manifest = unpack(plain, payload)
        usage = payload / "components/usage"
        has_usage = "usage" in json_object(manifest["roots"])
        require(
            usage.exists() == has_usage,
            "SSO history component differs from the paired manifest",
        )

        if has_usage:
            check_usage(usage)

        if isinstance(native, NativeDocker):
            require(
                json_object(manifest["images"])["kanidm"] == native.image,
                "Restore requires the archived immutable native image",
            )

        data = payload / "native/data"
        data.mkdir(parents=True, mode=0o700, exist_ok=True)

        if isinstance(native, NativeDocker):
            for item in [data, *data.rglob("*")]:
                if not item.is_symlink():
                    os.chown(item, native.uid, native.gid)

        exported = payload / "native/directory.json.gz"
        native.run("restore", data, payload / "native/server.toml", exported)
        native.run("verify", data, payload / "native/server.toml")

        reexported = root / "restored-native.json.gz"
        native.run("backup", data, payload / "native/server.toml", reexported)
        count = compare_exports(exported, reexported)

        _, entries = load_export(exported)
        counts = check_registry(
            payload / "components/portal/enrollment/enrollment.sqlite3",
            payload / "components/portal/access/grants.sqlite3",
            entries,
            clear_sessions=True,
        )
        sqlite_check(payload / "components/portal/enrollment/enrollment.sqlite3")
        sqlite_check(payload / "components/portal/access/grants.sqlite3")

        for path in payload.rglob("*"):
            if path.is_file() and path.name.endswith(("-wal", "-shm")):
                path.unlink()

        report: JSONObject = {
            "restored_at": datetime.now(UTC).isoformat(),
            "native_version": VERSION,
            "native_entries": count,
            "native_identity_credentials_keyhandles_preserved": True,
            "portal_sessions_cleared": True,
            "recovery_authorizations_cleared": True,
            "usage_history_preserved": has_usage,
            "images": manifest["images"],
            "offsite_verified": False,
            **counts,
        }
        write_json(payload / "restore-report.json", report)

        if destination.exists():
            require(
                not any(destination.iterdir()),
                "Restore destination changed during verification",
            )
            destination.rmdir()

        payload.rename(destination)

    return report


def production_plan(
    environment: PathValue,
    recipients: PathValue,
    destination: PathValue,
    offsite: PathValue | None = None,
) -> BackupPlan:
    settings: dict[str, str] = {}
    for line in private_path(environment).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        key, separator, value = line.partition("=")
        require(
            separator
            and key not in settings
            and value
            and "$" not in value
            and not any(character.isspace() for character in value),
            "Deployment environment must contain literal unique values",
        )
        settings[key] = value

    keys = {
        "portal": "IDENTITY_PORTAL_STATE_DIR",
        "posix": "IDENTITY_POSIX_STATE_DIR",
        "configuration": "IDENTITY_CONFIG_DIR",
        "pki": "IDENTITY_PKI_DIR",
    }
    roots = {name: str(private_path(settings[key])) for name, key in keys.items()}

    if "IDENTITY_USAGE_STATE_DIR" in settings:
        roots["usage"] = str(private_path(settings["IDENTITY_USAGE_STATE_DIR"]))

    roots["branding"] = str(ROOT / "service/branding")
    roots["portal-ui"] = str(ROOT / "service/enrollment-ui")

    return {
        "environment": str(private_path(environment)),
        "compose": str(ROOT / "deploy/oci/compose.yaml"),
        "lock": str(private_path(settings["IDENTITY_PKI_DIR"]) / "renew.lock"),
        "roots": roots,
        "recipients": str(private_path(recipients)),
        "destination": str(private_path(destination)),
        "offsite": str(private_path(offsite)) if offsite else None,
        "files": {
            "google-client.json": str(private_path(settings["IDENTITY_GOOGLE_CLIENT"])),
            "operator-credentials.json": str(
                private_path(settings["IDENTITY_OPERATOR_CREDENTIALS"])
            ),
            "backend-ca.key": str(private_path(settings["IDENTITY_BACKEND_CA_KEY"])),
            "tunnel.token": str(private_path(settings["IDENTITY_TUNNEL_TOKEN_FILE"])),
            "deployment.env": str(private_path(environment)),
        },
        "native": {
            "image": settings["IDENTITY_KANIDM_IMAGE"],
            "data": str(private_path(settings["IDENTITY_KANIDM_DATA_DIR"])),
            "server_config": str(
                private_path(settings["IDENTITY_CONFIG_DIR"]) / "server.toml"
            ),
            "tls": str(private_path(settings["IDENTITY_PKI_DIR"]) / "kanidm"),
            "uid": 10001,
            "gid": 10001,
        },
    }


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        description="Paired, age-encrypted identity backups and isolated, verified restoration"
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    plan = commands.add_parser("plan")
    for field in ("env", "recipients", "destination", "output"):
        plan.add_argument("--" + field, required=True)
    plan.add_argument("--offsite")

    create_parser = commands.add_parser("create")
    create_parser.add_argument("--config", required=True)

    for mode in ("restore", "drill"):
        child = commands.add_parser(mode)
        for field in ("config", "archive", "identity"):
            child.add_argument("--" + field, required=True)
        child.add_argument("--native-binary")
        child.add_argument(
            "--sha256",
            required=True,
            help="Ciphertext digest from the trusted backup receipt",
        )

        if mode == "restore":
            child.add_argument("--destination", required=True)

    arguments = parser.parse_args(namespace=Options())

    try:
        if arguments.operation == "plan":
            write_json(
                private_path(arguments.output),
                production_plan(
                    arguments.env,
                    arguments.recipients,
                    arguments.destination,
                    arguments.offsite,
                ),
            )
            print("Paired backup plan written privately, no services were changed")
            return

        config = backup_plan(json.loads(private_path(arguments.config).read_text()))

        if arguments.operation == "create":
            report = create(config)
        else:
            native = (
                NativeBinary(arguments.native_binary)
                if arguments.native_binary
                else None
            )

            if arguments.operation == "drill":
                with tempfile.TemporaryDirectory(
                    prefix="identity-paired-drill-"
                ) as directory:
                    report = restore(
                        config,
                        arguments.archive,
                        Path(directory) / "restored",
                        arguments.identity,
                        native=native,
                        expected_sha256=arguments.sha256,
                    )
                    report["isolated_drill"] = True
            else:
                report = restore(
                    config,
                    arguments.archive,
                    arguments.destination,
                    arguments.identity,
                    native=native,
                    expected_sha256=arguments.sha256,
                )

        print(json.dumps(report, indent=2))
    except (
        BackupError,
        OSError,
        ValueError,
        KeyError,
        sqlite3.Error,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        parser.exit(
            1,
            f"Paired backup operation failed: {type(error).__name__}, private output withheld\n",
        )


if __name__ == "__main__":
    main()
