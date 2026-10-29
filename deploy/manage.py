#!/usr/bin/env python3

import argparse
import base64
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import certificates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))
from contracts import json_array, json_object, json_string

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/oci/compose.yaml"
STARTUP_TIMEOUT_SECONDS = 100
IMAGE_KEYS = ("IDENTITY_KANIDM_IMAGE", "IDENTITY_PORTAL_IMAGE")
PATH_KEYS = (
    "IDENTITY_KANIDM_DATA_DIR",
    "IDENTITY_PORTAL_STATE_DIR",
    "IDENTITY_CONFIG_DIR",
    "IDENTITY_PKI_DIR",
    "IDENTITY_GOOGLE_CLIENT",
    "IDENTITY_OPERATOR_CREDENTIALS",
    "IDENTITY_BACKEND_CA_KEY",
    "IDENTITY_TUNNEL_TOKEN_FILE",
    "IDENTITY_POSIX_STATE_DIR",
    "IDENTITY_POSIX_STATUS_DIR",
    "IDENTITY_BACKUP_STATUS_DIR",
    "IDENTITY_OPERATOR_SESSION_DIR",
    "IDENTITY_METRICS_DASHBOARD_DIR",
    "IDENTITY_MEMBER_DASHBOARD_DIR",
    "IDENTITY_USAGE_STATE_DIR",
    "IDENTITY_USAGE_EXPORT_DIR",
)


@dataclass
class Arguments(argparse.Namespace):
    command: str = ""
    env: str = ""


def require(value: object, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def environment(path: str | Path) -> dict[str, str]:
    value: dict[str, str] = {}

    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        key, separator, item = line.partition("=")
        require(
            separator and key not in value,
            "Deployment environment contains invalid or duplicate fields",
        )
        require(
            key in {*IMAGE_KEYS, *PATH_KEYS, "IDENTITY_TUNNEL_ID"},
            "Deployment environment has an unsupported field",
        )
        require(
            item
            and not any(character.isspace() for character in item)
            and "$" not in item,
            "Deployment values must be literal, nonempty values without whitespace",
        )
        value[key] = item

    require(
        set(value) == {*IMAGE_KEYS, *PATH_KEYS, "IDENTITY_TUNNEL_ID"},
        "Deployment environment fields are incomplete",
    )
    require(
        str(uuid.UUID(value["IDENTITY_TUNNEL_ID"])) == value["IDENTITY_TUNNEL_ID"],
        "Tunnel identity must be a canonical UUID",
    )

    for key in PATH_KEYS:
        candidate = Path(value[key])
        require(
            candidate.is_absolute()
            and ".." not in candidate.parts
            and candidate != Path("/")
            and candidate != ROOT
            and ROOT not in candidate.parents
            and candidate.resolve() != ROOT
            and ROOT not in candidate.resolve().parents,
            "Persistent data, deployment config and secrets must stay outside the checkout",
        )

    require(
        Path(value["IDENTITY_USAGE_STATE_DIR"]) == Path("/var/lib/identity/usage")
        and Path(value["IDENTITY_USAGE_EXPORT_DIR"])
        == Path("/var/lib/identity/usage-export"),
        "SSO collector state and export paths must use the service defaults",
    )
    require(
        len({value[key] for key in PATH_KEYS}) == len(PATH_KEYS),
        "Deployment paths must be distinct",
    )
    portal = Path(value["IDENTITY_PORTAL_STATE_DIR"]).resolve()

    for key in (
        "IDENTITY_POSIX_STATE_DIR",
        "IDENTITY_OPERATOR_SESSION_DIR",
        "IDENTITY_KANIDM_DATA_DIR",
        "IDENTITY_USAGE_STATE_DIR",
    ):
        secret = Path(value[key]).resolve()
        require(
            portal != secret
            and portal not in secret.parents
            and secret not in portal.parents,
            "Privileged state must stay outside the portal state tree",
        )

    for key in (
        "IDENTITY_METRICS_DASHBOARD_DIR",
        "IDENTITY_MEMBER_DASHBOARD_DIR",
        "IDENTITY_USAGE_EXPORT_DIR",
    ):
        dashboard = Path(value[key]).resolve()

        for other in PATH_KEYS:
            if other == key:
                continue

            path = Path(value[other]).resolve()
            require(
                dashboard != path
                and dashboard not in path.parents
                and path not in dashboard.parents,
                "Dashboard exports must stay separate from private state and each other",
            )

    return value


def command(
    *arguments: str,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments, env=env, capture_output=True, text=True, check=False, timeout=timeout
    )
    require(
        not check or result.returncode == 0,
        f"{arguments[0]} {arguments[1]} failed, output was withheld",
    )
    return result


def compose(
    config: Mapping[str, str],
    *arguments: str,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return command(
        "docker",
        "compose",
        "--file",
        str(COMPOSE),
        *arguments,
        env=dict(os.environ) | dict(config),
        check=check,
        timeout=timeout,
    )


def remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Production startup timed out")
    return remaining


def wait_for_readiness(config: Mapping[str, str], deadline: float) -> None:
    name = f"identity-readiness-{os.getpid()}"

    while True:
        try:
            result = compose(
                config,
                "run",
                "--rm",
                "--no-deps",
                "--name",
                name,
                "--env",
                "IDENTITY_PROCESS_ROLE=portal",
                "access",
                "check",
                check=False,
                timeout=remaining_timeout(deadline),
            )
        except subprocess.TimeoutExpired as error:
            command("docker", "rm", "--force", name, check=False, timeout=5)
            raise RuntimeError("Production readiness timed out") from error

        if result.returncode == 0:
            return

        require(
            result.returncode == 1,
            "Production readiness command failed",
        )
        time.sleep(min(2, remaining_timeout(deadline)))


def require_root_path(
    path: Path,
    *,
    directory: bool = False,
    missing: bool = False,
    mode: int | None = None,
    gid: int | None = None,
) -> None:
    require(path.is_absolute() and ".." not in path.parts, "Invalid deployment path")

    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            require(missing, "A required private deployment path is missing")
            continue

        expected = stat.S_ISDIR if item != path or directory else stat.S_ISREG
        require(
            expected(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "Operator paths must be root-owned and unwritable by service users",
        )

        if item == path:
            require(
                (mode is None or stat.S_IMODE(info.st_mode) == mode)
                and (gid is None or info.st_gid == gid),
                "Deployment secret ownership or permissions are invalid",
            )


def prepare_directory(path: Path, uid: int, gid: int, mode: int) -> None:
    require(path.is_absolute() and ".." not in path.parts, "Invalid deployment path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    current = Path("/")

    try:
        for part in path.parts[1:]:
            current /= part

            with suppress(FileExistsError):
                os.mkdir(
                    part, mode=mode if current == path else 0o755, dir_fd=descriptor
                )

            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child

        require(
            os.fstat(descriptor).st_uid in {0, uid},
            "Deployment directory belongs to another service",
        )
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def validate_image(value: object, kind: str, architecture: str = "arm64") -> None:
    metadata = json_object(value)
    require(
        metadata.get("Architecture") == architecture and metadata.get("Os") == "linux",
        "Production image architecture is unsupported",
    )
    labels = json_object(json_object(metadata.get("Config", {})).get("Labels") or {})
    require(
        labels.get("com.kanidm.version") == "1.11.2",
        "Production image version does not match the supported release",
    )
    origin = (
        "https://auth.slugsec.club" if kind == "kanidm" else "https://my.slugsec.club"
    )
    require(
        labels.get("identity.production.origin") == origin,
        "Production image origin does not match the deployment",
    )
    require(
        labels.get("identity.credential-update-compare.version") == "1",
        "Production image lacks the native comparison capability",
    )

    if kind == "kanidm":
        require(
            labels.get("identity.usage-events.version") == "1",
            "Production image lacks committed SSO events",
        )
        from branding_config import branding_hash

        for filename, label in (
            ("consent-recipient.patch", "identity.consent-recipient.patch-sha256"),
            (
                "credential-conflict.patch",
                "identity.credential-conflict.patch-sha256",
            ),
            ("page-load.patch", "identity.page-load.patch-sha256"),
            ("usage-events.patch", "identity.usage-events.patch-sha256"),
        ):
            expected = hashlib.sha256(
                (ROOT / "service/branding/kanidm-1.11.2" / filename).read_bytes()
            ).hexdigest()
            require(
                labels.get(label) == expected,
                "Production image does not match the audited native patches",
            )

        require(
            labels.get("identity.production.branding-sha256") == branding_hash(),
            "Production image does not match the current branding build",
        )


def validate_tunnel_token(config: Mapping[str, str]) -> None:
    token = Path(config["IDENTITY_TUNNEL_TOKEN_FILE"]).read_bytes().strip()
    tunnel = json_object(json.loads(base64.b64decode(token, validate=True)))
    account = json_string(tunnel.get("a"))
    secret = json_string(tunnel.get("s"))

    require(
        tunnel.get("t") == config["IDENTITY_TUNNEL_ID"]
        and re.fullmatch(r"[a-f0-9]{32}", account),
        "Tunnel token does not match the configured connector",
    )
    require(
        len(base64.b64decode(secret, validate=True)) >= 32,
        "Tunnel token secret is invalid",
    )


def validate(config: Mapping[str, str], deadline: float | None = None) -> None:
    for key, kind in zip(IMAGE_KEYS, ("kanidm", "portal"), strict=True):
        require(
            re.fullmatch(r"sha256:[a-f0-9]{64}", config[key]),
            "Production images must use immutable loaded image IDs",
        )
        inspected = json_array(
            json.loads(
                command(
                    "docker",
                    "image",
                    "inspect",
                    config[key],
                    timeout=remaining_timeout(deadline)
                    if deadline is not None
                    else None,
                ).stdout
            )
        )
        require(
            len(inspected) == 1 and json_object(inspected[0]).get("Id") == config[key],
            "Loaded image ID changed",
        )
        validate_image(inspected[0], kind)

    metrics_group()
    directory = Path(config["IDENTITY_CONFIG_DIR"])

    for key in (
        "IDENTITY_CONFIG_DIR",
        "IDENTITY_PKI_DIR",
        "IDENTITY_BACKUP_STATUS_DIR",
        "IDENTITY_OPERATOR_SESSION_DIR",
    ):
        require_root_path(Path(config[key]), directory=True)

    for filename in ("server.toml", "runtime.json"):
        require_root_path(directory / filename)

    require_root_path(Path(config["IDENTITY_PKI_DIR"]) / "ca.pem")

    for key, mode, gid in (
        ("IDENTITY_GOOGLE_CLIENT", 0o640, 10002),
        ("IDENTITY_OPERATOR_CREDENTIALS", 0o600, None),
        ("IDENTITY_BACKEND_CA_KEY", 0o600, None),
        ("IDENTITY_TUNNEL_TOKEN_FILE", 0o600, None),
    ):
        require_root_path(Path(config[key]), mode=mode, gid=gid)

    server = json_object(tomllib.loads((directory / "server.toml").read_text()))
    require(
        server.get("version") == "2"
        and server.get("domain") == "auth.slugsec.club"
        and server.get("origin") == "https://auth.slugsec.club"
        and "http_client_address_info" not in server,
        "Production server identity or proxy trust changed",
    )
    require(
        json_object(server.get("online_backup", {})).get("path") == "/data/backups",
        "Native online backups must stay in the persisted data directory",
    )
    os.environ["IDENTITY_RUNTIME_CONFIG"] = str(directory / "runtime.json")
    from runtime import load_config

    load_config(directory / "runtime.json")

    for key in PATH_KEYS:
        require(
            Path(config[key]).exists(), "A required private deployment path is missing"
        )

    validate_tunnel_token(config)
    client = json_object(
        json_object(json.loads(Path(config["IDENTITY_GOOGLE_CLIENT"]).read_text())).get(
            "web", {}
        )
    )
    require(
        client.get("client_id")
        and client.get("client_secret")
        and "https://my.slugsec.club/google/callback"
        in json_array(client.get("redirect_uris", [])),
        "Google web client must register the production enrollment callback",
    )
    require(
        not str(client["client_secret"]).startswith(("CHANGE", "REPLACE")),
        "Google credentials are still placeholders",
    )
    operator = json_object(
        json.loads(Path(config["IDENTITY_OPERATOR_CREDENTIALS"]).read_text())
    )
    accounts = json_object(operator["accounts"])
    require(
        operator.get("url") == "https://auth.slugsec.club"
        and set(accounts) in (set(), {"admin", "idm_admin"})
        and all(
            isinstance(item, str)
            and item
            and not item.startswith(("CHANGE", "REPLACE"))
            for item in accounts.values()
        ),
        "Private operator credentials are incomplete",
    )
    compose(
        config,
        "config",
        "--quiet",
        timeout=remaining_timeout(deadline) if deadline is not None else None,
    )


def metrics_group(*, create: bool = False) -> None:
    require(
        not any(account.pw_gid == 10005 for account in pwd.getpwall()),
        "Metrics group ID is already assigned to a host account",
    )
    groups: list[grp.struct_group] = []

    lookups: tuple[Callable[[], grp.struct_group], ...] = (
        lambda: grp.getgrnam("identity-metrics"),
        lambda: grp.getgrgid(10005),
    )

    for lookup in lookups:
        with suppress(KeyError):
            groups.append(lookup())

    if not groups:
        require(create, "Metrics system group is missing, run deployment prepare")
        command("groupadd", "--system", "--gid", "10005", "identity-metrics")
        metrics_group()
        return

    require(
        len(groups) == 2
        and all(
            group.gr_name == "identity-metrics"
            and group.gr_gid == 10005
            and not group.gr_mem
            for group in groups
        ),
        "Metrics system group conflicts with an existing group or host members",
    )


def prepare(config: Mapping[str, str]) -> None:
    require(os.geteuid() == 0, "Production preparation requires a root operator")
    metrics_group(create=True)

    for key, uid, gid, mode in (
        ("IDENTITY_KANIDM_DATA_DIR", 10001, 10001, 0o700),
        ("IDENTITY_PORTAL_STATE_DIR", 10002, 10002, 0o700),
        ("IDENTITY_POSIX_STATE_DIR", 10004, 10004, 0o700),
        ("IDENTITY_POSIX_STATUS_DIR", 10004, 10002, 0o750),
        ("IDENTITY_BACKUP_STATUS_DIR", 0, 10002, 0o750),
        ("IDENTITY_OPERATOR_SESSION_DIR", 0, 0, 0o700),
        ("IDENTITY_METRICS_DASHBOARD_DIR", 10002, 10005, 0o2750),
        ("IDENTITY_MEMBER_DASHBOARD_DIR", 10002, 10005, 0o2750),
        ("IDENTITY_USAGE_STATE_DIR", 0, 0, 0o700),
        ("IDENTITY_USAGE_EXPORT_DIR", 0, 10005, 0o750),
    ):
        path = Path(config[key])
        require_root_path(path.parent, directory=True, missing=True)
        prepare_directory(path, uid, gid, mode)

    backups = Path(config["IDENTITY_KANIDM_DATA_DIR"]) / "backups"
    prepare_directory(backups, 10001, 10001, 0o700)
    prepare_directory(
        Path(config["IDENTITY_PORTAL_STATE_DIR"]) / "enrollment", 10002, 10002, 0o700
    )
    metrics = Path(config["IDENTITY_PORTAL_STATE_DIR"]) / "metrics"
    prepare_directory(metrics, 10002, 10002, 0o700)
    prepare_directory(metrics / "observer", 10002, 10002, 0o700)
    directory = Path(config["IDENTITY_CONFIG_DIR"])
    require_root_path(directory, directory=True, missing=True)
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)

    for filename in ("server.toml", "runtime.json"):
        target = directory / filename
        require_root_path(target, missing=True)
        expected = (ROOT / "deploy/oci" / filename).read_bytes()
        require(
            not target.exists() or target.read_bytes() == expected,
            "Existing deployment config differs, review before replacing it",
        )

        if not target.exists():
            target.write_bytes(expected)

        os.chown(target, 0, 0)
        target.chmod(0o644)

    renew(config, activate=False)
    backup_status(config)


def backup_status(config: Mapping[str, str]) -> None:
    require(os.geteuid() == 0, "Backup status export requires a root operator")
    now = time.time()
    times: list[float] = []

    for path in (Path(config["IDENTITY_KANIDM_DATA_DIR"]) / "backups").glob("*"):
        if path.is_symlink() or not path.name.endswith((".json", ".json.gz")):
            continue

        info = path.stat()

        if path.is_file() and info.st_size and info.st_mtime <= now:
            times.append(info.st_mtime)

    directory = Path(config["IDENTITY_BACKUP_STATUS_DIR"])
    require_root_path(directory, directory=True)

    with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
        temporary = Path(stream.name)

        try:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, 10002)
            json.dump(
                {
                    "checked_at": now,
                    "present": bool(times),
                    "latest_at": max(times) if times else None,
                },
                stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(directory / "status.json")
        finally:
            temporary.unlink(missing_ok=True)


def renew(config: Mapping[str, str], activate: bool = True) -> None:
    require(os.geteuid() == 0, "Backend certificate renewal requires a root operator")
    pki = Path(config["IDENTITY_PKI_DIR"])
    require_root_path(pki, directory=True, missing=True)
    require_root_path(Path(config["IDENTITY_BACKEND_CA_KEY"]), missing=True, mode=0o600)
    pki.mkdir(parents=True, exist_ok=True, mode=0o755)
    require_root_path(pki / "renew.lock", missing=True)

    with (pki / "renew.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_root_path(pki / "ca.pem", missing=True)

        for service in ("kanidm", "portal"):
            require_root_path(pki / service, directory=True, missing=True)

        certificates.ensure_ca(pki, config["IDENTITY_BACKEND_CA_KEY"])
        changed = [
            service
            for service, host in (
                ("kanidm", "auth.slugsec.club"),
                ("portal", "my.slugsec.club"),
            )
            if certificates.issue(
                pki,
                config["IDENTITY_BACKEND_CA_KEY"],
                service,
                host,
                gid=10001 if service == "kanidm" else 10002,
            )
        ]

        if activate:
            for service in ("kanidm", "portal"):
                generation = (pki / service / "current").readlink()
                require(
                    re.fullmatch(r"generation-[a-f0-9]{24}", str(generation)),
                    "Backend TLS generation must stay in its service directory",
                )
                require_root_path(pki / service / generation, directory=True)
                activated = pki / f"{service}.activated"
                require_root_path(activated, missing=True)

                if activated.exists() and activated.read_text() == str(generation):
                    continue

                if service == "kanidm":
                    compose(config, "kill", "--signal", "SIGHUP", service)
                else:
                    compose(config, "restart", service)

                with tempfile.NamedTemporaryFile(
                    mode="w", dir=pki, delete=False
                ) as stream:
                    temporary = Path(stream.name)

                    try:
                        stream.write(str(generation))
                        stream.flush()
                        os.fsync(stream.fileno())
                        temporary.replace(activated)
                    finally:
                        temporary.unlink(missing_ok=True)

        print(
            "Backend certificates renewed"
            if changed
            else "Backend certificates remain valid"
        )


def main() -> None:
    startup_deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "validate",
            "prepare",
            "renew-certificates",
            "backup-status",
            "private-stage",
            "up",
        ),
    )
    parser.add_argument("--env", required=True)
    arguments = parser.parse_args(namespace=Arguments())
    config = environment(arguments.env)

    if arguments.command == "prepare":
        prepare(config)
        return

    if arguments.command == "renew-certificates":
        renew(config)
        return

    if arguments.command == "backup-status":
        backup_status(config)
        return

    validate(config, deadline=startup_deadline if arguments.command == "up" else None)

    if arguments.command == "private-stage":
        backup_status(config)
        compose(
            config,
            "up",
            "--detach",
            "kanidm",
            "posix",
            "access",
            "portal",
            "observer",
        )
        print("Private identity services staged")

    if arguments.command == "up":
        backup_status(config)
        compose(
            config,
            "up",
            "--detach",
            "kanidm",
            "posix",
            "access",
            "portal",
            "observer",
            timeout=remaining_timeout(startup_deadline),
        )
        wait_for_readiness(config, startup_deadline)

    print("Production deployment validated")


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        print("Deployment command timed out, output was withheld", file=sys.stderr)
        raise SystemExit(1) from error
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
