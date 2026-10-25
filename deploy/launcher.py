#!/usr/bin/env python3

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "service"))
sys.path.insert(0, str(ROOT / "deploy"))
os.umask(0o077)


def create_app() -> Flask:
    import runtime as native

    sys.modules["container"] = native
    from enrollment import create_app as factory

    return factory()


@dataclass
class Arguments(argparse.Namespace):
    command: str = ""
    service: str | None = None
    actor: str | None = None
    team: str | None = None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "web",
            "observer",
            "bootstrap",
            "posix",
            "access",
            "activate-group",
            "check",
            "rotate",
            "retire",
            "login",
            "reauth",
            "logout",
        ],
    )
    parser.add_argument(
        "service",
        nargs="?",
        choices=[
            "enrollment",
            "posix",
            "monitor",
            "authorization",
            "access",
            "admin",
            "idm_admin",
        ],
    )
    parser.add_argument("--actor")
    parser.add_argument("--team")
    arguments = parser.parse_args(namespace=Arguments())

    if arguments.command != "activate-group" and (
        arguments.actor is not None or arguments.team is not None
    ):
        parser.error("--actor and --team require activate-group")

    if arguments.command in {"check", "activate-group"} and os.geteuid() != 10002:
        parser.error("Readiness and group activation require service UID 10002")

    if (
        arguments.command == "check"
        and os.environ.get("IDENTITY_PROCESS_ROLE") != "portal"
    ):
        parser.error("Readiness requires the portal service role")

    if arguments.command == "observer":
        if arguments.service is not None:
            parser.error("Observer does not accept a service")

        observer_container_bind = "0.0.0.0"  # nosec B104
        os.execv(
            sys.executable,
            [
                sys.executable,
                str(ROOT / "service/observability.py"),
                "--credentials",
                "/run/observer/credentials.json",
                "--url",
                "https://auth.slugsec.club",
                "--ca",
                "/observe/ca.pem",
                "--service-account",
                "directory_reader",
                "--group",
                "members",
                "--dashboard-output",
                "/dashboards/identity.json",
                "--lookup-dashboard-output",
                "/member-dashboards/directory.json",
                "--usage-metrics",
                "/observe/usage/usage.prom",
                "--operations-url",
                "https://portal:9443/operations/metrics",
                "--bind",
                observer_container_bind,
                "--port",
                "19101",
            ],
        )

    import runtime as native

    sys.modules["container"] = native

    if arguments.command in {"login", "reauth", "logout"}:
        if arguments.service not in {"admin", "idm_admin"}:
            parser.error("Native operator sessions require admin or idm_admin")

        environment = native.cli_env(arguments.service, interactive=True)
        os.execvpe("kanidm", ["kanidm", arguments.command], environment)
    elif arguments.command == "web":
        native.ready()
        os.execvp(
            "gunicorn",
            [
                "gunicorn",
                "--no-control-socket",
                "--bind",
                "0.0.0.0:443",
                "--bind",
                "0.0.0.0:9443",
                "--forwarded-allow-ips",
                "",
                "--workers",
                "1",
                "--threads",
                "2",
                "--keep-alive",  # gunicorn 26 direct tls connections stall in chromium when reused
                "0",
                "--timeout",
                "30",
                "--certfile",
                "/run/tls/portal/current/chain.pem",
                "--keyfile",
                "/run/tls/portal/current/key.pem",
                "--access-logfile",
                "/dev/null",
                "--error-logfile",
                "-",
                "launcher:create_app()",
            ],
        )
    elif arguments.command == "bootstrap":
        os.environ["IDENTITY_BOOTSTRAP_PASSWORD"] = "1"
        from bootstrap import run

        run()
    elif arguments.command == "posix":
        from posix_defaults import run

        run()
    elif arguments.command == "access":
        from access_runtime import run

        run()
    elif arguments.command == "activate-group":
        if (
            arguments.service is not None
            or arguments.actor is None
            or arguments.team is None
        ):
            parser.error("Group activation requires --actor and --team")

        from access_runtime import activate_group

        print(json.dumps(activate_group(arguments.actor, arguments.team)))
    elif arguments.command == "check":
        import operations

        snapshot = operations.dependency_snapshot()
        from enrollment_kanidm import privileged_readiness

        privileged = privileged_readiness()
        native.require_native_credential_compare()
        ready = snapshot["ready"] and privileged["ready"]
        print(
            "Production dependencies and privileged authenticators ready"
            if ready
            else "Production dependencies or privileged authenticators require attention"
        )
        raise SystemExit(0 if ready else 1)
    else:
        if arguments.service is None:
            parser.error("Token rotation requires a service")

        import operations

        if arguments.service not in operations.PRINCIPALS:
            parser.error("Token maintenance requires a service principal")

        if arguments.command == "rotate":
            operations.rotate(arguments.service)
            print(
                "Service credential rotated, retire the replaced token after consumers reload"
            )
        else:
            operations.retire(arguments.service)
            print("Replaced service credential retired")


if __name__ == "__main__":
    main()
