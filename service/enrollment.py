import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import (
    Literal,
    NotRequired,
    Protocol,
    TypedDict,
    TypeGuard,
    cast,
    overload,
    runtime_checkable,
)
from urllib.parse import quote, urlencode

import qrcode
import qrcode.image.svg
from flask import (
    Flask,
    Request,
    abort,
    g,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
)
from flask import (
    session as flask_session,
)
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Response

import access_portal
import access_runtime
import branding_config as branding
import directory
import enrollment_google as google
import enrollment_kanidm as kanidm
import membership
import membership_portal
import operations
from contracts import (
    ProductionRuntime,
    is_list,
    is_object_dict,
    json_number,
)
from runtime_view import runtime as container

BASE_URL = container.PORTAL_URL
STATE = container.STATE / "enrollment"
DATABASE = STATE / "enrollment.sqlite3"
GOOGLE_CONFIG = STATE / "google-client.json"
SESSION_TTL = 7 * 24 * 3600
COOKIE_NAME = "__Host-enrollment"


type RouteResult = str | Response | tuple[str, int]
type SqlRow = dict[str, object]


class EnrollmentRecord(TypedDict):
    id: str
    person_uuid: str
    issuer: str
    subject: str
    username: str
    name: str
    email: str
    status: str
    created_at: str


class GoogleFlow(TypedDict):
    state: str
    nonce: str
    verifier: str
    started: int | float
    purpose: NotRequired[str]


class RecoveryProof(TypedDict):
    id: str
    application_id: str
    issuer: str
    subject: str
    verified_at: int | float


class CredentialSetup(TypedDict):
    application_id: str
    mode: str
    native: kanidm.CredentialSession
    stage: str
    totp: NotRequired[kanidm.TotpDetails]
    compatibility: NotRequired[bool]


class ReadinessCache(TypedDict):
    at: float
    snapshot: operations.DependencySnapshot | None


def _is_identity(value: object) -> TypeGuard[google.GoogleIdentity]:
    return (
        is_object_dict(value)
        and all(
            isinstance(value.get(key), str)
            for key in ("issuer", "subject", "email", "display_name")
        )
        and type(value.get("is_ucsc")) is bool
        and type(value.get("email_authority")) is bool
    )


def _is_flow(value: object) -> TypeGuard[GoogleFlow]:
    return (
        is_object_dict(value)
        and all(
            isinstance(value.get(key), str) for key in ("state", "nonce", "verifier")
        )
        and type(value.get("started")) in (int, float)
        and ("purpose" not in value or isinstance(value["purpose"], str))
    )


def _is_proof(value: object) -> TypeGuard[RecoveryProof]:
    return (
        is_object_dict(value)
        and all(
            isinstance(value.get(key), str)
            for key in ("id", "application_id", "issuer", "subject")
        )
        and type(value.get("verified_at")) in (int, float)
    )


def _is_totp(value: object) -> TypeGuard[kanidm.TotpDetails]:
    if not is_object_dict(value):
        return False

    secret = value.get("secret")
    return (
        all(
            isinstance(value.get(key), str) for key in ("accountname", "issuer", "algo")
        )
        and all(type(value.get(key)) is int for key in ("step", "digits"))
        and is_list(secret)
        and all(type(item) is int and 0 <= item <= 255 for item in secret)
    )


def _is_credentials(value: object) -> TypeGuard[CredentialSetup]:
    if not is_object_dict(value):
        return False

    native = value.get("native")
    return (
        all(
            isinstance(value.get(key), str)
            for key in ("application_id", "mode", "stage")
        )
        and is_object_dict(native)
        and all(isinstance(native.get(key), str) for key in ("token", "person_uuid"))
        and type(native.get("expires_at")) is int
        and type(native.get("recovery")) is bool
        and (
            "primary_replaced" not in native or type(native["primary_replaced"]) is bool
        )
        and ("totp" not in value or _is_totp(value["totp"]))
        and ("compatibility" not in value or type(value["compatibility"]) is bool)
    )


def _is_enrollment(value: object) -> TypeGuard[EnrollmentRecord]:
    return is_object_dict(value) and all(
        isinstance(value.get(key), str)
        for key in (
            "id",
            "person_uuid",
            "issuer",
            "subject",
            "username",
            "name",
            "email",
            "status",
            "created_at",
        )
    )


def enrollment_record(value: object) -> EnrollmentRecord | None:
    if value is None:
        return None

    if not _is_enrollment(value):
        raise RuntimeError("Invalid saved enrollment")

    return value


@contextlib.contextmanager
def connect(path: Path = DATABASE) -> Generator[sqlite3.Connection]:
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize(path: Path = DATABASE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)

    with connect(path) as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY, person_uuid TEXT UNIQUE NOT NULL,
                issuer TEXT NOT NULL, subject TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                email TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(issuer, subject)
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, application_id TEXT NOT NULL,
                action TEXT NOT NULL, actor TEXT NOT NULL, at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recovery_authorizations (
                id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
                verified_at REAL NOT NULL, consumed_at REAL
            );
        """)

    path.chmod(0o600)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def username_from_email(email: str) -> str:
    return email.split("@", 1)[0].lower()


def same_secret(expected: object, received: object) -> bool:
    return (
        isinstance(expected, str)
        and isinstance(received, str)
        and hmac.compare_digest(expected.encode(), received.encode())
    )


def google_settings() -> google.GoogleClientConfig:
    config = google.load_config(GOOGLE_CONFIG)

    if BASE_URL + "/google/callback" not in config["redirect_uris"]:
        raise google.GoogleSetupError(
            f"Register {BASE_URL}/google/callback on the Google OAuth web client."
        )

    return config


@runtime_checkable
class SessionItems(Protocol):
    def keys(self) -> Iterable[str]: ...
    def __getitem__(self, key: str, /) -> object: ...


class ServerSession(CallbackDict[str, object], SessionMixin):
    def __init__(
        self,
        sid: str,
        data: Mapping[str, object] | None = None,
        opened_data: str | None = None,
    ) -> None:
        super().__init__(data, lambda item: setattr(item, "modified", True))
        self.sid = sid
        self.opened_data = opened_data
        self.modified = False

    def update(
        self,
        items: SessionItems | Iterable[tuple[str, object]] | None = None,
        /,
        **kwargs: object,
    ) -> None:
        if isinstance(items, SessionItems):
            items = {key: items[key] for key in list(items.keys())}
        super().update(items, **kwargs)


def current_session() -> ServerSession:
    if not isinstance(flask_session, ServerSession):
        raise RuntimeError("Invalid enrollment session interface")

    return flask_session


def stored[T](key: str, check: Callable[[object], TypeGuard[T]]) -> T | None:
    value = current_session().get(key)
    return value if check(value) else None


def session_database(app: Flask) -> Path:
    config: object = app.config

    if not is_object_dict(config):
        raise RuntimeError("Invalid enrollment configuration")

    value = config.get("DATABASE")

    if not isinstance(value, Path):
        raise RuntimeError("Invalid enrollment database path")

    return value


class SQLiteSessions(SessionInterface):
    def open_session(self, app: Flask, request: Request) -> ServerSession:
        if request.path.startswith("/assets/"):
            return ServerSession(secrets.token_urlsafe(32))

        sid = request.cookies.get(COOKIE_NAME, "")

        if re.fullmatch(r"[A-Za-z0-9_-]{43}", sid):
            key = hashlib.sha256(sid.encode()).hexdigest()
            with connect(session_database(app)) as db:
                row: sqlite3.Row | None = db.execute(
                    "SELECT data FROM sessions WHERE id=? AND expires_at>?",
                    (key, int(time.time())),
                ).fetchone()

            if row:
                data: object = json.loads(row["data"])

                if not is_object_dict(data):
                    raise RuntimeError("Invalid saved browser session")

                return ServerSession(sid, data, row["data"])

        return ServerSession(secrets.token_urlsafe(32))

    def save_session(
        self, app: Flask, session: SessionMixin, response: Response
    ) -> None:
        if not isinstance(session, ServerSession):
            raise RuntimeError("Invalid enrollment session interface")

        saved = session

        if has_request_context() and request.path.startswith("/assets/"):
            return

        key = hashlib.sha256(saved.sid.encode()).hexdigest()
        current_time = int(time.time())

        if not saved:
            if saved.opened_data is None:
                return

            with connect(session_database(app)) as db:
                result = db.execute(
                    "DELETE FROM sessions WHERE id=? AND data=? AND expires_at>?",
                    (key, saved.opened_data, current_time),
                )

            if result.rowcount != 1:
                return

            response.delete_cookie(
                COOKIE_NAME, secure=True, httponly=True, samesite="Lax"
            )
            return

        serialized = json.dumps(dict(saved))
        expires_at = current_time + SESSION_TTL
        with connect(session_database(app)) as db:
            db.execute("DELETE FROM sessions WHERE expires_at<?", (current_time,))

            if saved.opened_data is None:
                db.execute(
                    "INSERT INTO sessions VALUES (?, ?, ?)",
                    (key, serialized, expires_at),
                )
            else:
                result = db.execute(
                    "UPDATE sessions SET data=?, expires_at=? WHERE id=? AND data=? "
                    "AND expires_at>?",
                    (serialized, expires_at, key, saved.opened_data, current_time),
                )

                if result.rowcount != 1:
                    return

        saved.opened_data = serialized
        response.set_cookie(
            COOKIE_NAME,
            saved.sid,
            max_age=SESSION_TTL,
            secure=True,
            httponly=True,
            samesite="Lax",
        )


def create_app(database: Path = DATABASE) -> Flask:
    initialize(database)
    app = Flask(__name__, template_folder="enrollment-ui", static_folder=None)
    app.jinja_env.filters["study_names"] = membership.study_names
    app.config["DATABASE"] = database
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["TESTING"] = False
    app.session_interface = SQLiteSessions()

    @app.before_request
    def private_operations() -> None:
        if not isinstance(container, ProductionRuntime) or not (
            request.path in {"/ready", "/operations"}
            or request.path.startswith("/operations/")
        ):
            return

        connection = request.environ.get("gunicorn.socket")

        if not isinstance(connection, socket.socket):
            abort(404)

        try:
            address = cast(tuple[object, ...] | str, connection.getsockname())
        except OSError:
            abort(404)

        if not isinstance(address, tuple) or len(address) < 2 or address[1] != 9443:
            abort(404)

    membership_store = membership.MembershipStore(database)
    readiness_lock = threading.Lock()
    readiness_cache: ReadinessCache = {"at": 0.0, "snapshot": None}

    def unavailable_readiness() -> operations.DependencySnapshot:
        return {
            "ready": False,
            "checked_at": time.time(),
            "checks": {"configuration": False},
            "token_remaining_seconds": {},
            "signals": {},
            "alarms": [],
        }

    def readiness_snapshot() -> operations.DependencySnapshot:
        if not readiness_lock.acquire(
            blocking=False
        ):  # self tls checks need a free request worker
            cached = readiness_cache.copy()

            if cached["snapshot"] is not None and time.monotonic() - cached["at"] < 30:
                return cached["snapshot"]

            return unavailable_readiness()

        try:
            current = time.monotonic()

            if (
                readiness_cache["snapshot"] is None
                or current - readiness_cache["at"] >= 15
            ):
                try:
                    snapshot = operations.dependency_snapshot()
                except operations.SAFE_FAILURES:
                    snapshot = unavailable_readiness()
                readiness_cache.update({"at": current, "snapshot": snapshot})

            cached_snapshot = readiness_cache["snapshot"]

            if cached_snapshot is None:
                raise RuntimeError("Missing readiness snapshot")

            return cached_snapshot
        finally:
            readiness_lock.release()

    @overload
    def sql(
        query: str, values: Sequence[object] = (), *, one: Literal[True]
    ) -> SqlRow | None: ...

    @overload
    def sql(
        query: str, values: Sequence[object] = (), *, one: Literal[False] = False
    ) -> list[SqlRow]: ...

    def sql(
        query: str, values: Sequence[object] = (), *, one: bool = False
    ) -> SqlRow | list[SqlRow] | None:
        with connect(database) as db:
            cursor = db.execute(query, values)
            rows: list[sqlite3.Row] = cursor.fetchall() if cursor.description else []

        if one:
            return dict(rows[0]) if rows else None

        return [dict(row) for row in rows]

    def page(page: str, **values: object) -> str:
        session = current_session()
        csrf = session.setdefault("csrf", secrets.token_urlsafe(32))
        membership_identity = values.get("membership_identity")
        account_name = (
            membership_identity.get("name")
            if is_object_dict(membership_identity)
            else None
        )

        if not account_name:
            account_name = g.get("account_name", "Account")

        return render_template(
            "page.html",
            page=page,
            csrf=csrf,
            auth_title=branding.AUTH_TITLE,
            tagline=branding.TAGLINE,
            auth_login_url=container.URL + "/ui/login",
            account_name=account_name,
            credentials_url=container.URL + "/ui/update_credentials",
            identity=session.get("identity"),
            google_username=username_from_email(
                identity["email"]
                if (identity := stored("identity", _is_identity))
                else ""
            ),
            **values,
        )

    def csrf_check() -> None:
        session = current_session()
        expected, received = session.get("csrf"), request.form.get("csrf", "")

        if not expected or not same_secret(expected, received):
            abort(403, "Reload the page before submitting this form.")

        if request.headers.get("Origin") not in (None, BASE_URL):
            app.logger.warning("Rejected form origin %r", request.headers.get("Origin"))
            abort(403, "This form must be submitted from the SlugSec enrollment page.")

    def rotate_session() -> None:
        session = current_session()
        old_key = hashlib.sha256(session.sid.encode()).hexdigest()
        sql("DELETE FROM sessions WHERE id=?", (old_key,))
        session.sid = secrets.token_urlsafe(32)
        session.opened_data = None

    def owned_enrollment() -> EnrollmentRecord:
        session = current_session()
        application = enrollment_record(
            sql(
                "SELECT * FROM applications WHERE id=?",
                (session.get("application_id", ""),),
                one=True,
            )
        )

        if not application:
            abort(404)

        return application

    @contextlib.contextmanager
    def mutations() -> Generator[None]:
        with (STATE / "portal-mutations.lock").open("a+") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def audit(application_id: str, action: str, actor: str) -> None:
        sql(
            "INSERT INTO audit(application_id, action, actor, at) VALUES (?, ?, ?, ?)",
            (application_id, action, actor, now()),
        )

    def provision(application: EnrollmentRecord) -> bool:
        try:
            kanidm.provision_person(
                application["id"],
                application["person_uuid"],
                application["username"],
                application["name"],
                application["email"],
            )
        except (RuntimeError, OSError, ValueError) as error:
            app.logger.error("Account provisioning failed, %s", type(error).__name__)
            sql(
                "UPDATE applications SET status='provisioning_error' WHERE id=?",
                (application["id"],),
            )
            return False

        sql(
            "UPDATE applications SET status='setup_required' WHERE id=?",
            (application["id"],),
        )
        return True

    def new_enrollment(identity: google.GoogleIdentity) -> EnrollmentRecord:
        session = current_session()

        if (
            identity.get("is_ucsc") is not True
            or identity.get("issuer") != google.GOOGLE_ISSUER
        ):
            raise ValueError("Use a UCSC account to continue.")

        username = username_from_email(identity["email"])

        if (
            not kanidm.USERNAME.fullmatch(username)
            or username in kanidm.RESERVED
            or username.startswith(("idm_", "system_", "identity_"))
        ):
            raise ValueError(
                "Your verified email prefix cannot be used as a SlugSec username. "
                "Contact an officer for help."
            )

        identifier, person_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        with connect(database) as db:
            db.execute(
                """INSERT INTO applications
                (id, person_uuid, issuer, subject, username, name, email,
                 status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'creating', ?)""",
                (
                    identifier,
                    person_uuid,
                    identity["issuer"],
                    identity["subject"],
                    username,
                    identity["display_name"],
                    identity["email"],
                    now(),
                ),
            )
            db.execute(
                "INSERT INTO audit(application_id, action, actor, at) VALUES (?, ?, "
                "?, ?)",
                (
                    identifier,
                    "school_verified",
                    "google",
                    now(),
                ),
            )

        session["application_id"] = identifier
        result = enrollment_record(
            sql("SELECT * FROM applications WHERE id=?", (identifier,), one=True)
        )

        if result is None:
            raise RuntimeError("New enrollment was not saved")

        return result

    def recovery_check(application: EnrollmentRecord) -> RecoveryProof:
        session = current_session()
        proof = stored("recovery_proof", _is_proof)
        authorization = sql(
            "SELECT * FROM recovery_authorizations WHERE id=? AND application_id=? "
            "AND consumed_at IS NULL",
            (proof["id"] if proof else "", application["id"]),
            one=True,
        )

        if (
            not authorization
            or not proof
            or not 0 <= time.time() - json_number(authorization["verified_at"]) <= 600
            or proof.get("application_id") != application["id"]
            or proof.get("issuer") != application["issuer"]
            or proof.get("subject") != application["subject"]
            or not 0 <= time.time() - proof.get("verified_at", 0) <= 600
            or application["status"] != "active"
        ):
            session.pop("recovery_proof", None)
            session.pop("credential_setup", None)
            abort(403, "Verify your UCSC Google account again to recover this account.")

        status = kanidm.account_status(application["person_uuid"])

        if (
            status.get("expired")
            or status.get("not_yet_valid")
            or not status.get("approved")
        ):
            session.pop("recovery_proof", None)
            session.pop("credential_setup", None)
            abort(
                403,
                "This account is not active. Contact infrastructure administration.",
            )

        return proof

    def consume_recovery(application: EnrollmentRecord) -> None:
        proof = recovery_check(application)
        with connect(database) as db:
            result = db.execute(
                "UPDATE recovery_authorizations SET consumed_at=? WHERE id=? AND "
                "application_id=? AND consumed_at IS NULL",
                (time.time(), proof["id"], application["id"]),
            )

        if result.rowcount != 1:
            abort(403, "Verify your UCSC Google account again to recover this account.")

    def credential_context(application: EnrollmentRecord) -> CredentialSetup | None:
        session = current_session()
        context = stored("credential_setup", _is_credentials)

        if context and context.get("application_id") != application["id"]:
            abort(403, "This setup session belongs to another account.")

        if session.get("recovery_proof") or (
            context and context.get("mode") == "recover"
        ):
            recovery_check(application)
        elif application["status"] not in (
            "creating",
            "setup_required",
            "provisioning_error",
        ):
            abort(403, "Account setup is not available for this account.")

        return context

    def totp_key(totp: kanidm.TotpDetails) -> str:
        return base64.b32encode(bytes(totp["secret"])).decode("ascii").rstrip("=")

    def setup_page(application: EnrollmentRecord, **values: object) -> str:
        session = current_session()
        context = credential_context(application)
        totp = context.get("totp") if context else None
        return page(
            "setup",
            application=application,
            recovery=bool(session.get("recovery_proof")),
            credential_stage=context["stage"] if context else "password",
            totp_secret=totp_key(totp) if totp else "",
            compatibility=context.get("compatibility", False) if context else False,
            **values,
        )

    def password_errors() -> list[str]:
        password = request.form.get("password", "")

        if not 15 <= len(password) <= 128:
            return ["Use a password between 15 and 128 characters."]

        if password != request.form.get("password_confirm", ""):
            return ["The passwords do not match."]

        return []

    def stage_password(application: EnrollmentRecord) -> RouteResult:
        session = current_session()
        context: CredentialSetup | None = credential_context(application)
        recovery = bool(session.get("recovery_proof"))

        if not context:
            context = {
                "application_id": application["id"],
                "mode": "recover" if recovery else "enroll",
                "native": kanidm.begin_credentials(
                    application["person_uuid"], recovery=recovery
                ),
                "stage": "password",
            }

        if context["stage"] != "password":
            return redirect("/setup")

        session["credential_setup"] = context
        status = kanidm.set_password(
            application["person_uuid"],
            context["native"],
            request.form["password"],
            replace_primary=recovery,
        )

        if status.get("can_commit") and not status.get("warnings"):
            return finish_credentials(application, context, status)

        if "MfaRequired" not in status.get("warnings", []):
            raise kanidm.CredentialValidationError(
                "Your account requires another sign-in method. Contact infrastructure"
                " administration."
            )

        status = kanidm.generate_totp(application["person_uuid"], context["native"])
        totp = status.get("mfaregstate", {})

        if not is_object_dict(totp):
            raise kanidm.CredentialValidationError(
                "Authenticator setup could not start. Try again."
            )

        details = totp.get("TotpCheck")

        if not _is_totp(details):
            raise kanidm.CredentialValidationError(
                "Authenticator setup could not start. Try again."
            )

        context.update({"stage": "totp", "totp": details})
        session["credential_setup"] = context
        return redirect("/setup")

    def credential_error(
        error: kanidm.CredentialValidationError, application: EnrollmentRecord
    ) -> tuple[str, int]:
        session = current_session()

        if error.restart:
            session.pop("credential_setup", None)

        return setup_page(
            application, errors=[str(error)]
        ), 409 if error.restart else 400

    def finish_admission(application: EnrollmentRecord) -> None:
        kanidm.complete_credentials(application["person_uuid"])
        membership_store.ensure_account(application["person_uuid"])
        sql("UPDATE applications SET status='active' WHERE id=?", (application["id"],))
        audit(application["id"], "activated", "google")
        event("enrollment_created")

    def login_response(destination: str | None = None) -> Response:
        destination = destination or container.URL + "/ui/login"

        if request.accept_mimetypes.best == "application/json":
            return jsonify(redirect=destination)

        return redirect(destination)

    def finish_credentials(
        application: EnrollmentRecord,
        context: CredentialSetup,
        status: kanidm.CredentialStatus,
    ) -> Response:
        session = current_session()

        if not status.get("can_commit") or status.get("warnings"):
            raise kanidm.CredentialValidationError(
                "Finish setting up your credentials first."
            )

        if context["mode"] == "recover":
            consume_recovery(application)

        kanidm.commit_credentials(application["person_uuid"], context["native"])
        access_portal.discard_other_identities(application["person_uuid"])
        session.pop("credential_setup", None)

        if context["mode"] == "enroll":
            finish_admission(application)
            session["membership_onboarding"] = {
                "uuid": application["person_uuid"],
                "expires_at": time.time() + 1800,
            }
        else:
            audit(application["id"], "credentials_recovered", "google")
            event("recovery_completed")

        session.pop("recovery_proof", None)
        return login_response("/membership" if context["mode"] == "enroll" else None)

    @app.after_request
    def headers(response: Response) -> Response:
        session = current_session()
        response.headers["Cache-Control"] = (
            "no-cache" if request.path.startswith("/assets/") else "no-store"
        )
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; "
            f"form-action 'self' https://accounts.google.com {container.URL}; "
            "frame-ancestors 'none'; base-uri 'none'"
        )

        if response.status_code >= 400 and request.path in (
            "/join/complete",
            "/join",
            "/setup",
            "/google/callback",
        ):
            event(
                "recovery_failed"
                if session.get("recovery_proof")
                else "enrollment_failed"
            )

        return response

    def event(name: str) -> None:
        if app.testing:
            return

        try:
            operations.record_event(name)
        except operations.SAFE_FAILURES:
            app.logger.error("Operational event could not be saved")

    def error_page(message: str, status: int) -> tuple[str, int]:
        for path, kind, label in (
            ("/access", "access_error", "Groups"),
            ("/membership", "membership_error", "Registration"),
        ):
            if request.path == path or request.path.startswith(path + "/"):
                return page(
                    kind,
                    message=message,
                    action_url=path,
                    action_label=label,
                ), status

        return page("error", message=message), status

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    def expected_error(error: HTTPException) -> tuple[str, int]:
        return error_page(
            error.description or "The request could not be completed.",
            error.code or 500,
        )

    @app.errorhandler(RuntimeError)
    @app.errorhandler(OSError)
    def unavailable(error: RuntimeError | OSError) -> tuple[str, int]:
        app.logger.error("Enrollment operation failed, %s", type(error).__name__)
        return error_page("This service is unavailable. Try again.", 503)

    @app.get("/assets/<name>")
    def assets(name: str) -> Response:
        files = {
            "bootstrap.bundle.min.js": Path(
                os.environ.get(
                    "IDENTITY_BOOTSTRAP_JS",
                    Path(__file__).with_name("enrollment-ui")
                    / "bootstrap.bundle.min.js",
                )
            ),
            "bootstrap.min.css": Path(
                os.environ.get(
                    "IDENTITY_BOOTSTRAP_CSS",
                    Path(__file__).with_name("enrollment-ui") / "bootstrap.min.css",
                )
            ),
            "style.css": Path(__file__).with_name("enrollment-ui") / "style.css",
            "flow.js": Path(__file__).with_name("enrollment-ui") / "flow.js",
            "logo.png": container.ROOT / "service" / "branding" / "slugsec-logo.png",
            "background.webp": branding.BACKGROUND,
        }

        if name not in files:
            abort(404)

        return send_file(files[name])

    @app.get("/")
    def index() -> Response:
        return redirect(container.URL + "/ui/login")

    @app.get("/join")
    def join() -> str:
        return page("join")

    @app.get("/join/profile")
    def join_profile() -> RouteResult:
        session = current_session()

        if not session.get("identity") and session.get("application_id"):
            return redirect("/setup")

        if not session.get("identity"):
            return redirect("/join")

        identity = stored("identity", _is_identity)

        if not identity or identity["is_ucsc"] is not True:
            return page("join", message="Use a UCSC account to continue.")

        return page("profile")

    @app.get("/recover")
    def recover() -> str:
        return page("recover")

    @app.post("/google/start")
    def google_start() -> RouteResult:
        session = current_session()
        csrf_check()
        purpose = request.form.get("purpose")

        if purpose not in ("enroll", "recovery"):
            abort(400, "Choose account creation or recovery.")

        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        try:
            config = google_settings()
            destination = google.authorization_url(
                config, BASE_URL + "/google/callback", state, nonce, verifier
            )
        except google.GoogleSetupError as error:
            return page("error", message=str(error)), 503

        session["google_flow"] = {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "started": time.time(),
            "purpose": purpose,
        }
        return redirect(destination)

    @app.get("/google/callback")
    def google_callback() -> RouteResult:
        session = current_session()
        flow_value = session.pop("google_flow", None)
        flow = flow_value if _is_flow(flow_value) else None
        purpose = flow.get("purpose") if flow else None

        if (
            not flow
            or purpose not in ("enroll", "recovery")
            or not 0 <= time.time() - flow["started"] <= 600
            or not same_secret(flow["state"], request.args.get("state", ""))
        ):
            abort(
                400,
                "Google verification failed. Start again.",
            )

        if request.args.get("error") or not request.args.get("code"):
            abort(400, "Google verification was cancelled.")

        try:
            identity = google.exchange_and_verify(
                google_settings(),
                request.args["code"],
                BASE_URL + "/google/callback",
                flow["verifier"],
                flow["nonce"],
            )
        except (google.GoogleSetupError, google.GoogleVerificationError) as error:
            return page("error", message=str(error)), 400

        if identity["is_ucsc"] is not True:
            abort(403, "Use a UCSC account to continue.")

        existing = enrollment_record(
            sql(
                "SELECT * FROM applications WHERE issuer=? AND subject=?",
                (identity["issuer"], identity["subject"]),
                one=True,
            )
        )

        rotate_session()
        unfinished = bool(
            existing
            and existing["status"]
            in ("creating", "setup_required", "provisioning_error")
        )

        context = stored("credential_setup", _is_credentials)
        expected_mode = (
            "recover" if purpose == "recovery" and not unfinished else "enroll"
        )

        if (
            not existing
            or not context
            or context.get("application_id") != existing["id"]
            or context.get("mode") != expected_mode
        ):
            session.pop("credential_setup", None)

        session.pop("recovery_proof", None)

        if purpose == "recovery":
            session.pop("identity", None)
            session.pop("identity_verified_at", None)
            session.pop("application_id", None)

            if not existing:
                abort(
                    403,
                    "No active SlugSec account is linked to this UCSC Google account.",
                )

            session["application_id"] = existing["id"]

            if unfinished:
                return redirect("/setup")

            authorization_id = secrets.token_urlsafe(32)
            verified_at = time.time()
            sql(
                "INSERT INTO recovery_authorizations(id, application_id, verified_at)"
                " VALUES (?, ?, ?)",
                (authorization_id, existing["id"], verified_at),
            )
            session["recovery_proof"] = {
                "id": authorization_id,
                "application_id": existing["id"],
                "issuer": identity["issuer"],
                "subject": identity["subject"],
                "verified_at": verified_at,
            }
            recovery_check(existing)
            audit(existing["id"], "recovery_verified", "google")
            event("recovery_started")
            return redirect("/setup")

        if existing:
            session["application_id"] = existing["id"]
            session.pop("identity", None)
            return redirect(
                "/setup"
                if existing["status"]
                in ("creating", "setup_required", "provisioning_error")
                else container.URL + "/ui/login"
            )

        session["identity"] = identity
        session["identity_verified_at"] = time.time()
        session.pop("application_id", None)
        return redirect("/join/profile")

    @app.post("/join/complete")
    def complete() -> RouteResult:
        session = current_session()
        csrf_check()
        identity = stored("identity", _is_identity)

        if not identity:
            abort(403, "Verify your Google account first.")

        verified_at = json_number(session.get("identity_verified_at", 0))

        if not 0 <= time.time() - verified_at <= 3600:
            session.pop("identity", None)
            abort(
                403,
                "Google verification expired. Sign in with Google again.",
            )

        if identity.get("is_ucsc") is not True:
            return page("join", message="Use a UCSC account to continue."), 403

        errors = password_errors()

        if errors:
            return page("profile", errors=errors), 400

        try:
            with mutations():
                application = new_enrollment(identity)
                provision(application)
        except (ValueError, sqlite3.IntegrityError) as error:
            message = (
                str(error)
                if isinstance(error, ValueError)
                else "An account already exists for these details. "
                "Sign in or contact an officer."
            )
            return page("profile", errors=[message]), 400

        session.pop("identity", None)
        session.pop("identity_verified_at", None)
        application = owned_enrollment()

        if application["status"] == "provisioning_error":
            return setup_page(
                application, errors=["Account creation could not finish. Try again."]
            ), 503

        try:
            with mutations():
                return stage_password(application)
        except kanidm.CredentialValidationError as error:
            return credential_error(error, application)

    @app.get("/setup")
    def setup() -> RouteResult:
        session = current_session()
        application = owned_enrollment()

        if session.get("recovery_proof"):
            recovery_check(application)
        elif application["status"] == "active":
            return redirect(container.URL + "/ui/login")

        context = credential_context(application)

        if context:
            try:
                kanidm.credential_status(application["person_uuid"], context["native"])
            except kanidm.CredentialValidationError as error:
                return credential_error(error, application)
        elif (
            not session.get("recovery_proof")
            and application["status"] == "setup_required"
            and kanidm.account_status(application["person_uuid"])["credential_present"]
        ):
            with mutations():
                application = owned_enrollment()

                if application["status"] == "setup_required":
                    finish_admission(application)

            session["membership_onboarding"] = {
                "uuid": application["person_uuid"],
                "expires_at": time.time() + 1800,
            }
            return redirect("/membership")

        return setup_page(application)

    @app.post("/setup")
    def setup_begin() -> RouteResult:
        session = current_session()
        csrf_check()
        application = owned_enrollment()
        credential_context(application)
        errors = password_errors()

        if errors:
            return setup_page(application, errors=errors), 400

        with mutations():
            if application["status"] in ("creating", "provisioning_error"):
                provision(application)
                application = owned_enrollment()

            if application["status"] == "provisioning_error":
                return setup_page(
                    application,
                    errors=["Account creation could not finish. Try again."],
                ), 503

            if application["status"] != "setup_required" and not session.get(
                "recovery_proof"
            ):
                abort(403, "Account setup is not available for this account.")

            if (
                not session.get("recovery_proof")
                and kanidm.account_status(application["person_uuid"])[
                    "credential_present"
                ]
            ):
                return setup_page(
                    application,
                    errors=[
                        "Credentials already exist. Use account recovery to change "
                        "them."
                    ],
                ), 409

            try:
                return stage_password(application)
            except kanidm.CredentialValidationError as error:
                return credential_error(error, application)

    @app.get("/setup/qr.svg")
    def setup_qr() -> Response:
        application = owned_enrollment()
        context = credential_context(application)

        if not context or context.get("stage") != "totp" or "totp" not in context:
            abort(404)

        kanidm.credential_status(application["person_uuid"], context["native"])
        totp = context["totp"]
        uri = (
            "otpauth://totp/"
            + quote(totp["issuer"] + ":" + totp["accountname"], safe="")
            + "?"
            + urlencode(
                {
                    "secret": totp_key(totp),
                    "issuer": totp["issuer"],
                    "algorithm": totp["algo"].upper(),
                    "digits": totp["digits"],
                    "period": totp["step"],
                }
            )
        )

        image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        return Response(image.to_string(), mimetype="image/svg+xml")

    @app.post("/setup/finish")
    def setup_finish() -> RouteResult:
        session = current_session()
        csrf_check()
        with mutations():
            application = owned_enrollment()

            if application["status"] == "active" and not session.get("recovery_proof"):
                return login_response()

            context = credential_context(application)

            if not context or context.get("stage") != "totp":
                return setup_page(
                    application, errors=["Create your password first."]
                ), 409

            try:
                if request.form.get("allow_sha1") == "on" and context.get(
                    "compatibility"
                ):
                    status = kanidm.accept_totp_sha1(
                        application["person_uuid"], context["native"]
                    )
                else:
                    status = kanidm.verify_totp(
                        application["person_uuid"],
                        context["native"],
                        request.form.get("code", ""),
                    )

                return finish_credentials(application, context, status)
            except kanidm.CredentialValidationError as error:
                if error.state == "TotpInvalidSha1":
                    context["compatibility"] = True
                    session["credential_setup"] = context

                return credential_error(error, application)

    @app.get("/health")
    def health() -> dict[str, str | bool]:
        return {"status": "ok", "google_configured": _google_ready()}

    @app.get("/ready")
    def ready() -> tuple[dict[str, object], int]:
        snapshot = readiness_snapshot()
        return {
            "ready": snapshot["ready"],
            "checked_at": snapshot["checked_at"],
            "checks": snapshot["checks"],
        }, 200 if snapshot["ready"] else 503

    @app.get("/operations/metrics")
    def operations_metrics() -> Response:
        return Response(
            operations.render_metrics(readiness_snapshot())
            + membership_store.demographic_metrics(),
            mimetype="text/plain",
        )

    @app.get("/operations/registrations")
    def registration_information() -> Response:
        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            abort(401)

        try:
            operations.authorize_registration_export(authorization[7:])
            catalog = {
                attrs["uuid"][0]: attrs
                for attrs in access_runtime.controller().backend.person_catalog()
                if "person" in attrs.get("class", [])
            }
            members: list[dict[str, str]] = []

            for record in membership_store.current_records():
                person = catalog.get(record["person_uuid"])

                if person is None or not kanidm.active_person(person):
                    continue

                answers = record["responses"]
                member = {
                    "person_uuid": record["person_uuid"],
                    "username": person["name"][0],
                    "name": person["displayname"][0],
                    "email": next(iter(person.get("mail", [])), ""),
                    "preferred_name": str(answers.get("preferred_name") or ""),
                    "studies": ", ".join(membership.study_names(answers)),
                    "referral_details": membership.referral_details(answers),
                    "submitted_at": record["submitted_at"],
                    "expires_at": record["expires_at"],
                    "status": "Submitted",
                }
                detailed_sources = {
                    code
                    for code, field in (
                        ("social_media", "social_media_source"),
                        ("faculty", "faculty_name"),
                        ("discord", "discord_source"),
                        ("other", "heard_about_other"),
                    )
                    if isinstance(value := answers.get(field), str) and value
                }

                for key in ("school_level", "shirt_size", "heard_about"):
                    value = answers.get(key)
                    codes = value if isinstance(value, list) else [value]

                    if key == "heard_about":
                        codes = [code for code in codes if code not in detailed_sources]
                    labels = dict(membership.OPTIONS[key])
                    member[key] = ", ".join(labels[code] for code in codes if code)

                if answers.get("shirt_size") == "other" and answers.get(
                    "shirt_size_other"
                ):
                    member["shirt_size"] += (
                        " (" + str(answers["shirt_size_other"]) + ")"
                    )

                members.append(member)

            return jsonify(
                members=members,
                first_registered={
                    identifier: instant
                    for identifier, instant in membership_store.first_registrations().items()
                    if identifier in catalog
                },
            )
        except operations.SAFE_FAILURES:
            abort(403)

    @app.get("/operations/directory")
    def group_directory() -> Response:
        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            abort(401)

        try:
            operations.authorize_registration_export(authorization[7:])
            return jsonify(directory.snapshot(access_runtime.controller().backend))
        except operations.SAFE_FAILURES:
            abort(403)

    def _google_ready() -> bool:
        try:
            google_settings()
            return True
        except google.GoogleSetupError:
            return False

    access_portal.register(app, page, csrf_check, rotate_session)
    membership_portal.register(app, page, csrf_check, membership_store)
    return app


if __name__ == "__main__":
    os.umask(0o077)
    create_app().run(
        host="127.0.0.1",
        port=18643,
        ssl_context=(
            str(container.DATA / "chain.pem"),
            str(container.DATA / "key.pem"),
        ),
    )
