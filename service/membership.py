import contextlib
import json
import os
import sqlite3
import time
import unicodedata
import uuid
from collections.abc import Callable, Generator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict, TypeGuard, overload
from zoneinfo import ZoneInfo

from contracts import is_mapping, is_sequence, is_str_list

type Responses = dict[str, str | list[str] | None]


class RegistrationPeriod(TypedDict):
    key: str
    startyear: int
    label: str
    starts_at: str
    expires_at: str


class RegistrationRecord(TypedDict):
    person_uuid: str
    period: str
    startyear: int
    starts_at: str
    expires_at: str
    submitted_at: str
    responses: Responses


class MembershipStatus(TypedDict):
    person_uuid: str
    suspended: bool
    period: str | None
    startyear: int | None
    starts_at: str | None
    expires_at: str | None
    submitted_at: str | None
    active: bool
    status: str


def _mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    return is_mapping(value) and all(isinstance(key, str) for key in value)


def _column[T](row: sqlite3.Row, key: str, expected: type[T]) -> T:
    value: object = row[key]

    if not isinstance(value, expected):
        raise MembershipUnavailable("Membership storage has an invalid field.")

    return value


def _optional_column[T](row: sqlite3.Row, key: str, expected: type[T]) -> T | None:
    return None if row[key] is None else _column(row, key, expected)


STUDENT_LEVELS = frozenset(
    {"freshman", "sophomore", "junior", "senior", "masters", "phd"}
)
OPTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "school_level": (
        ("freshman", "Freshman"),
        ("sophomore", "Sophomore"),
        ("junior", "Junior"),
        ("senior", "Senior"),
        ("masters", "Master's student"),
        ("phd", "PhD student"),
        ("other", "Other"),
        ("alumni", "Alumni"),
        ("nonstudent", "Nonstudent"),
    ),
    "studies": (
        ("ancient_studies", "Ancient Studies"),
        ("anthropology", "Anthropology"),
        ("applied_mathematics", "Applied Mathematics"),
        ("applied_physics", "Applied Physics"),
        ("assistive_technology", "Assistive Technology"),
        ("astrophysics", "Astrophysics"),
        ("biochemistry", "Biochemistry and Molecular Biology"),
        ("bioelectronics_biophotonics", "Bioelectronics and Biophotonics"),
        ("bioinformatics", "Bioinformatics"),
        ("biology", "Biology"),
        ("biomolecular_engineering", "Biomolecular Engineering and Bioinformatics"),
        ("black_studies", "Black Studies"),
        ("chemistry", "Chemistry"),
        ("cognitive_science", "Cognitive Science"),
        ("computer_engineering", "Computer Engineering"),
        ("computer_science", "Computer Science"),
        ("computer_science_game_design", "Computer Science: Computer Game Design"),
        ("dance", "Dance"),
        ("digital_justice_studies", "Digital Justice Studies"),
        ("earth_sciences", "Earth Sciences"),
        ("east_asian_studies", "East Asian Studies"),
        ("ecology_and_evolutionary_biology", "Ecology and Evolutionary Biology"),
        ("economics", "Economics"),
        ("education", "Education"),
        ("electrical_engineering", "Electrical Engineering"),
        ("electronic_music", "Electronic Music"),
        ("environmental_sciences", "Environmental Sciences"),
        ("film_digital_media", "Film and Digital Media"),
        ("history", "History"),
        ("history_art_visual_culture", "History of Art and Visual Culture"),
        ("history_consciousness", "History of Consciousness"),
        ("human_biology", "Human Biology"),
        ("italian_studies", "Italian Studies"),
        ("jazz_improvisation", "Jazz, Spontaneous Composition and Improvisation"),
        ("jewish_studies", "Jewish Studies"),
        ("language_studies", "Language Studies"),
        ("latin_american_latino_studies", "Latin American and Latino Studies"),
        ("legal_studies", "Legal Studies"),
        ("linguistics", "Linguistics"),
        ("literature", "Literature"),
        ("marine_biology", "Marine Biology"),
        ("mathematics", "Mathematics"),
        ("microbiology", "Microbiology"),
        (
            "middle_eastern_north_african_studies",
            "Middle Eastern and North African Studies",
        ),
        (
            "molecular_cell_and_developmental_biology",
            "Molecular, Cell and Developmental Biology",
        ),
        ("neuroscience", "Neuroscience"),
        ("philosophy", "Philosophy"),
        ("physics", "Physics"),
        ("plant_sciences", "Plant Sciences"),
        ("politics", "Politics"),
        ("robotics_engineering", "Robotics Engineering"),
        (
            "stem_education",
            "Science, Technology, Engineering and Mathematics Education",
        ),
        ("spanish_studies", "Spanish Studies"),
        ("statistics", "Statistics"),
        ("sustainability_studies", "Sustainability Studies"),
        (
            "technology_and_information_management",
            "Technology and Information Management",
        ),
        ("theater_arts", "Theater Arts"),
        ("western_music", "Western Music"),
        ("other", "Other"),
        ("undeclared", "Undeclared"),
    ),
    "shirt_size": (
        ("xs", "XS"),
        ("s", "S"),
        ("m", "M"),
        ("l", "L"),
        ("xl", "XL"),
        ("xxl", "XXL"),
        ("other", "Other"),
    ),
    "heard_about": (
        ("returning_member", "I'm a returning member"),
        ("friend", "Friend"),
        ("social_media", "Social media"),
        ("faculty", "Professor or faculty member"),
        ("discord", "Discord server or Student Hub"),
        ("campus", "Campus fair, event or flyer"),
        ("newsletter", "UCSC newsletter"),
        ("website", "SlugSec website"),
        ("other", "Other"),
    ),
    "gender": (
        ("male", "Male"),
        ("female", "Female"),
        ("nonbinary", "Nonbinary"),
        ("other", "Other"),
        ("prefer_not_to_say", "Prefer not to say"),
    ),
    "ethnicity": (
        ("american_indian_alaska_native", "American Indian or Alaska Native"),
        ("asian", "Asian"),
        ("black_african_american", "Black or African American"),
        ("hispanic_latino_spanish", "Hispanic, Latino, or Spanish origin"),
        ("native_hawaiian_pacific_islander", "Native Hawaiian or Pacific Islander"),
        ("white", "White"),
        ("other", "Other"),
        ("prefer_not_to_say", "Prefer not to say"),
    ),
    "lgbtq": (("yes", "Yes"), ("no", "No"), ("prefer_not_to_say", "Prefer not to say")),
    "veteran": (
        ("yes", "Yes"),
        ("no", "No"),
        ("prefer_not_to_say", "Prefer not to say"),
    ),
}


class MembershipValidationError(ValueError):
    def __init__(self, errors: dict[str, str]) -> None:
        self.errors = errors
        super().__init__("Check the registration fields.")


class AlreadySubmitted(RuntimeError):
    pass


class MembershipUnavailable(RuntimeError):
    pass


def study_names(answers: object) -> list[str]:
    if not _mapping(answers):
        return []

    names: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        if not isinstance(value, str):
            return

        value = unicodedata.normalize("NFC", value.strip())

        if value and value.casefold() not in seen:
            seen.add(value.casefold())
            names.append(value)

    selected = answers.get("studies")

    if not is_sequence(selected):
        return []

    labels = dict(OPTIONS["studies"])

    for code in selected:
        if isinstance(code, str):
            add(
                answers.get("study_other")
                if code == "other"
                else labels.get(code, code)
            )

    return names


def referral_details(answers: Responses) -> str:
    selected = answers.get("heard_about")

    if not isinstance(selected, list):
        return ""

    labels = dict(OPTIONS["heard_about"])
    details: list[str] = []

    for code, field in (
        ("social_media", "social_media_source"),
        ("faculty", "faculty_name"),
        ("discord", "discord_source"),
        ("other", "heard_about_other"),
    ):
        value = answers.get(field)

        if code in selected and isinstance(value, str) and value:
            details.append(f"{labels[code]}: {value}")

    return "\n".join(details)


def validate_responses(values: object) -> Responses:
    if not _mapping(values):
        raise MembershipValidationError({"form": "Submit valid registration fields."})

    errors: dict[str, str] = {}

    def raw(field: str) -> list[object]:
        value = values.get(field)

        if is_sequence(value):
            return list(value)

        return [] if value is None else [value]

    def text(field: str, limit: int) -> str | None:
        entries = raw(field)

        if not entries:
            return None

        if len(entries) != 1 or not isinstance(entries[0], str):
            errors[field] = "Enter one text value."
            return None

        value = unicodedata.normalize("NFC", entries[0].strip())

        if len(value) > limit or any(
            unicodedata.category(character) in {"Cc", "Cs"} for character in value
        ):
            errors[field] = f"Use valid text of at most {limit} characters."
            return None

        return value or None

    def choice(field: str, *, required: bool = False) -> str | None:
        value = text(field, 64)

        if value is None:
            if required:
                errors.setdefault(field, "Select an option.")

            return None

        if value not in {code for code, _ in OPTIONS[field]}:
            errors[field] = "Select a valid option."
            return None

        return value

    def choices(field: str, *, required: bool = False) -> list[str]:
        entries = raw(field)
        codes = [code for code, _ in OPTIONS[field]]

        if len(entries) > 2 * len(codes) or any(
            not isinstance(entry, str) or entry not in codes for entry in entries
        ):
            errors[field] = "Select valid options."
            return []

        selected = [code for code in codes if code in entries]

        if required and not selected:
            errors[field] = "Select at least one option."

        if "prefer_not_to_say" in selected and len(selected) > 1:
            errors[field] = "Select either Prefer not to say or the other options."

        return selected

    def other(
        field: str, selected: Sequence[str | None], limit: int = 120
    ) -> str | None:
        if "other" not in selected:
            return None

        value = text(field, limit)

        if value is None:
            errors.setdefault(field, "Enter a value for Other.")

        return value

    school = choice("school_level", required=True)
    studies = choices("studies", required=school in STUDENT_LEVELS)

    if "undeclared" in studies and len(studies) > 1:
        errors["studies"] = "Select either Undeclared or your fields of study."

    gender = choice("gender")
    ethnicity = choices("ethnicity")
    shirt = choice("shirt_size", required=True)
    heard = choices("heard_about", required=True)
    faculty = text("faculty_name", 120) if "faculty" in heard else None

    if "faculty" in heard and not faculty:
        errors.setdefault(
            "faculty_name", "Enter the professor or faculty member's name."
        )

    responses: Responses = {
        "preferred_name": text("preferred_name", 120),
        "school_level": school,
        "school_level_other": other("school_level_other", [school]),
        "studies": studies,
        "study_other": other("study_other", studies, 240),
        "shirt_size": shirt,
        "shirt_size_other": other("shirt_size_other", [shirt], 40),
        "heard_about": heard,
        "heard_about_other": other("heard_about_other", heard, 240),
        "faculty_name": faculty,
        "gender": gender,
        "gender_other": other("gender_other", [gender]),
        "ethnicity": ethnicity,
        "ethnicity_other": other("ethnicity_other", ethnicity),
        "lgbtq": choice("lgbtq"),
        "veteran": choice("veteran"),
    }

    for code, field, limit, prompt in (
        ("social_media", "social_media_source", 120, "Enter the platform."),
        ("discord", "discord_source", 240, "Enter the server or Student Hub."),
    ):
        value = text(field, limit) if code in heard else None

        if code in heard and value is None:
            errors.setdefault(field, prompt)

        responses[field] = value

    if errors:
        raise MembershipValidationError(errors)

    return responses


def _instant(value: object) -> datetime:
    if value is None:
        return datetime.now(UTC)

    if isinstance(value, str):
        value = datetime.fromisoformat(value)

    try:
        if isinstance(value, datetime) and value.utcoffset() is not None:
            return value.astimezone(UTC)

        if type(value) is int or type(value) is float:
            return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError) as error:
        raise ValueError("An absolute date and time is required.") from error

    raise ValueError("An absolute date and time is required.")


def _identity(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("A canonical account UUID is required.")

    try:
        parsed = str(uuid.UUID(value))
    except ValueError as error:
        raise ValueError("A canonical account UUID is required.") from error

    if parsed != value:
        raise ValueError("A canonical account UUID is required.")

    return value


def period(now: object = None) -> RegistrationPeriod:
    zone = ZoneInfo("America/Los_Angeles")
    local = _instant(now).astimezone(zone)
    startyear = local.year if local.month >= 9 else local.year - 1
    start = datetime(startyear, 9, 1, tzinfo=zone)
    end = datetime(startyear + 1, 9, 1, tzinfo=zone)
    return {
        "key": f"{startyear}-{startyear + 1}",
        "startyear": startyear,
        "label": f"{startyear}-{startyear + 1}",
        "starts_at": start.astimezone(UTC).isoformat(),
        "expires_at": end.astimezone(UTC).isoformat(),
    }


class MembershipStore:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float | datetime] = time.time,
    ) -> None:
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

        try:
            if os.fstat(descriptor).st_uid != os.geteuid():
                raise ValueError("Membership storage must belong to this service.")

            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

        with self._db() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS membership_accounts (
                    person_uuid TEXT PRIMARY KEY,
                    suspended INTEGER NOT NULL DEFAULT 0 CHECK(suspended IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS annual_membership (
                    person_uuid TEXT NOT NULL REFERENCES membership_accounts(person_uuid),
                    period TEXT NOT NULL,
                    startyear INTEGER NOT NULL,
                    starts_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    responses_json TEXT NOT NULL,
                    PRIMARY KEY(person_uuid,period),
                    UNIQUE(person_uuid,startyear)
                );
                CREATE TRIGGER IF NOT EXISTS annual_membership_no_update
                BEFORE UPDATE ON annual_membership
                BEGIN SELECT RAISE(ABORT,'Annual registration is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS annual_membership_no_delete
                BEFORE DELETE ON annual_membership
                BEGIN SELECT RAISE(ABORT,'Annual registration is immutable'); END;
            """)

    @contextlib.contextmanager
    def _db(self) -> Generator[sqlite3.Connection]:
        try:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA synchronous = FULL")

            try:
                with db:
                    yield db
            finally:
                db.close()
        except sqlite3.Error as error:
            raise MembershipUnavailable("Membership storage is unavailable.") from error

    @staticmethod
    @overload
    def _record(row: None) -> None: ...

    @staticmethod
    @overload
    def _record(row: sqlite3.Row) -> RegistrationRecord: ...

    @staticmethod
    def _record(row: sqlite3.Row | None) -> RegistrationRecord | None:
        if row is None:
            return None

        try:
            decoded: object = json.loads(_column(row, "responses_json", str))
        except (json.JSONDecodeError, TypeError) as error:
            raise MembershipUnavailable(
                "Membership registration is unreadable."
            ) from error

        if not _mapping(decoded):
            raise MembershipUnavailable("Membership registration is unreadable.")

        responses: Responses = {}

        for key, value in decoded.items():
            if value is None or isinstance(value, str) or is_str_list(value):
                responses[key] = value
            else:
                raise MembershipUnavailable("Membership registration is unreadable.")

        return {
            "person_uuid": _column(row, "person_uuid", str),
            "period": _column(row, "period", str),
            "startyear": _column(row, "startyear", int),
            "starts_at": _column(row, "starts_at", str),
            "expires_at": _column(row, "expires_at", str),
            "submitted_at": _column(row, "submitted_at", str),
            "responses": responses,
        }

    def submit(
        self, person_uuid: object, answers: object, expected_period: str
    ) -> RegistrationRecord:
        person_uuid = _identity(person_uuid)
        instant = _instant(self.clock())
        current_period = period(instant)

        if expected_period != current_period["key"]:
            raise MembershipValidationError(
                {"period": "The registration year changed. Start again."}
            )

        with self._db() as db:
            responses = validate_responses(answers)
            encoded = json.dumps(
                responses, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            db.execute(
                "INSERT INTO membership_accounts(person_uuid) VALUES(?) "
                "ON CONFLICT(person_uuid) DO NOTHING",
                (person_uuid,),
            )
            db.execute(
                "INSERT INTO annual_membership VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(person_uuid,period) DO NOTHING",
                (
                    person_uuid,
                    current_period["key"],
                    current_period["startyear"],
                    current_period["starts_at"],
                    current_period["expires_at"],
                    instant.isoformat(),
                    encoded,
                ),
            )
            row: sqlite3.Row | None = db.execute(
                "SELECT * FROM annual_membership WHERE person_uuid=? AND period=?",
                (person_uuid, current_period["key"]),
            ).fetchone()

            if row is None:
                raise MembershipUnavailable("Membership registration was not saved.")

            if row["responses_json"] != encoded:
                raise AlreadySubmitted(
                    "Registration is already submitted for this year."
                )

            return self._record(row)

    def current(self, person_uuid: object) -> RegistrationRecord | None:
        person_uuid = _identity(person_uuid)
        current_period = period(self.clock())

        with self._db() as db:
            row: sqlite3.Row | None = db.execute(
                "SELECT * FROM annual_membership WHERE person_uuid=? AND period=?",
                (person_uuid, current_period["key"]),
            ).fetchone()
            return self._record(row)

    def current_records(self) -> list[RegistrationRecord]:
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM annual_membership WHERE period=? ORDER BY person_uuid",
                (period(self.clock())["key"],),
            ).fetchall()

        return [self._record(row) for row in rows]

    def first_registrations(self) -> dict[str, str]:
        with self._db() as db:
            rows = db.execute(
                "SELECT person_uuid,submitted_at FROM annual_membership"
            ).fetchall()

        first: dict[str, datetime] = {}

        for row in rows:
            identifier = _identity(_column(row, "person_uuid", str))
            instant = _instant(_column(row, "submitted_at", str))
            first[identifier] = min(first.get(identifier, instant), instant)

        return {
            identifier: instant.isoformat() for identifier, instant in first.items()
        }

    def demographic_metrics(self) -> str:
        records = self.current_records()
        instant = _instant(self.clock())
        current = period(instant)
        lines = [
            "# TYPE identity_registration_count gauge",
            f"identity_registration_count {len(records)}",
            "# TYPE identity_registration_snapshot_timestamp_seconds gauge",
            f"identity_registration_snapshot_timestamp_seconds {instant.timestamp()}",
            "# TYPE identity_registration_period_info gauge",
            f'identity_registration_period_info{{period="{current["key"]}"}} 1',
            "# TYPE identity_registration_demographics gauge",
        ]

        for question in OPTIONS:
            counts = dict.fromkeys((*dict(OPTIONS[question]), "not_provided"), 0)

            for record in records:
                value = record["responses"].get(question)
                answers = value if isinstance(value, list) else [value]

                for answer in set(answers or [None]):
                    counts[answer or "not_provided"] += 1

            lines.extend(
                f'identity_registration_demographics{{question="{question}",answer="{answer}"}} {count}'
                for answer, count in counts.items()
            )

        return "\n".join(lines) + "\n"

    def _metadata(
        self, row: sqlite3.Row, instant: datetime, period: RegistrationPeriod
    ) -> MembershipStatus:
        suspended = bool(_column(row, "suspended", int))
        starts_at = _optional_column(row, "starts_at", str)
        expires_at = _optional_column(row, "expires_at", str)
        registered_period = _optional_column(row, "period", str)
        fresh = registered_period == period["key"] and (
            starts_at is not None
            and expires_at is not None
            and _instant(starts_at) <= instant < _instant(expires_at)
        )

        if suspended:
            status = "paused"
        elif fresh:
            status = "registered"
        else:
            status = "renewal_required"

        return {
            "person_uuid": _column(row, "person_uuid", str),
            "period": registered_period,
            "startyear": _optional_column(row, "startyear", int),
            "starts_at": starts_at,
            "expires_at": expires_at,
            "submitted_at": _optional_column(row, "submitted_at", str),
            "suspended": suspended,
            "active": not suspended and fresh,
            "status": status,
        }

    def subjects(self) -> list[MembershipStatus]:
        instant = _instant(self.clock())
        current_period = period(instant)

        with self._db() as db:
            rows: list[sqlite3.Row] = db.execute(
                """
                SELECT a.person_uuid,a.suspended,
                    r.period,r.startyear,r.starts_at,r.expires_at,r.submitted_at
                FROM membership_accounts a
                LEFT JOIN annual_membership r ON r.person_uuid=a.person_uuid
                    AND r.period=(
                        SELECT period FROM annual_membership
                        WHERE person_uuid=a.person_uuid
                        ORDER BY (period=?) DESC,startyear DESC LIMIT 1
                    )
                ORDER BY a.person_uuid
                """,
                (current_period["key"],),
            ).fetchall()

        return [self._metadata(row, instant, current_period) for row in rows]

    def ensure_account(self, person_uuid: object) -> MembershipStatus:
        person_uuid = _identity(person_uuid)

        with self._db() as db:
            db.execute(
                "INSERT INTO membership_accounts(person_uuid) VALUES(?) "
                "ON CONFLICT(person_uuid) DO NOTHING",
                (person_uuid,),
            )

        return next(
            entry for entry in self.subjects() if entry["person_uuid"] == person_uuid
        )

    def active_people(self) -> frozenset[str]:
        instant = _instant(self.clock())
        current_period = period(instant)

        with self._db() as db:
            rows: list[sqlite3.Row] = db.execute(
                "SELECT r.person_uuid,r.starts_at,r.expires_at "
                "FROM annual_membership r JOIN membership_accounts a "
                "ON a.person_uuid=r.person_uuid WHERE r.period=? AND a.suspended=0",
                (current_period["key"],),
            ).fetchall()

        return frozenset(
            _identity(_column(row, "person_uuid", str))
            for row in rows
            if _instant(_column(row, "starts_at", str))
            <= instant
            < _instant(_column(row, "expires_at", str))
        )

    def active(self, person_uuid: object) -> bool:
        person_uuid = _identity(person_uuid)
        instant = _instant(self.clock())
        current_period = period(instant)

        with self._db() as db:
            account: sqlite3.Row | None = db.execute(
                "SELECT suspended FROM membership_accounts WHERE person_uuid=?",
                (person_uuid,),
            ).fetchone()

            if account is None or account["suspended"]:
                return False

            row: sqlite3.Row | None = db.execute(
                "SELECT starts_at,expires_at FROM annual_membership WHERE person_uuid=? AND period=?",
                (person_uuid, current_period["key"]),
            ).fetchone()

        fresh = row is not None and _instant(row["starts_at"]) <= instant < _instant(
            row["expires_at"]
        )
        return fresh

    def suspended(self, person_uuid: object) -> bool:
        with self._db() as db:
            row: sqlite3.Row | None = db.execute(
                "SELECT suspended FROM membership_accounts WHERE person_uuid=?",
                (_identity(person_uuid),),
            ).fetchone()

        return row is not None and bool(row["suspended"])

    def suspend(self, person_uuid: object, suspended: object) -> MembershipStatus:
        person_uuid = _identity(person_uuid)

        if type(suspended) is not bool:
            raise ValueError("Membership suspension must be true or false.")

        with self._db() as db:
            db.execute(
                "INSERT INTO membership_accounts(person_uuid,suspended) VALUES(?,?) "
                "ON CONFLICT(person_uuid) DO UPDATE SET suspended=excluded.suspended",
                (person_uuid, int(suspended)),
            )

        return next(
            entry for entry in self.subjects() if entry["person_uuid"] == person_uuid
        )
