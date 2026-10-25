import math
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from subprocess import CompletedProcess
from typing import Protocol, TypeAlias, TypedDict, TypeGuard, runtime_checkable
from urllib.request import OpenerDirector

JSONValue: TypeAlias = (
    bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
)
JSONObject: TypeAlias = dict[str, JSONValue]
NativeAttrs: TypeAlias = dict[str, list[str]]
Attrs: TypeAlias = NativeAttrs


class JWKSet(TypedDict):
    keys: list[dict[str, str | list[str]]]


class OIDCConfig(TypedDict):
    client_id: str
    client_secret: str
    callback_url: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    jwks: JWKSet


class NativeAPI(Protocol):
    def __call__(
        self, path: str, method: str = "GET", body: object = None
    ) -> object: ...


class NativeReadAPI(Protocol):
    def __call__(
        self, path: str, token: str, method: str = "GET", body: object = None
    ) -> object: ...


class Page(Protocol):
    def __call__(self, page: str, **context: object) -> str: ...


CsrfCheck: TypeAlias = Callable[[], None]
RotateSession: TypeAlias = Callable[[], None]


def is_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def is_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return is_dict(value) and all(isinstance(key, str) for key in value)


def is_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


def is_sequence(value: object) -> TypeGuard[Sequence[object]]:
    return isinstance(value, (list, tuple))


def is_str_list(value: object) -> TypeGuard[list[str]]:
    return is_list(value) and all(isinstance(item, str) for item in value)


def is_json_object(value: object) -> TypeGuard[JSONObject]:
    return is_object_dict(value) and all(is_json_value(item) for item in value.values())


def is_json_array(value: object) -> TypeGuard[list[JSONValue]]:
    return is_list(value) and all(is_json_value(item) for item in value)


def is_json_value(value: object) -> TypeGuard[JSONValue]:
    return (
        value is None
        or isinstance(value, (str, bool, int))
        or (isinstance(value, float) and math.isfinite(value))
        or is_json_array(value)
        or is_json_object(value)
    )


def json_object(value: object) -> JSONObject:
    if not is_json_object(value):
        raise ValueError("Expected a JSON object")

    return value


def json_array(value: object) -> list[JSONValue]:
    if not is_json_array(value):
        raise ValueError("Expected a JSON array")

    return value


def json_string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a string")

    return value


def json_number(value: object) -> int | float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        raise ValueError("Expected a number")

    return value


def is_native_attrs(value: object) -> TypeGuard[NativeAttrs]:
    return is_object_dict(value) and all(is_str_list(items) for items in value.values())


def native_attrs(value: object) -> NativeAttrs:
    if not is_native_attrs(value):
        raise ValueError("Native attributes must contain string arrays")

    return value


def jwk_set(value: object) -> JWKSet:
    if not is_object_dict(value):
        raise ValueError("Expected a signing key set")

    items = value.get("keys")

    if not is_list(items):
        raise ValueError("Expected a signing key array")

    keys: list[dict[str, str | list[str]]] = []

    for item in items:
        if not is_object_dict(item):
            raise ValueError("Expected a signing key object")

        key: dict[str, str | list[str]] = {}

        for name, component in item.items():
            if not isinstance(component, str) and not is_str_list(component):
                raise ValueError("Invalid signing key component")

            key[name] = component

        keys.append(key)

    return {"keys": keys}


@runtime_checkable
class NativeRuntime(Protocol):
    ROOT: Path
    STATE: Path
    DATA: Path
    CREDENTIALS: Path
    DOMAIN: str
    URL: str
    PORTAL_URL: str

    def command(
        self,
        *args: str,
        check: bool = True,
        env: Mapping[str, str] | None = None,
        timeout: float = 120,
    ) -> CompletedProcess[str]: ...

    def cli(
        self, *args: str, name: str = "idm_admin", check: bool = True
    ) -> CompletedProcess[str]: ...
    def cli_env(self, name: str) -> dict[str, str]: ...
    def load_credentials(self) -> JSONObject: ...
    def update_credentials(
        self, update: Callable[[JSONObject], None]
    ) -> JSONObject: ...
    def entry_exists(self, kind: str, name: str) -> bool: ...
    def opener(self) -> OpenerDirector: ...
    def api(
        self, path: str, token: str, method: str = "GET", body: object = None
    ) -> object: ...
    def ready(self) -> None: ...
    def require_native_credential_compare(self) -> None: ...


@runtime_checkable
class ProductionRuntime(NativeRuntime, Protocol):
    POSIX_STATUS: Path
    BACKUP_STATUS: Path
    ISOLATED_POSIX: bool
    PUBLIC_READINESS: bool

    def operator_token(self, name: str = "idm_admin") -> str: ...
    def prepare_private_directory(self, path: Path) -> None: ...
    def protect_private_file(self, descriptor: int, path: Path) -> None: ...
