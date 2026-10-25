from collections.abc import Mapping
from typing import Protocol

class Response(Protocol):
    @property
    def status(self) -> int: ...
    @property
    def data(self) -> bytes: ...
    @property
    def headers(self) -> Mapping[str, str]: ...
