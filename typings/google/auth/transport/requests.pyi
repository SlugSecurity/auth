from collections.abc import Mapping

from requests import Session

from . import Response

class Request:
    def __init__(self, session: Session | None = None) -> None: ...
    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 120,
        **kwargs: object,
    ) -> Response: ...
