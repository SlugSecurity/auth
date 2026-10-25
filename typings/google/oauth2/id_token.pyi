from typing import Protocol

from google.auth.transport import Response

class _CertificateRequest(Protocol):
    def __call__(self, url: str, /, *, method: str) -> Response: ...

def verify_oauth2_token(
    id_token: str | bytes,
    request: _CertificateRequest,
    audience: str | list[str] | None = None,
    clock_skew_in_seconds: int = 0,
) -> dict[str, object]: ...
