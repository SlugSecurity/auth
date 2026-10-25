import base64
import hashlib
import hmac
import json
import os
import re
import stat
import time
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlencode, urlsplit

import requests
from google.auth import exceptions as google_exceptions
from google.auth.transport import Response as GoogleResponse
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from contracts import is_object_dict, is_str_list

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUER = "https://accounts.google.com"
SCOPES = "openid email profile"
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9_-]+\.apps\.googleusercontent\.com\Z")


class GoogleClientConfig(TypedDict):
    client_id: str
    client_secret: str
    redirect_uris: list[str]


class GoogleIdentity(TypedDict):
    issuer: str
    subject: str
    email: str
    display_name: str
    is_ucsc: bool
    email_authority: bool


class GoogleSetupError(Exception):
    pass


class GoogleVerificationError(Exception):
    pass


def load_config(path: Path) -> GoogleClientConfig:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise GoogleSetupError(
            "Google verification needs a private Google OAuth client configuration."
        ) from None

    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        user_private = metadata.st_uid == os.geteuid() and mode == 0o600
        root_shared = (
            metadata.st_uid == 0 and metadata.st_gid == os.getegid() and mode == 0o640
        )

        if not stat.S_ISREG(metadata.st_mode) or not (user_private or root_shared):
            raise GoogleSetupError(
                "Google OAuth configuration must be a regular file with mode 0600 "
                "owned by this user, or mode 0640 owned by root and this process group."
            )

        try:
            with os.fdopen(descriptor, encoding="utf-8", closefd=False) as source:
                contents = source.read(16_385)

                if len(contents) > 16_384:
                    raise ValueError

                document: object = json.loads(contents)
        except ValueError, UnicodeError, OSError:
            raise GoogleSetupError(
                "Google OAuth configuration is not valid JSON."
            ) from None
    except OSError:
        raise GoogleSetupError(
            "Google verification needs a private Google OAuth client configuration."
        ) from None
    finally:
        os.close(descriptor)

    if not is_object_dict(document):
        raise GoogleSetupError(
            "Google OAuth configuration must describe a Web application client."
        )

    config = document.get("web")

    if not is_object_dict(config):
        raise GoogleSetupError(
            "Google OAuth configuration must describe a Web application client."
        )

    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    if (
        not isinstance(client_id, str)
        or not _CLIENT_ID.fullmatch(client_id)
        or not isinstance(client_secret, str)
        or not 8 <= len(client_secret) <= 4096
        or any(character.isspace() for character in client_secret)
    ):
        raise GoogleSetupError(
            "Google OAuth configuration must contain a valid client_id and "
            "client_secret."
        )

    redirects = config.get("redirect_uris")

    if not is_str_list(redirects) or not redirects or not all(redirects):
        raise GoogleSetupError(
            "Google OAuth configuration must list its authorized callback URLs."
        )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": redirects,
    }


def _check_flow_parameters(
    config: GoogleClientConfig, redirect_uri: object, verifier: object
) -> tuple[str, str]:
    if not isinstance(verifier, str) or not _VERIFIER.fullmatch(verifier):
        raise GoogleSetupError("Google enrollment requires a valid PKCE verifier.")

    try:
        if not isinstance(redirect_uri, str):
            raise ValueError

        redirect = urlsplit(redirect_uri)
        secure = redirect.scheme == "https"
        local_http = redirect.scheme == "http" and redirect.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }

        if (
            not redirect.hostname
            or not (secure or local_http)
            or redirect.username is not None
            or redirect.password is not None
            or redirect.fragment
            or redirect.query
        ):
            raise ValueError

        _ = redirect.port
    except ValueError, TypeError, AttributeError:
        raise GoogleSetupError(
            "Google enrollment requires a fixed HTTPS or localhost callback."
        ) from None

    if redirect_uri not in config["redirect_uris"]:
        raise GoogleSetupError(
            "The Google OAuth client must authorize this enrollment callback URL."
        )

    return redirect_uri, verifier


def authorization_url(
    config: GoogleClientConfig,
    redirect_uri: object,
    state: object,
    nonce: object,
    verifier: object,
) -> str:
    redirect_uri, verifier = _check_flow_parameters(config, redirect_uri, verifier)

    if (
        not isinstance(state, str)
        or not 16 <= len(state) <= 512
        or not isinstance(nonce, str)
        or not 16 <= len(nonce) <= 512
    ):
        raise GoogleSetupError(
            "Google enrollment requires fresh state and nonce values."
        )

    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )

    parameters = {
        "client_id": config["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
        "access_type": "online",
        "hd": "ucsc.edu",
    }

    return AUTHORIZATION_ENDPOINT + "?" + urlencode(parameters)


def validate_claims(
    claims: object, nonce: object
) -> GoogleIdentity:  # callers must verify signature and audience
    if not is_object_dict(claims) or claims.get("iss") not in (
        GOOGLE_ISSUER,
        "accounts.google.com",
    ):
        raise GoogleVerificationError("Google returned an invalid identity issuer.")

    received_nonce = claims.get("nonce")

    if (
        not isinstance(nonce, str)
        or not nonce
        or not nonce.isascii()
        or not isinstance(received_nonce, str)
        or not received_nonce.isascii()
        or not hmac.compare_digest(
            received_nonce.encode("utf-8"), nonce.encode("utf-8")
        )
    ):
        raise GoogleVerificationError(
            "Google verification did not match this enrollment session. Please start "
            "again."
        )

    subject = claims.get("sub")

    if (
        not isinstance(subject, str)
        or not 1 <= len(subject) <= 255
        or not subject.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in subject)
    ):
        raise GoogleVerificationError(
            "Google did not return a valid account identifier."
        )

    if claims.get("email_verified") is not True:
        raise GoogleVerificationError(
            "Google did not verify this email address. Please use a verified Google "
            "account."
        )

    email = claims.get("email")

    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 254
        or not email.isascii()
        or email.count("@") != 1
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in email
        )
    ):
        raise GoogleVerificationError("Google did not return a valid email address.")

    local_part, domain = email.split("@")
    domain = domain.lower()

    if not local_part or not domain or domain.startswith(".") or domain.endswith("."):
        raise GoogleVerificationError("Google did not return a valid email address.")

    hosted_domain = claims.get("hd")

    if hosted_domain is not None and (
        not isinstance(hosted_domain, str)
        or not hosted_domain
        or not hosted_domain.isascii()
        or any(character.isspace() for character in hosted_domain)
    ):
        raise GoogleVerificationError("Google did not return a valid hosted domain.")

    name = claims.get("name")

    if not isinstance(name, str) or not name.strip():
        raise GoogleVerificationError(
            "Google did not provide your name. Enrollment requires the name from your"
            " Google account."
        )

    name = name.strip()

    if len(name) > 256 or any(
        unicodedata.category(character) in {"Cc", "Cs"} for character in name
    ):
        raise GoogleVerificationError("Google did not return a valid account name.")

    return {
        "issuer": GOOGLE_ISSUER,
        "subject": subject,
        "email": email,
        "display_name": name,
        "is_ucsc": hosted_domain == "ucsc.edu" and domain == "ucsc.edu",
        "email_authority": domain == "gmail.com" or hosted_domain is not None,
    }


def exchange_and_verify(
    config: GoogleClientConfig,
    code: object,
    redirect_uri: object,
    verifier: object,
    nonce: object,
) -> GoogleIdentity:
    redirect_uri, verifier = _check_flow_parameters(config, redirect_uri, verifier)

    if not isinstance(code, str) or not code or len(code) > 4096:
        raise GoogleVerificationError(
            "Google did not return an authorization code. Please start again."
        )

    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(
                TOKEN_ENDPOINT,
                data={
                    "client_id": config["client_id"],
                    "client_secret": config["client_secret"],
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                    "code_verifier": verifier,
                },
                timeout=(5, 15),
                allow_redirects=False,
            )

            if response.status_code != 200:
                raise GoogleVerificationError(
                    "Google could not complete verification. Please start again."
                )

            payload: object = response.json()
            token = payload.get("id_token") if is_object_dict(payload) else None

            if not isinstance(token, str) or not token or len(token) > 65_536:
                raise GoogleVerificationError(
                    "Google did not return a valid identity token. Please start again."
                )

            transport = Request(session=session)

            def bounded_request(
                url: str,
                method: str = "GET",
                body: bytes | str | None = None,
                headers: Mapping[str, str] | None = None,
                timeout: float = 120,
                **kwargs: object,
            ) -> GoogleResponse:
                kwargs["allow_redirects"] = False
                return transport(
                    url,
                    method=method,
                    body=body,
                    headers=headers,
                    timeout=15,
                    **kwargs,
                )

            claims = id_token.verify_oauth2_token(
                token, bounded_request, audience=config["client_id"]
            )
            expires = claims.get("exp") if is_object_dict(claims) else None

            if (
                type(expires) is not int
                or type(claims.get("iat")) is not int
                or expires <= time.time()
            ):
                raise GoogleVerificationError(
                    "Google returned an invalid identity-token lifetime. Please start"
                    " again."
                )

            if "azp" in claims and claims["azp"] != config["client_id"]:
                raise GoogleVerificationError(
                    "Google returned an invalid authorized identity-token presenter. "
                    "Please start again."
                )
    except (
        google_exceptions.GoogleAuthError,
        requests.RequestException,
        ValueError,
        TypeError,
        KeyError,
    ):
        raise GoogleVerificationError(
            "Google identity verification failed. Please start again."
        ) from None

    return validate_claims(claims, nonce)
