import hashlib
import json
from html import escape
from pathlib import Path

AUTH_TITLE = "Slug Security - Authentication"
TAGLINE = "Cyber @ UC Santa Cruz"
BACKGROUND = Path(__file__).with_name("branding") / "background.webp"
UI = Path(__file__).with_name("enrollment-ui")
OVERLAY = BACKGROUND.parent / "kanidm-1.11.2"


def native_script(portal_url: str, identity_domain: str) -> bytes:
    notice = (UI / "registration-notice.html").read_text()
    notice = notice.replace(
        "{{ registration_url }}", escape(portal_url + "/membership", quote=True)
    )
    overlay = (OVERLAY / "enrollment-notice.js").read_text()
    overlay = overlay.replace("__IDENTITY_PORTAL_URL__", json.dumps(portal_url))
    overlay = overlay.replace("__IDENTITY_DOMAIN__", json.dumps(identity_domain))
    overlay = overlay.replace("__IDENTITY_REGISTRATION_NOTICE__", json.dumps(notice))
    return (OVERLAY / "upstream-style.js").read_bytes() + b"\n" + overlay.encode()


def branding_hash() -> str:
    sources = (
        OVERLAY / "upstream-style.js",
        OVERLAY / "enrollment-notice.js",
        UI / "registration-notice.html",
        Path(__file__),
        UI / "style.css",
        OVERLAY / "page-load.patch",
    )
    content = b"".join(path.read_bytes() for path in sources)
    images = (
        BACKGROUND,
        BACKGROUND.parent / "slugsec-logo.png",
        OVERLAY / "favicon.png",
        OVERLAY / "apple-touch-icon.png",
        OVERLAY / "logo-180.png",
        OVERLAY / "logo-192.png",
        OVERLAY / "logo-256.png",
        OVERLAY / "logo-512.png",
        OVERLAY / "logo-square.svg",
        OVERLAY / "logo.svg",
        OVERLAY / "kani-waving.svg",
    )

    for path in images:
        content += hashlib.sha256(path.read_bytes()).hexdigest().encode()

    return hashlib.sha256(content).hexdigest()


if __name__ == "__main__":
    import sys

    sys.stdout.buffer.write(native_script(sys.argv[1], sys.argv[2]))
