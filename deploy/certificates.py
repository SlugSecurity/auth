import os
import secrets
import shutil
import subprocess
from pathlib import Path


def openssl(*arguments: str | Path | int) -> bytes:
    result = subprocess.run(
        ["openssl", *map(str, arguments)], capture_output=True, check=False
    )

    if result.returncode:
        raise RuntimeError("Backend certificate operation failed")

    return result.stdout


def sync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_ca(pki: str | Path, key: str | Path) -> Path:
    pki, key = Path(pki), Path(key)
    certificate = pki / "ca.pem"

    if certificate.exists() or key.exists():
        if not certificate.is_file() or not key.is_file():
            raise RuntimeError(
                "Restore the paired backend CA certificate and private key"
            )

        openssl("x509", "-in", certificate, "-checkend", 365 * 86400, "-noout")
        certificate_public = openssl("x509", "-in", certificate, "-pubkey", "-noout")
        key_public = openssl("pkey", "-in", key, "-pubout")

        if certificate_public != key_public:
            raise RuntimeError("Backend CA certificate and private key do not match")

        return certificate

    pki.mkdir(mode=0o755, parents=True, exist_ok=True)
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    openssl(
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        key,
    )
    key.chmod(0o600)
    openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        key,
        "-sha256",
        "-days",
        "3650",
        "-subj",
        "/CN=Identity backend CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-out",
        certificate,
    )
    certificate.chmod(0o644)
    return certificate


def issue(
    pki: str | Path,
    ca_key: str | Path,
    service: str,
    hostname: str,
    gid: int | None = None,
    force: bool = False,
) -> bool:
    if (service, hostname) not in (
        ("kanidm", "auth.slugsec.club"),
        ("portal", "my.slugsec.club"),
    ):
        raise RuntimeError(
            "Backend certificate identity is not in the deployment manifest"
        )

    names = (hostname, "portal") if service == "portal" else (hostname,)
    root = Path(pki) / service
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    root.chmod(0o755)
    current = root / "current"

    if current.is_symlink() and not force:
        certificate = current / "chain.pem"
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(certificate),
                "-checkend",
                str(30 * 86400),
                "-noout",
            ],
            capture_output=True,
            check=False,
        )

        if result.returncode == 0:
            for name in names:
                openssl(
                    "verify",
                    "-trusted",
                    Path(pki) / "ca.pem",
                    "-verify_hostname",
                    name,
                    "-purpose",
                    "sslserver",
                    certificate,
                )

            if openssl("x509", "-in", certificate, "-pubkey", "-noout") != openssl(
                "pkey", "-in", current / "key.pem", "-pubout"
            ):
                raise RuntimeError(
                    "Backend leaf certificate and private key do not match"
                )

            return False
    elif current.exists() and not current.is_symlink():
        raise RuntimeError(
            "Backend TLS current generation must be an operator-owned symlink"
        )

    generation = root / ("generation-" + secrets.token_hex(12))
    generation.mkdir(mode=0o755)
    installed = False

    try:
        generation.chmod(0o755)
        key = generation / "key.pem"
        openssl(
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            key,
        )
        key.chmod(0o640)

        if gid is not None:
            os.chown(key, 0, gid)

        request = generation / "request.pem"
        openssl("req", "-new", "-key", key, "-subj", "/CN=" + hostname, "-out", request)
        extensions = generation / "extensions.cnf"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName="
            + ",".join("DNS:" + name for name in names)
            + "\n"
        )
        certificate = generation / "chain.pem"
        openssl(
            "x509",
            "-req",
            "-in",
            request,
            "-CA",
            Path(pki) / "ca.pem",
            "-CAkey",
            ca_key,
            "-set_serial",
            secrets.randbits(159) + 1,
            "-days",
            "90",
            "-sha256",
            "-extfile",
            extensions,
            "-out",
            certificate,
        )
        certificate.chmod(0o644)

        for name in names:
            openssl(
                "verify",
                "-trusted",
                Path(pki) / "ca.pem",
                "-verify_hostname",
                name,
                "-purpose",
                "sslserver",
                certificate,
            )

        request.unlink()
        extensions.unlink()

        for path in (key, certificate, generation):
            sync_path(path)

        temporary = root / ("current-" + secrets.token_hex(8))
        temporary.symlink_to(generation.name)
        temporary.replace(current)
        installed = True
        sync_path(root)
        return True
    finally:
        if not installed:
            shutil.rmtree(generation)
