"""Certificate authority for remote sensor mTLS authentication."""
from __future__ import annotations

import ipaddress
import json
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CANotInitialized(Exception):
    pass


def _generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _write_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _load_registry(ca_dir: Path) -> list[dict]:
    path = ca_dir / "certs.json"
    if path.exists():
        return json.loads(path.read_text())
    return []


def _save_registry(ca_dir: Path, registry: list[dict]) -> None:
    (ca_dir / "certs.json").write_text(json.dumps(registry, indent=2))


def init_ca(ca_dir: Path) -> None:
    if (ca_dir / "ca.crt").exists():
        raise FileExistsError(f"CA already initialized in {ca_dir}")
    ca_dir.mkdir(parents=True, exist_ok=True)

    key = _generate_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leetha-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_key(key, ca_dir / "ca.key")
    _write_cert(cert, ca_dir / "ca.crt")
    _save_registry(ca_dir, [])


def load_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    if not (ca_dir / "ca.crt").exists():
        raise CANotInitialized("Run `leetha remote ca init` first")
    return _load_cert(ca_dir / "ca.crt"), _load_key(ca_dir / "ca.key")


def issue_cert(
    ca_dir: Path, name: str, out_dir: Path
) -> tuple[Path, Path]:
    ca_cert, ca_key = load_ca(ca_dir)
    registry = _load_registry(ca_dir)

    for entry in registry:
        if entry["name"] == name and not entry["revoked"]:
            raise ValueError(f"Certificate '{name}' already exists")

    key = _generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / f"{name}.crt"
    key_path = out_dir / f"{name}.key"
    _write_cert(cert, cert_path)
    _write_key(key, key_path)

    registry.append(
        {
            "name": name,
            "serial": cert.serial_number,
            "issued": now.isoformat(),
            "revoked": False,
        }
    )
    _save_registry(ca_dir, registry)
    return cert_path, key_path


def revoke_cert(ca_dir: Path, name: str) -> None:
    registry = _load_registry(ca_dir)
    found = False
    for entry in registry:
        if entry["name"] == name and not entry["revoked"]:
            entry["revoked"] = True
            found = True
    if not found:
        raise ValueError(f"Certificate '{name}' not found")
    _save_registry(ca_dir, registry)


def ensure_server_cert(ca_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path) for the listener's TLS server cert.

    Generates a new one signed by the CA if it doesn't exist yet.
    """
    cert_path = ca_dir / "server.crt"
    key_path = ca_dir / "server.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    ca_cert, ca_key = load_ca(ca_dir)
    key = _generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leetha-server")])
    now = datetime.datetime.now(datetime.timezone.utc)

    # Include all local IPs in SAN so sensors can connect to any address
    san_entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family.name == "AF_INET" and addr.address != "127.0.0.1":
                    san_entries.append(
                        x509.IPAddress(ipaddress.IPv4Address(addr.address))
                    )
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(key, key_path)
    _write_cert(cert, cert_path)
    return cert_path, key_path


def list_certs(ca_dir: Path) -> list[dict]:
    return _load_registry(ca_dir)
