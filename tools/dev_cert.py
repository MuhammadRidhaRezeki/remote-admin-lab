"""Development self-signed certificate generator.

Production uses Let's Encrypt certificates issued for the relay domain; this
helper only creates a trusted local certificate for the lab network.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_dev_certificate(
    cert_path: Path,
    key_path: Path,
    server_name: str = "remote-admin-lab.local",
    days: int = 365,
    extra_dns: Iterable[str] = (),
    extra_ips: Iterable[str] = (),
) -> None:
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Remote Admin Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, server_name),
        ]
    )

    san_names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    try:
        server_ip = ipaddress.ip_address(server_name)
    except ValueError:
        san_names.append(x509.DNSName(server_name))
    else:
        san_names.append(x509.IPAddress(server_ip))

    for name in extra_dns:
        candidate = x509.DNSName(name)
        if candidate not in san_names:
            san_names.append(candidate)
    for value in ("127.0.0.1", *extra_ips):
        try:
            candidate = x509.IPAddress(ipaddress.ip_address(value))
        except ValueError:
            continue
        if candidate not in san_names:
            san_names.append(candidate)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=7))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
