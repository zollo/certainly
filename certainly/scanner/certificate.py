"""X.509 certificate parsing and validation helpers."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import CertificateInfo

# Signature hash algorithms that are considered weak / broken.
WEAK_SIG_HASHES = {"md5", "sha1"}


def _name_to_str(name: x509.Name) -> str:
    """Render an X.509 name as a compact human-readable string."""
    parts = []
    for attr in name:
        try:
            short = attr.oid._name  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - defensive
            short = attr.oid.dotted_string
        parts.append(f"{short}={attr.value}")
    return ", ".join(parts)


def _common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if values:
        return str(values[0].value)
    return _name_to_str(name)


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _key_details(cert: x509.Certificate) -> tuple[str, int | None]:
    """Return (key_type, key_bits)."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.curve.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pub).__name__, None


def _hostname_matches(hostname: str, cert_der: bytes) -> bool:
    """Validate that ``hostname`` matches the certificate's names.

    Implements RFC 6125-style matching, including single-label wildcards.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    names = set(_extract_sans(cert))
    cn = None
    cn_values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_values:
        cn = str(cn_values[0].value)
        names.add(cn)

    host = hostname.lower().rstrip(".")
    for name in names:
        if _match_single(host, name.lower().rstrip(".")):
            return True
    return False


def _match_single(host: str, pattern: str) -> bool:
    if pattern == host:
        return True
    if pattern.startswith("*."):
        # Wildcard matches exactly one left-most label.
        suffix = pattern[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return bool(left) and "." not in left
    return False


def _fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def parse_certificate(cert_der: bytes, hostname: str) -> CertificateInfo:
    """Parse a DER-encoded certificate into a :class:`CertificateInfo`."""
    cert = x509.load_der_x509_certificate(cert_der)

    not_before = _as_utc(cert)
    not_after = _as_utc_after(cert)
    now = datetime.now(timezone.utc)

    key_type, key_bits = _key_details(cert)
    sig_hash = (cert.signature_hash_algorithm.name.lower()
                if cert.signature_hash_algorithm else "unknown")

    is_self_signed = cert.issuer == cert.subject

    return CertificateInfo(
        subject=_common_name(cert.subject),
        subject_alt_names=_extract_sans(cert),
        issuer=_common_name(cert.issuer),
        serial_number=format(cert.serial_number, "X"),
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=(not_after - now).days,
        is_expired=now > not_after,
        is_not_yet_valid=now < not_before,
        is_self_signed=is_self_signed,
        signature_algorithm=cert.signature_algorithm_oid._name,  # type: ignore[attr-defined]
        key_type=key_type,
        key_bits=key_bits,
        sha256_fingerprint=_fingerprint(cert),
        version=cert.version.name,
        hostname_matches=_hostname_matches(hostname, cert_der),
        weak_signature=sig_hash in WEAK_SIG_HASHES,
    )


def _as_utc(cert: x509.Certificate) -> datetime:
    # ``not_valid_before_utc`` is preferred on newer cryptography versions.
    value = getattr(cert, "not_valid_before_utc", None)
    if value is None:  # pragma: no cover - older cryptography
        value = cert.not_valid_before.replace(tzinfo=timezone.utc)
    return value


def _as_utc_after(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:  # pragma: no cover - older cryptography
        value = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return value
