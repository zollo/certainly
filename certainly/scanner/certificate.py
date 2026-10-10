"""X.509 certificate parsing and validation helpers."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from ..models import CertificateInfo

# Signature hash algorithms that are considered weak / broken.
WEAK_SIG_HASHES = {"md5", "sha1"}

# Known post-quantum signature/key algorithm OIDs (NIST FIPS 203/204/205 and
# related). Classical certificates never carry these; their presence means the
# certificate is quantum-resistant.
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17",  # ML-DSA-44
    "2.16.840.1.101.3.4.3.18",  # ML-DSA-65
    "2.16.840.1.101.3.4.3.19",  # ML-DSA-87
    "2.16.840.1.101.3.4.3.20",  # SLH-DSA-SHA2-128s
    "2.16.840.1.101.3.4.3.21",  # SLH-DSA-SHA2-128f
    "1.3.6.1.4.1.2.267.7.4.4",  # Dilithium2 (pre-standardisation)
    "1.3.9999.3.6",             # Falcon-512 (pre-standardisation)
    "1.3.9999.6.4.16",          # SPHINCS+ (pre-standardisation)
}


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


def _ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP and isinstance(
            desc.access_location, x509.UniformResourceIdentifier
        ):
            urls.append(desc.access_location.value)
    return urls


def _ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(
            desc.access_location, x509.UniformResourceIdentifier
        ):
            urls.append(desc.access_location.value)
    return urls


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        dps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for dp in dps:
        for name in dp.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _must_staple(cert: x509.Certificate) -> bool:
    try:
        feature = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
    except x509.ExtensionNotFound:
        return False
    return x509.TLSFeatureType.status_request in feature


def _sct_count(cert: x509.Certificate) -> int:
    try:
        scts = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        ).value
    except x509.ExtensionNotFound:
        return 0
    try:
        return len(list(scts))
    except TypeError:  # pragma: no cover - defensive
        return 0


def _is_post_quantum(cert: x509.Certificate) -> bool:
    """Return True only for explicitly recognised post-quantum algorithms.

    An unrecognised key class is NOT treated as post-quantum: classical
    key-agreement types (X25519, X448, DH) are also "unknown" to the signature
    classifier, so guessing from absence would misreport them.
    """
    oids = set()
    try:
        oids.add(cert.signature_algorithm_oid.dotted_string)
    except Exception:  # pragma: no cover - defensive
        pass
    try:
        spki_oid = cert.public_key_algorithm_oid.dotted_string  # cryptography >= 43
        oids.add(spki_oid)
    except Exception:  # pragma: no cover - older cryptography / unusual keys
        pass
    return bool(oids & PQC_OIDS)


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
        ocsp_urls=_ocsp_urls(cert),
        crl_urls=_crl_urls(cert),
        ca_issuer_urls=_ca_issuer_urls(cert),
        must_staple=_must_staple(cert),
        sct_count=_sct_count(cert),
        is_post_quantum=_is_post_quantum(cert),
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
