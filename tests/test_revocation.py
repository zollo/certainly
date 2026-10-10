"""Tests for validated, SSRF-hardened OCSP revocation checking (no network).

A synthetic issuer + leaf + signed OCSP responses are generated in-process so
the full validation path (CertID match, freshness, signature, delegated
responder) can be exercised deterministically.
"""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certainly.scanner import revocation
from certainly.scanner.revocation import (
    _is_public_host,
    _safe_open,
    check_ocsp,
    validate_response,
)

_DER = serialization.Encoding.DER


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer_name, pub, signer_key, *, ca=False, ocsp_signing=False):
    now = datetime.now(timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer_name).public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if ocsp_signing:
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
    return b.sign(signer_key, hashes.SHA256())


# --- fixtures: a tiny CA hierarchy -----------------------------------------
_issuer_key = _key()
_issuer = _cert(_name("Test Issuer CA"), _name("Test Issuer CA"),
                _issuer_key.public_key(), _issuer_key, ca=True)
_leaf_key = _key()
_leaf = _cert(_name("example.com"), _issuer.subject, _leaf_key.public_key(), _issuer_key)

_ISSUER_DER = _issuer.public_bytes(_DER)
_LEAF_DER = _leaf.public_bytes(_DER)


def _ocsp_response(status, *, signer_key=_issuer_key, responder_cert=_issuer,
                   embed=None, this_update=None, next_update=None, leaf=_leaf):
    now = datetime.now(timezone.utc)
    this_update = this_update or (now - timedelta(hours=1))
    next_update = next_update or (now + timedelta(days=1))
    kwargs = dict(
        cert=leaf, issuer=_issuer, algorithm=hashes.SHA256(),
        cert_status=status, this_update=this_update, next_update=next_update,
        revocation_time=(now - timedelta(hours=2)) if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=None,
    )
    builder = ocsp.OCSPResponseBuilder().add_response(**kwargs).responder_id(
        ocsp.OCSPResponderEncoding.NAME, responder_cert
    )
    if embed:
        builder = builder.certificates(embed)
    resp = builder.sign(signer_key, hashes.SHA256())
    return resp.public_bytes(_DER)


def test_valid_good_response():
    raw = _ocsp_response(ocsp.OCSPCertStatus.GOOD)
    assert validate_response(raw, _leaf, _issuer) == "good"


def test_valid_revoked_response():
    raw = _ocsp_response(ocsp.OCSPCertStatus.REVOKED)
    assert validate_response(raw, _leaf, _issuer) == "revoked"


def test_wrong_signer_is_unavailable():
    # Signed by an unrelated (self-signed) responder not embedded in the
    # response, so validation falls back to the issuer key and the signature
    # (made with the rogue key) fails to verify.
    rogue = _key()
    rogue_cert = _cert(_name("Rogue"), _name("Rogue"), rogue.public_key(), rogue, ca=True)
    raw = _ocsp_response(ocsp.OCSPCertStatus.GOOD, signer_key=rogue,
                         responder_cert=rogue_cert)
    assert validate_response(raw, _leaf, _issuer) == "unavailable"


def test_delegated_responder_is_accepted():
    # A responder cert issued by the CA with the OCSP-signing EKU may sign.
    resp_key = _key()
    responder = _cert(_name("Delegated OCSP Responder"), _issuer.subject,
                      resp_key.public_key(), _issuer_key, ocsp_signing=True)
    raw = _ocsp_response(ocsp.OCSPCertStatus.GOOD, signer_key=resp_key,
                         responder_cert=responder, embed=[responder])
    assert validate_response(raw, _leaf, _issuer) == "good"


def test_delegated_without_ocsp_eku_is_rejected():
    resp_key = _key()
    responder = _cert(_name("Not A Responder"), _issuer.subject,
                      resp_key.public_key(), _issuer_key, ocsp_signing=False)
    raw = _ocsp_response(ocsp.OCSPCertStatus.GOOD, signer_key=resp_key,
                         responder_cert=responder, embed=[responder])
    assert validate_response(raw, _leaf, _issuer) == "unavailable"


def test_certid_mismatch_is_unavailable():
    # A response about a different leaf must not be accepted for _leaf.
    other_key = _key()
    other = _cert(_name("other.example"), _issuer.subject, other_key.public_key(), _issuer_key)
    raw = _ocsp_response(ocsp.OCSPCertStatus.GOOD, leaf=other)
    assert validate_response(raw, _leaf, _issuer) == "unavailable"


def test_stale_response_is_unavailable():
    now = datetime.now(timezone.utc)
    raw = _ocsp_response(
        ocsp.OCSPCertStatus.GOOD,
        this_update=now - timedelta(days=10), next_update=now - timedelta(days=5),
    )
    assert validate_response(raw, _leaf, _issuer) == "unavailable"


def test_future_response_is_unavailable():
    now = datetime.now(timezone.utc)
    raw = _ocsp_response(
        ocsp.OCSPCertStatus.GOOD,
        this_update=now + timedelta(days=2), next_update=now + timedelta(days=3),
    )
    assert validate_response(raw, _leaf, _issuer) == "unavailable"


def test_tampered_response_is_unavailable():
    raw = bytearray(_ocsp_response(ocsp.OCSPCertStatus.GOOD))
    raw[-1] ^= 0xFF  # corrupt the signature
    assert validate_response(bytes(raw), _leaf, _issuer) == "unavailable"


def test_garbage_is_unavailable():
    assert validate_response(b"not an ocsp response", _leaf, _issuer) == "unavailable"


# --- SSRF guard -------------------------------------------------------------
def test_is_public_host_rejects_private_and_loopback():
    assert _is_public_host("127.0.0.1") is False
    assert _is_public_host("10.0.0.1") is False
    assert _is_public_host("169.254.0.1") is False
    assert _is_public_host("8.8.8.8") is True


def test_safe_open_rejects_non_http_scheme():
    assert _safe_open("ftp://example.com/x", 1.0) is None


def test_safe_open_rejects_private_host(monkeypatch):
    # Should never open a connection to a private address.
    def boom(*a, **k):
        raise AssertionError("must not open connection to private host")
    monkeypatch.setattr(revocation.urllib.request, "build_opener", boom)
    assert _safe_open("http://127.0.0.1/ocsp", 1.0) is None


def test_check_ocsp_requires_issuer_and_url():
    assert check_ocsp(_LEAF_DER, None, "http://ocsp.x", 1.0) == "unavailable"
    assert check_ocsp(_LEAF_DER, _ISSUER_DER, "", 1.0) == "unavailable"
    # Bad scheme is refused before any network access.
    assert check_ocsp(_LEAF_DER, _ISSUER_DER, "ftp://ocsp.x", 1.0) == "unavailable"
