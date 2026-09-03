"""Tests for the scoring engine (no network)."""
from datetime import datetime, timedelta, timezone

from certainly.models import (
    CertificateInfo,
    CipherResult,
    HostResult,
    ProtocolResult,
)
from certainly.scanner.scoring import score_host


def _cert(**overrides) -> CertificateInfo:
    now = datetime.now(timezone.utc)
    defaults = dict(
        subject="example.com",
        subject_alt_names=["example.com", "www.example.com"],
        issuer="Example CA",
        serial_number="ABCD",
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=200),
        days_until_expiry=200,
        is_expired=False,
        is_not_yet_valid=False,
        is_self_signed=False,
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=2048,
        sha256_fingerprint="AA:BB",
        version="v3",
        hostname_matches=True,
        weak_signature=False,
    )
    defaults.update(overrides)
    return CertificateInfo(**defaults)


def _protocols(names_supported):
    all_protos = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    secure = {"TLSv1.2", "TLSv1.3"}
    return [
        ProtocolResult(name=n, supported=n in names_supported, secure=n in secure)
        for n in all_protos
    ]


def _modern_host() -> HostResult:
    return HostResult(
        target="example.com", hostname="example.com", port=443, reachable=True,
        protocols=_protocols({"TLSv1.2", "TLSv1.3"}),
        ciphers=[
            CipherResult(name="TLS_AES_256_GCM_SHA384", protocol="TLSv1.3",
                         bits=256, forward_secrecy=True, strong=True, aead=True),
            CipherResult(name="ECDHE-RSA-AES128-GCM-SHA256", protocol="TLSv1.2",
                         bits=128, forward_secrecy=True, strong=True, aead=True),
        ],
        forward_secrecy=True,
        certificate=_cert(),
        supports_tls13=True,
    )


def test_modern_config_scores_high():
    host = _modern_host()
    host.hsts = True
    host.hsts_max_age = 63072000
    score_host(host)
    assert host.score >= 90
    assert host.grade in {"A", "A+"}


def test_hsts_required_for_a_plus():
    host = _modern_host()
    host.hsts = False
    score_host(host)
    # Even with a perfect config, no HSTS means at most A.
    assert host.grade != "A+"


def test_expired_certificate_fails():
    host = _modern_host()
    host.certificate = _cert(
        is_expired=True,
        not_after=datetime.now(timezone.utc) - timedelta(days=1),
        days_until_expiry=-1,
    )
    score_host(host)
    assert host.grade == "F"
    assert host.score <= 20


def test_hostname_mismatch_fails():
    host = _modern_host()
    host.certificate = _cert(hostname_matches=False)
    score_host(host)
    assert host.grade == "F"


def test_self_signed_fails():
    host = _modern_host()
    host.certificate = _cert(is_self_signed=True)
    score_host(host)
    assert host.grade == "F"


def test_sslv3_and_weak_cipher_caps_score():
    host = HostResult(
        target="old.example", hostname="old.example", port=443, reachable=True,
        protocols=_protocols({"SSLv3", "TLSv1.0", "TLSv1.2"}),
        ciphers=[
            CipherResult(name="RC4-MD5", protocol="TLSv1.0", bits=128,
                         forward_secrecy=False, strong=False, aead=False),
            CipherResult(name="AES256-SHA", protocol="TLSv1.2", bits=256,
                         forward_secrecy=False, strong=True, aead=False),
        ],
        forward_secrecy=False,
        certificate=_cert(),
    )
    score_host(host)
    # SSLv3 + weak cipher + no FS should force a poor grade.
    assert host.score <= 50
    titles = {f.title for f in host.findings}
    assert "SSLv3 supported" in titles


def test_unreachable_host_scores_zero_and_f():
    host = HostResult(
        target="nope.invalid", hostname="nope.invalid", port=443,
        reachable=False, error="DNS resolution failed",
    )
    score_host(host)
    assert host.score == 0
    assert host.grade == "F"


def test_breakdown_is_populated():
    host = _modern_host()
    score_host(host)
    assert host.breakdown is not None
    assert 0 <= host.breakdown.protocol_support <= 100
    assert 0 <= host.breakdown.cipher_strength <= 100
