"""Tests for the extended certificate details and new findings (no network)."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from certainly.models import CertificateInfo, CipherResult, HostResult, ProtocolResult
from certainly.scanner.caa import _candidate_names
from certainly.scanner.certificate import parse_certificate
from certainly.scanner.revocation import check_ocsp
from certainly.scanner.scoring import score_host


# --------------------------------------------------------------------------- #
# Certificate extension parsing
# --------------------------------------------------------------------------- #
def _make_cert_der(hostname="example.com", ocsp=True, crl=True, must_staple=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
    )
    if ocsp:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.com"),
                )
            ]),
            critical=False,
        )
    if crl:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://crl.example.com/a.crl")],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )
    if must_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate_extensions():
    info = parse_certificate(_make_cert_der(), "example.com")
    assert info.serial_number
    assert info.ocsp_urls == ["http://ocsp.example.com"]
    assert info.crl_urls == ["http://crl.example.com/a.crl"]
    assert info.must_staple is True
    assert info.sct_count == 0  # no SCTs synthesised
    assert info.is_post_quantum is False  # RSA is classical
    assert info.hostname_matches is True


def test_parse_certificate_without_optional_extensions():
    info = parse_certificate(
        _make_cert_der(ocsp=False, crl=False, must_staple=False), "example.com"
    )
    assert info.ocsp_urls == []
    assert info.crl_urls == []
    assert info.must_staple is False


# --------------------------------------------------------------------------- #
# CAA + OCSP helpers
# --------------------------------------------------------------------------- #
def test_caa_candidate_names_climbs_to_registrable_domain():
    assert _candidate_names("a.b.example.com") == [
        "a.b.example.com", "b.example.com", "example.com"
    ]
    assert _candidate_names("example.com") == ["example.com"]


def test_check_ocsp_unavailable_without_issuer_or_url():
    assert check_ocsp(b"leaf", None, "http://ocsp", 1.0) == "unavailable"
    assert check_ocsp(b"leaf", b"issuer", "", 1.0) == "unavailable"


# --------------------------------------------------------------------------- #
# New findings in the scorer
# --------------------------------------------------------------------------- #
def _host_with_cert(**cert_overrides) -> HostResult:
    now = datetime.now(timezone.utc)
    cert_kw = dict(
        subject="example.com", subject_alt_names=["example.com"], issuer="Example CA",
        serial_number="ABCD", not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=200), days_until_expiry=200,
        is_expired=False, is_not_yet_valid=False, is_self_signed=False,
        signature_algorithm="sha256WithRSAEncryption", key_type="RSA", key_bits=2048,
        sha256_fingerprint="AA:BB", version="v3", hostname_matches=True,
        weak_signature=False,
    )
    cert_kw.update(cert_overrides)
    return HostResult(
        target="example.com", hostname="example.com", port=443, reachable=True,
        protocols=[
            ProtocolResult(name="TLSv1.2", supported=True, secure=True),
            ProtocolResult(name="TLSv1.3", supported=True, secure=True),
        ],
        ciphers=[CipherResult(name="TLS_AES_256_GCM_SHA384", protocol="TLSv1.3",
                              bits=256, forward_secrecy=True, strong=True, aead=True)],
        forward_secrecy=True,
        certificate=CertificateInfo(**cert_kw),
    )


def test_pqc_finding_for_classical_certificate():
    host = _host_with_cert(is_post_quantum=False)
    score_host(host)
    assert "No post-quantum cryptography" in {f.title for f in host.findings}


def test_pqc_finding_good_when_post_quantum():
    host = _host_with_cert(is_post_quantum=True)
    score_host(host)
    pqc = next(f for f in host.findings if "post-quantum" in f.title.lower())
    assert pqc.severity == "good"


def test_ct_and_revocation_findings():
    host = _host_with_cert(sct_count=3, ocsp_urls=["http://ocsp.x"], ocsp_status="good")
    score_host(host)
    titles = {f.title for f in host.findings}
    assert "Certificate Transparency" in titles
    assert "Not revoked" in titles
    assert "Revocation information published" in titles


def test_revoked_certificate_fails():
    host = _host_with_cert(ocsp_status="revoked")
    score_host(host)
    assert host.grade == "F"
    assert host.score <= 20
    assert "Certificate revoked" in {f.title for f in host.findings}


def test_caa_findings():
    host = _host_with_cert()
    host.caa_checked = True
    host.caa_records = ['0 issue "letsencrypt.org"']
    score_host(host)
    assert "DNS CAA configured" in {f.title for f in host.findings}

    host2 = _host_with_cert()
    host2.caa_checked = True
    host2.caa_records = []
    score_host(host2)
    assert "No DNS CAA records" in {f.title for f in host2.findings}
