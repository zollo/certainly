"""Tests for the extended certificate details and new findings (no network)."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from certainly.models import CertificateInfo, CipherResult, HostResult, ProtocolResult
from certainly.scanner import caa as caa_module
from certainly.scanner.caa import lookup_caa
from certainly.scanner.certificate import parse_certificate
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
    assert info.is_post_quantum is False  # RSA is classical, explicitly assessed
    assert info.hostname_matches is True


def test_parse_certificate_without_optional_extensions():
    info = parse_certificate(
        _make_cert_der(ocsp=False, crl=False, must_staple=False), "example.com"
    )
    assert info.ocsp_urls == []
    assert info.crl_urls == []
    assert info.must_staple is False


def test_rsa_certificate_is_not_post_quantum():
    # An ordinary classical key must never be flagged as post-quantum.
    assert parse_certificate(_make_cert_der(), "example.com").is_post_quantum is False


# --------------------------------------------------------------------------- #
# CAA lookup (DoH parsing, no real network)
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_caa_lookup_parses_records(monkeypatch):
    body = b'{"Answer":[{"type":257,"data":"0 issue \\"letsencrypt.org\\""},' \
           b'{"type":257,"data":"0 iodef \\"mailto:a@example.com\\""}]}'
    monkeypatch.setattr(caa_module.urllib.request, "urlopen", lambda *a, **k: _FakeResp(body))
    records = lookup_caa("example.com", 2.0)
    assert records == ['0 issue "letsencrypt.org"', '0 iodef "mailto:a@example.com"']


def test_caa_lookup_error_returns_none(monkeypatch):
    def boom(*a, **k):
        raise OSError("blocked")
    monkeypatch.setattr(caa_module.urllib.request, "urlopen", boom)
    assert lookup_caa("example.com", 2.0) is None


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
        weak_signature=False, is_post_quantum=False,
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


def test_pqc_finding_classical_is_informational():
    host = _host_with_cert(is_post_quantum=False)
    score_host(host)
    pqc = next(f for f in host.findings if "classical" in f.title.lower())
    assert pqc.severity == "info"
    # Must not over-claim connection-level readiness or traffic decryption.
    assert "ready" not in pqc.title.lower()


def test_pqc_finding_positive_is_informational_not_good():
    host = _host_with_cert(is_post_quantum=True)
    score_host(host)
    pqc = next(f for f in host.findings if "post-quantum" in f.title.lower())
    assert pqc.severity == "info"


def test_pqc_finding_absent_when_not_assessed():
    host = _host_with_cert(is_post_quantum=None)
    score_host(host)
    assert not any("quantum" in f.title.lower() for f in host.findings)


def test_ct_and_revocation_findings():
    host = _host_with_cert(sct_count=3, ocsp_urls=["http://ocsp.x"])
    score_host(host)
    titles = {f.title for f in host.findings}
    assert "Certificate Transparency" in titles
    assert "Revocation information published" in titles


def test_caa_findings_neutral_wording():
    host = _host_with_cert()
    host.caa_checked = True
    host.caa_records = ['0 issue "letsencrypt.org"']
    score_host(host)
    caa = next(f for f in host.findings if "CAA" in f.title)
    assert caa.title == "DNS CAA records published"

    host2 = _host_with_cert()
    host2.caa_checked = True
    host2.caa_records = []
    score_host(host2)
    assert "No DNS CAA records" in {f.title for f in host2.findings}
