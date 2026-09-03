"""Security scoring for a scanned host.

The methodology is inspired by the Qualys SSL Labs rating guide: component
scores for protocol support, key exchange, and cipher strength are combined
with fixed weights, and then a series of caps are applied for conditions that
materially weaken the configuration (obsolete protocols, weak ciphers, missing
forward secrecy, certificate problems, ...).

The result is a 0-100 numeric score plus a convenience letter grade.
"""
from __future__ import annotations

from ..models import Finding, HostResult, ProtocolResult, ScoreBreakdown

# Component weights (must sum to 1.0).
WEIGHT_PROTOCOL = 0.30
WEIGHT_KEY_EXCHANGE = 0.30
WEIGHT_CIPHER = 0.40

# Numeric value of each protocol version for the protocol component.
PROTOCOL_VALUE = {
    "SSLv3": 0,
    "TLSv1.0": 40,
    "TLSv1.1": 55,
    "TLSv1.2": 95,
    "TLSv1.3": 100,
}


def _severity_finding(sev: str, title: str, detail: str) -> Finding:
    return Finding(severity=sev, title=title, detail=detail)


def _protocol_component(result: HostResult, findings: list[Finding]) -> int:
    supported = [p.name for p in result.protocols if p.supported]
    if not supported:
        return 0

    values = [PROTOCOL_VALUE.get(name, 0) for name in supported]
    best, worst = max(values), min(values)
    score = (best + worst) // 2

    if "SSLv3" in supported:
        findings.append(_severity_finding(
            "critical", "SSLv3 supported",
            "SSLv3 is obsolete and vulnerable (e.g. POODLE). It should be disabled.",
        ))
    if "TLSv1.0" in supported or "TLSv1.1" in supported:
        findings.append(_severity_finding(
            "medium", "Obsolete TLS versions supported",
            "TLS 1.0 / 1.1 are deprecated. Only TLS 1.2 and TLS 1.3 should be enabled.",
        ))
    if "TLSv1.3" in supported:
        findings.append(_severity_finding(
            "good", "TLS 1.3 supported", "The server supports the latest TLS version.",
        ))
    if "TLSv1.2" not in supported and "TLSv1.3" not in supported:
        findings.append(_severity_finding(
            "high", "No modern TLS", "Neither TLS 1.2 nor TLS 1.3 is supported.",
        ))
    return score


def _key_exchange_component(result: HostResult, findings: list[Finding]) -> int:
    cert = result.certificate
    if cert is None or cert.key_bits is None:
        return 40

    key_type = cert.key_type
    bits = cert.key_bits or 0

    if key_type.startswith("EC") or key_type in {"Ed25519", "Ed448"}:
        score = 100 if bits >= 256 else 80
    else:  # RSA / DSA
        if bits >= 4096:
            score = 100
        elif bits >= 3072:
            score = 95
        elif bits >= 2048:
            score = 90
        elif bits >= 1024:
            score = 40
            findings.append(_severity_finding(
                "high", "Weak key size", f"The {key_type} key is only {bits} bits.",
            ))
        else:
            score = 20
            findings.append(_severity_finding(
                "critical", "Very weak key size", f"The {key_type} key is only {bits} bits.",
            ))

    if not result.forward_secrecy:
        findings.append(_severity_finding(
            "medium", "No forward secrecy",
            "The server does not offer any forward-secret (ECDHE/DHE) cipher suites.",
        ))
        score = min(score, 70)
    else:
        findings.append(_severity_finding(
            "good", "Forward secrecy", "Forward-secret key exchange is supported.",
        ))
    return score


def _cipher_component(result: HostResult, findings: list[Finding]) -> int:
    if not result.ciphers:
        return 40

    bits_list = [c.bits for c in result.ciphers if c.bits is not None]
    if not bits_list:
        return 60
    strongest = max(bits_list)
    weakest = min(bits_list)

    def value(bits: int) -> int:
        if bits == 0:
            return 0
        if bits < 128:
            return 20
        if bits < 256:
            return 80
        return 100

    score = (value(strongest) + value(weakest)) // 2

    weak = [c for c in result.ciphers if not c.strong]
    if weak:
        names = ", ".join(sorted({c.name for c in weak})[:5])
        findings.append(_severity_finding(
            "high", "Weak cipher suites offered",
            f"The server offers weak or broken ciphers: {names}.",
        ))
    non_aead = [c for c in result.ciphers if not c.aead]
    if non_aead and not any(c.aead for c in result.ciphers):
        findings.append(_severity_finding(
            "low", "No AEAD ciphers",
            "No AEAD (GCM/ChaCha20) cipher suites are offered.",
        ))
    return score


def _certificate_component(result: HostResult, findings: list[Finding]) -> tuple[int, bool]:
    """Return (component_score, cert_is_valid)."""
    cert = result.certificate
    if cert is None:
        findings.append(_severity_finding(
            "critical", "No certificate", "No certificate could be retrieved.",
        ))
        return 0, False

    valid = True
    score = 100

    if cert.is_expired:
        findings.append(_severity_finding(
            "critical", "Certificate expired",
            f"The certificate expired on {cert.not_after.date()}.",
        ))
        valid = False
        score = 0
    elif cert.days_until_expiry < 15:
        findings.append(_severity_finding(
            "medium", "Certificate expiring soon",
            f"The certificate expires in {cert.days_until_expiry} day(s).",
        ))
        score = min(score, 80)

    if cert.is_not_yet_valid:
        findings.append(_severity_finding(
            "critical", "Certificate not yet valid",
            f"The certificate is not valid until {cert.not_before.date()}.",
        ))
        valid = False
        score = 0

    if not cert.hostname_matches:
        findings.append(_severity_finding(
            "critical", "Hostname mismatch",
            "The certificate is not valid for the requested hostname.",
        ))
        valid = False
        score = min(score, 20)

    if cert.is_self_signed:
        findings.append(_severity_finding(
            "high", "Self-signed certificate",
            "The certificate is self-signed and will not be trusted by browsers.",
        ))
        valid = False
        score = min(score, 30)

    if cert.weak_signature:
        findings.append(_severity_finding(
            "high", "Weak signature algorithm",
            f"The certificate uses a weak signature ({cert.signature_algorithm}).",
        ))
        score = min(score, 60)

    if valid:
        findings.append(_severity_finding(
            "good", "Valid certificate",
            f"Trusted for {cert.subject}, expires in {cert.days_until_expiry} days.",
        ))
    return score, valid


def _grade_for_score(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    if score >= 20:
        return "E"
    return "F"


def score_host(result: HostResult) -> None:
    """Compute score, grade, breakdown, and findings for ``result`` in place."""
    # An unreachable host cannot be assessed; it scores zero.
    if not result.reachable:
        result.score = 0
        result.grade = "F"
        result.breakdown = ScoreBreakdown(
            protocol_support=0, key_exchange=0, cipher_strength=0, certificate=0,
        )
        if not result.findings:
            result.findings = [_severity_finding(
                "critical", "Host unreachable",
                result.error or "The host could not be reached over TLS.",
            )]
        return

    findings: list[Finding] = []

    protocol = _protocol_component(result, findings)
    key_exchange = _key_exchange_component(result, findings)
    cipher = _cipher_component(result, findings)
    certificate, cert_valid = _certificate_component(result, findings)

    numeric = round(
        WEIGHT_PROTOCOL * protocol
        + WEIGHT_KEY_EXCHANGE * key_exchange
        + WEIGHT_CIPHER * cipher
    )

    supported = {p.name for p in result.protocols if p.supported}

    # --- Caps for materially weakening conditions -------------------------
    if "SSLv3" in supported:
        numeric = min(numeric, 50)
    if "TLSv1.0" in supported or "TLSv1.1" in supported:
        numeric = min(numeric, 65)
    if not result.forward_secrecy:
        numeric = min(numeric, 80)
    if any(not c.strong for c in result.ciphers):
        numeric = min(numeric, 50)
    if "TLSv1.2" not in supported and "TLSv1.3" not in supported:
        numeric = min(numeric, 50)

    # Certificate problems are a hard gate.
    if not cert_valid:
        numeric = min(numeric, 20)

    numeric = max(0, min(100, numeric))
    grade = _grade_for_score(numeric)

    # HSTS is required to reach the very top grade.
    if grade == "A+" and not result.hsts:
        grade = "A"
    if result.hsts:
        findings.append(_severity_finding(
            "good", "HSTS enabled",
            "HTTP Strict Transport Security is enabled"
            + (f" (max-age={result.hsts_max_age})." if result.hsts_max_age else "."),
        ))
    elif cert_valid:
        findings.append(_severity_finding(
            "low", "HSTS not enabled",
            "HTTP Strict Transport Security is not enabled.",
        ))

    if not cert_valid:
        grade = "F"

    result.score = numeric
    result.grade = grade
    result.breakdown = ScoreBreakdown(
        protocol_support=protocol,
        key_exchange=key_exchange,
        cipher_strength=cipher,
        certificate=certificate,
    )
    # Order findings by severity for presentation.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "good": 5}
    result.findings = sorted(findings, key=lambda f: order.get(f.severity, 9))
