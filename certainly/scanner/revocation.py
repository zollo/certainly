"""Active certificate revocation checking via OCSP.

Builds an OCSP request for the leaf certificate (using its issuer from the
chain) and queries the responder advertised in the certificate's Authority
Information Access extension. Best-effort: any error yields "unavailable" so a
scan is never blocked by a flaky or unreachable responder.
"""
from __future__ import annotations

import urllib.request
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus, OCSPResponseStatus


def check_ocsp(leaf_der: bytes, issuer_der: Optional[bytes], url: str,
               timeout: float) -> str:
    """Return the OCSP revocation status for a certificate.

    One of: ``good``, ``revoked``, ``unknown``, or ``unavailable``.
    """
    if not issuer_der or not url:
        return "unavailable"
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
        request = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(leaf, issuer, hashes.SHA1())  # SHA-1 is the OCSP CertID norm
            .build()
        )
        body = request.public_bytes(serialization.Encoding.DER)
        http_request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                "User-Agent": "Certainly/1.0",
            },
        )
        with urllib.request.urlopen(http_request, timeout=timeout) as response:
            raw = response.read()
        ocsp_response = ocsp.load_der_ocsp_response(raw)
        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return "unavailable"
        status = ocsp_response.certificate_status
        if status == OCSPCertStatus.GOOD:
            return "good"
        if status == OCSPCertStatus.REVOKED:
            return "revoked"
        return "unknown"
    except Exception:
        return "unavailable"
