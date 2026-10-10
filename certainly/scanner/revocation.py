"""Validated, SSRF-hardened live OCSP revocation checking.

The OCSP responder URL comes from the scanned certificate's AIA extension, so
it is attacker-influenced. Every request is therefore guarded against SSRF
(scheme allow-list, public-address check, no redirects, bounded response), and
every response is cryptographically validated before its status is trusted:

* the response is SUCCESSFUL,
* its CertID matches this exact leaf + issuer,
* it is fresh (thisUpdate/nextUpdate within a small clock skew), and
* it is signed by the issuer directly, or by a delegated responder certificate
  that is itself issuer-signed and carries the id-kp-OCSPSigning EKU.

Any failure, uncertainty, or unreachable/forbidden responder yields
``unavailable`` — an unverified response can never set the revocation status.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

_MAX_RESPONSE_BYTES = 64 * 1024
_CLOCK_SKEW = timedelta(minutes=5)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects (a redirect could point at an internal host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _is_public_host(host: str) -> bool:
    """True only if every resolved address for ``host`` is a public address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:  # pragma: no cover - defensive
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def _safe_open(url: str, timeout: float, data: Optional[bytes] = None,
               content_type: Optional[str] = None) -> Optional[bytes]:
    """SSRF-guarded HTTP(S) fetch: public host only, no redirects, size-capped."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if not _is_public_host(parsed.hostname):
        return None
    headers = {"User-Agent": "Certainly/1.0"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data else "GET")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            if getattr(response, "status", 200) != 200:
                return None
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except Exception:
        return None
    if len(raw) > _MAX_RESPONSE_BYTES:
        return None
    return raw


def _as_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _verify_signature(pubkey, signature: bytes, data: bytes, hash_algo) -> bool:
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(signature, data, padding.PKCS1v15(), hash_algo)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, data, ec.ECDSA(hash_algo))
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey.verify(signature, data)
        else:
            return False
        return True
    except Exception:
        return False


def _responder_key(response: "ocsp.OCSPResponse", issuer: x509.Certificate):
    """Return the public key authorised to have signed ``response``, or None.

    Either the issuer itself, or a delegated responder certificate that is
    issuer-signed and carries the OCSP-signing EKU and is time-valid.
    """
    certs = list(response.certificates or [])
    if not certs:
        return issuer.public_key()
    now = datetime.now(timezone.utc)
    for cert in certs:
        # Must be signed by the issuer.
        if not _verify_signature(issuer.public_key(), cert.signature,
                                  cert.tbs_certificate_bytes,
                                  cert.signature_hash_algorithm):
            continue
        # Must be an authorised OCSP responder.
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            continue
        not_before = _as_utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
        not_after = _as_utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
        if not_before - _CLOCK_SKEW > now or not_after + _CLOCK_SKEW < now:
            continue
        return cert.public_key()
    return None


def _expected_certid(leaf: x509.Certificate, issuer: x509.Certificate, hash_algo):
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hash_algo).build()
    return req.serial_number, req.issuer_key_hash, req.issuer_name_hash


def validate_response(raw: bytes, leaf: x509.Certificate,
                      issuer: x509.Certificate) -> str:
    """Validate a DER OCSP response for ``leaf``/``issuer`` and return its status.

    Returns ``good`` / ``revoked`` / ``unknown`` only after full validation;
    ``unavailable`` on any failure.
    """
    try:
        response = ocsp.load_der_ocsp_response(raw)
    except Exception:
        return "unavailable"
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "unavailable"

    # CertID must match this exact leaf + issuer (recomputed with the
    # response's own hash algorithm so the hashes are comparable).
    try:
        exp_serial, exp_key_hash, exp_name_hash = _expected_certid(
            leaf, issuer, response.hash_algorithm
        )
        if (response.serial_number != exp_serial
                or response.issuer_key_hash != exp_key_hash
                or response.issuer_name_hash != exp_name_hash):
            return "unavailable"
    except Exception:
        return "unavailable"

    # Freshness.
    now = datetime.now(timezone.utc)
    this_update = _as_utc(getattr(response, "this_update_utc", None) or response.this_update)
    next_update = _as_utc(getattr(response, "next_update_utc", None) or response.next_update)
    if this_update is None or this_update - _CLOCK_SKEW > now:
        return "unavailable"
    if next_update is not None and next_update + _CLOCK_SKEW < now:
        return "unavailable"

    # Signature by the issuer or an authorised delegated responder.
    signer_key = _responder_key(response, issuer)
    if signer_key is None:
        return "unavailable"
    if not _verify_signature(signer_key, response.signature,
                             response.tbs_response_bytes,
                             response.signature_hash_algorithm):
        return "unavailable"

    status = response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return "good"
    if status == ocsp.OCSPCertStatus.REVOKED:
        return "revoked"
    return "unknown"


def check_ocsp(leaf_der: bytes, issuer_der: Optional[bytes], url: str,
               timeout: float) -> str:
    """Query the OCSP responder for ``leaf_der`` and return a validated status."""
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
    except Exception:
        return "unavailable"
    raw = _safe_open(url, timeout, data=body, content_type="application/ocsp-request")
    if raw is None:
        return "unavailable"
    return validate_response(raw, leaf, issuer)


def fetch_issuer(leaf_der: bytes, ca_issuer_urls: list[str], timeout: float) -> Optional[bytes]:
    """Best-effort issuer retrieval via the AIA caIssuers URL (DER or PKCS7).

    Used when the server did not supply the chain (e.g. the TLS stack could not
    expose it). SSRF-guarded like all other fetches. Returns DER bytes or None.
    """
    for url in ca_issuer_urls:
        raw = _safe_open(url, timeout)
        if raw is None:
            continue
        # Try a bare DER certificate first, then a PKCS7 bundle.
        try:
            return x509.load_der_x509_certificate(raw).public_bytes(serialization.Encoding.DER)
        except Exception:
            pass
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            certs = pkcs7.load_der_pkcs7_certificates(raw)
            if certs:
                return certs[0].public_bytes(serialization.Encoding.DER)
        except Exception:
            continue
    return None
