"""Application-layer HTTPS checks (currently HSTS)."""
from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from typing import Optional


@dataclass
class HstsResult:
    present: bool = False
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False


def check_hsts(hostname: str, port: int, timeout: float) -> HstsResult:
    """Issue an HTTPS HEAD request and inspect the HSTS header.

    Certificate verification is disabled here because the certificate itself
    is assessed separately; we only care about the response header.
    """
    result = HstsResult()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=ctx)
        conn.request("HEAD", "/", headers={"User-Agent": "Certainly/1.0"})
        response = conn.getresponse()
        header = response.getheader("Strict-Transport-Security")
    except Exception:
        return result
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # pragma: no cover
                pass

    if not header:
        return result

    result.present = True
    for directive in header.split(";"):
        directive = directive.strip().lower()
        if directive.startswith("max-age"):
            _, _, value = directive.partition("=")
            try:
                result.max_age = int(value.strip())
            except ValueError:
                result.max_age = None
        elif directive == "includesubdomains":
            result.include_subdomains = True
        elif directive == "preload":
            result.preload = True
    return result
