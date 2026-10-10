"""DNS CAA (Certification Authority Authorization) lookup via DNS-over-HTTPS.

Uses a public DoH JSON resolver (works through an HTTPS egress proxy, unlike
raw UDP DNS). Best-effort: a lookup error returns ``None`` (not checked) so a
scan is never blocked, while a successful lookup returns the list of CAA
records found (possibly empty — meaning none are published).

Only the exact hostname is queried. CAA inheritance climbs parent labels, but
without a Public Suffix List that climb can cross a public-suffix boundary
(e.g. attributing ``co.uk``'s records to ``a.example.co.uk``), so we report
only what is published at the queried name rather than risk over-attribution.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Optional

DEFAULT_DOH_URL = "https://dns.google/resolve"
_CAA_TYPE = 257  # DNS resource record type for CAA


def _query(name: str, timeout: float, doh_url: str) -> list[str]:
    params = urllib.parse.urlencode({"name": name, "type": str(_CAA_TYPE)})
    request = urllib.request.Request(
        f"{doh_url}?{params}",
        headers={"Accept": "application/dns-json", "User-Agent": "Certainly/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    records = []
    for answer in payload.get("Answer", []):
        if answer.get("type") == _CAA_TYPE:
            data = str(answer.get("data", "")).strip()
            if data:
                records.append(data)
    return records


def lookup_caa(hostname: str, timeout: float,
               doh_url: str = DEFAULT_DOH_URL) -> Optional[list[str]]:
    """Return CAA records published at ``hostname``.

    ``None`` means the lookup could not be completed; an empty list means the
    lookup succeeded and no CAA records are published at that exact name.
    """
    try:
        return _query(hostname.strip(".").lower(), timeout, doh_url)
    except Exception:
        return None
