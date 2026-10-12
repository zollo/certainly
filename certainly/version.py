"""Build/version metadata surfaced in the UI footer.

The three values below identify exactly which build is running:

* ``version``    — the release version (e.g. ``1.4.0``).
* ``commit``     — the short git commit the image was built from.
* ``build_date`` — when the image was built (ISO-8601, UTC).

In a released container these are injected at image build time through the
``CERTAINLY_VERSION``, ``CERTAINLY_GIT_COMMIT`` and ``CERTAINLY_BUILD_DATE``
environment variables (see the Dockerfile and the release workflow). Outside a
built image — local development, tests, an editable install — the environment
variables are absent, so we fall back to the packaged version and, when a git
checkout is present, the live commit. Every field always resolves to a
non-empty string so the footer never renders a blank.
"""
from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from pathlib import Path

from . import __version__

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_short_commit() -> str | None:
    """Return the short commit of the surrounding checkout, if any.

    Only used as a local-dev fallback: a built image excludes ``.git`` (see
    ``.dockerignore``), so this returns ``None`` there and the injected
    environment variable is used instead.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else None


@lru_cache
def get_build_info() -> dict[str, str]:
    """Return build metadata for the footer, with sensible dev fallbacks."""
    version = os.getenv("CERTAINLY_VERSION") or __version__
    commit = os.getenv("CERTAINLY_GIT_COMMIT") or _git_short_commit() or "unknown"
    build_date = os.getenv("CERTAINLY_BUILD_DATE") or "dev"
    return {"version": version, "commit": commit, "build_date": build_date}


def format_build_line(info: dict[str, str] | None = None) -> str:
    """Render build metadata as the single line shown in the footer.

    e.g. ``v1.4.0 · a1b2c3d · built 2026-10-11T19:00:00Z`` for a released
    image, or ``v1.0.0 · 13e30c0 · dev build`` in local development.
    """
    info = info or get_build_info()
    parts = [f"v{info['version']}"]
    commit = info.get("commit")
    if commit and commit != "unknown":
        parts.append(commit)
    build_date = info.get("build_date")
    if build_date and build_date != "dev":
        parts.append(f"built {build_date}")
    elif build_date == "dev":
        parts.append("dev build")
    return " · ".join(parts)
