"""Settings parsing from the environment."""
import pytest

from certainly.config import Settings


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ("*", ["*"]),
        ("https://a.example, https://b.example", ["https://a.example", "https://b.example"]),
    ],
)
def test_cors_allow_origins_from_env(monkeypatch, raw, expected):
    monkeypatch.setenv("CERTAINLY_CORS_ALLOW_ORIGINS", raw)
    assert Settings(_env_file=None).cors_allow_origins == expected


def test_cors_allow_origins_default(monkeypatch):
    monkeypatch.delenv("CERTAINLY_CORS_ALLOW_ORIGINS", raising=False)
    assert Settings(_env_file=None).cors_allow_origins == []
