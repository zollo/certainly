"""Tests for target parsing and cipher classification (no network)."""
from certainly.scanner.analyzer import parse_target
from certainly.scanner.tls import classify_cipher


def test_parse_bare_hostname():
    t = parse_target("example.com", 443)
    assert t.hostname == "example.com"
    assert t.port == 443


def test_parse_host_with_port():
    t = parse_target("example.com:8443", 443)
    assert t.hostname == "example.com"
    assert t.port == 8443


def test_parse_full_url():
    t = parse_target("https://example.com/some/path", 443)
    assert t.hostname == "example.com"
    assert t.port == 443


def test_parse_url_with_explicit_port():
    t = parse_target("https://example.com:9443/x", 443)
    assert t.hostname == "example.com"
    assert t.port == 9443


def test_parse_strips_whitespace_and_slash():
    t = parse_target("  example.com/  ", 443)
    assert t.hostname == "example.com"


def test_parse_empty_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_target("   ", 443)


def test_parse_invalid_port_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_target("example.com:notaport", 443)


def test_classify_modern_cipher_is_strong_fs_aead():
    c = classify_cipher("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
    assert c.strong and c.forward_secrecy and c.aead


def test_classify_rc4_is_weak():
    c = classify_cipher("RC4-MD5", "TLSv1.2", 128)
    assert not c.strong


def test_classify_3des_is_weak():
    c = classify_cipher("DES-CBC3-SHA", "TLSv1.2", 112)
    assert not c.strong
    assert not c.aead


def test_classify_non_fs_cipher():
    c = classify_cipher("AES128-GCM-SHA256", "TLSv1.2", 128)
    assert c.strong and c.aead and not c.forward_secrecy


def test_classify_tls13_always_strong():
    c = classify_cipher("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    assert c.strong and c.forward_secrecy and c.aead
