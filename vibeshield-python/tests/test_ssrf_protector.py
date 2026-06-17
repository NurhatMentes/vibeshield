"""
VibeShield SSRF Protector — Python Test Suite

Comprehensive tests for SSRF URL validation, host parsing bypasses, and middleware enforcement.
"""

import pytest
from src.ssrf_protector import parse_ipv4, validate_url
from src.middleware.ssrf_security import enforce_safe_url, VibeShieldSSRFError


class TestSsrfProtector:
    # ── IPv4 Parser Unit Tests ────────────────────────────────────────

    def test_parse_ipv4_valid_standard(self):
        assert parse_ipv4("127.0.0.1") == [127, 0, 0, 1]
        assert parse_ipv4("192.168.1.254") == [192, 168, 1, 254]

    def test_parse_ipv4_hex(self):
        assert parse_ipv4("0x7f.0x0.0x0.0x1") == [127, 0, 0, 1]
        assert parse_ipv4("0x7f000001") == [127, 0, 0, 1]

    def test_parse_ipv4_octal(self):
        assert parse_ipv4("0177.0000.0000.0001") == [127, 0, 0, 1]
        # 0177 in octal is 127
        assert parse_ipv4("0177.0.0.1") == [127, 0, 0, 1]

    def test_parse_ipv4_decimal(self):
        # 2130706433 is 127.0.0.1
        assert parse_ipv4("2130706433") == [127, 0, 0, 1]

    def test_parse_ipv4_fewer_parts_carry_over(self):
        # 127.1 -> 127.0.0.1 (last part is 1)
        assert parse_ipv4("127.1") == [127, 0, 0, 1]
        # 10.0.1 -> 10.0.0.1
        assert parse_ipv4("10.0.1") == [10, 0, 0, 1]
        # 127.0.0.1 -> 127.0.0.1
        assert parse_ipv4("127.0.0.1") == [127, 0, 0, 1]

    def test_parse_ipv4_invalid_octal(self):
        # 08 is invalid in octal
        assert parse_ipv4("08.0.0.1") is None
        assert parse_ipv4("0179.0.0.1") is None

    def test_parse_ipv4_out_of_range(self):
        assert parse_ipv4("256.0.0.1") is None
        assert parse_ipv4("127.0.0.256") is None
        assert parse_ipv4("4294967296") is None  # max is 4294967295

    def test_parse_ipv4_invalid_strings(self):
        assert parse_ipv4("127.0.0.1.5") is None
        assert parse_ipv4("127.0.0.a") is None
        assert parse_ipv4("abc") is None
        assert parse_ipv4("") is None

    # ── URL Validator — Protocol & Scheme Tests ───────────────────────

    def test_validate_url_allow_http_https(self):
        assert validate_url("http://example.com")["safe"] is True
        assert validate_url("https://example.com")["safe"] is True

    def test_validate_url_block_other_protocols(self):
        res1 = validate_url("gopher://example.com")
        assert res1["safe"] is False
        assert "Forbidden protocol" in res1["reason"]

        res2 = validate_url("file:///etc/passwd")
        assert res2["safe"] is False
        assert "Forbidden protocol" in res2["reason"]

        res3 = validate_url("ftp://example.com")
        assert res3["safe"] is False

    # ── URL Validator — Loopback / Unspecified Hostnames ──────────────

    def test_validate_url_block_localhost_literal(self):
        res = validate_url("http://localhost")
        assert res["safe"] is False
        assert "Blocked loopback" in res["reason"]

    def test_validate_url_block_unspecified_ips(self):
        assert validate_url("http://0.0.0.0")["safe"] is False
        assert validate_url("http://[::]")["safe"] is False
        assert validate_url("http://[::ffff:0.0.0.0]")["safe"] is False

    # ── URL Validator — Loopback and Private IP Address Checks ────────

    def test_validate_url_block_loopback_ipv4(self):
        assert validate_url("http://127.0.0.1")["safe"] is False
        assert validate_url("http://127.1")["safe"] is False
        assert validate_url("http://127.0.0.254")["safe"] is False

    def test_validate_url_block_loopback_ipv6(self):
        assert validate_url("http://[::1]")["safe"] is False

    def test_validate_url_block_private_ipv4(self):
        # Class A
        assert validate_url("http://10.0.0.1")["safe"] is False
        assert validate_url("http://10.254.254.254")["safe"] is False
        # Class B
        assert validate_url("http://172.16.0.1")["safe"] is False
        assert validate_url("http://172.31.255.255")["safe"] is False
        # Class C
        assert validate_url("http://192.168.1.1")["safe"] is False

    def test_validate_url_block_carrier_grade_nat(self):
        assert validate_url("http://100.64.0.1")["safe"] is False
        assert validate_url("http://100.127.255.255")["safe"] is False
        # 100.63.255.255 is safe (not Carrier-grade NAT)
        assert validate_url("http://100.63.255.255")["safe"] is True

    def test_validate_url_block_link_local(self):
        assert validate_url("http://169.254.0.1")["safe"] is False
        assert validate_url("http://[fe80::1]")["safe"] is False

    def test_validate_url_block_multicast(self):
        assert validate_url("http://224.0.0.1")["safe"] is False
        assert validate_url("http://[ff02::1]")["safe"] is False

    # ── URL Validator — Obfuscation & Bypasses ────────────────────────

    def test_validate_url_block_decimal_ip(self):
        # 2130706433 = 127.0.0.1
        assert validate_url("http://2130706433")["safe"] is False

    def test_validate_url_block_hex_ip(self):
        assert validate_url("http://0x7f.0x0.0x0.0x1")["safe"] is False

    def test_validate_url_block_octal_ip(self):
        assert validate_url("http://0177.0.0.1")["safe"] is False

    # ── URL Validator — IDN Homograph Script Mixing ───────────────────

    def test_validate_url_block_mixed_scripts_latin_cyrillic(self):
        # 'google.com' with Cyrillic 'е' (U+0435) instead of Latin 'e'
        mixed_host = "googl\u0435.com"
        res = validate_url(f"http://{mixed_host}")
        assert res["safe"] is False
        assert "homograph" in res["reason"]

    def test_validate_url_block_mixed_scripts_latin_greek(self):
        # 'google.com' with Greek 'ο' (U+03BF) instead of Latin 'o'
        mixed_host = "g\u03BF\u03BFgle.com"
        res = validate_url(f"http://{mixed_host}")
        assert res["safe"] is False
        assert "homograph" in res["reason"]

    def test_validate_url_allow_single_script_non_latin(self):
        # pure cyrillic host name should not trigger mixing error
        cyrillic_host = "\u043f\u0440\u0435\u0437\u0438\u0434\u0435\u043d\u0442.\u0440\u0444"
        res = validate_url(f"http://{cyrillic_host}")
        # should pass the homograph mixed checks and be treated as normal domain
        assert res["safe"] is True

    # ── URL Validator — General Parsing Cases ─────────────────────────

    def test_validate_url_missing_hostname(self):
        res = validate_url("http:///path/to/resource")
        assert res["safe"] is False
        assert "hostname" in res["reason"]

    def test_validate_url_malformed_url(self):
        res = validate_url("http://[invalid-ipv6-bracket")
        assert res["safe"] is False

    # ── Middleware Enforcement Tests ──────────────────────────────────

    def test_enforce_safe_url_success(self):
        # Should complete silently without raising exceptions
        enforce_safe_url("http://example.com")
        enforce_safe_url("https://github.com/vibe")

    def test_enforce_safe_url_raises_custom_error(self):
        with pytest.raises(VibeShieldSSRFError) as exc_info:
            enforce_safe_url("http://127.0.0.1")
        
        assert exc_info.value.url == "http://127.0.0.1"
        assert "SSRF Protection" in str(exc_info.value)
        assert "Loopback IP address blocked" in exc_info.value.reason
