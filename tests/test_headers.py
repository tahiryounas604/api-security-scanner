"""Check (e): security headers audit -- positive + negative cases."""

import asyncio

from api_security_scanner.scanner import REQUIRED_HEADERS, ScanConfig, Scanner


def _probe(base_url, urls):
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [])
    asyncio.run(scanner.check_security_headers(probe_urls=urls))
    return scanner


def test_headers_positive_root_missing_all(base_url):
    """Fixture root sends none of the six headers -> six Low findings."""
    scanner = _probe(base_url, [base_url + "/"])
    findings = [f for f in scanner.findings if f.check == "missing-header"]
    assert len(findings) == len(REQUIRED_HEADERS) == 6
    missing = {f.title.split(": ", 1)[1] for f in findings}
    assert missing == set(REQUIRED_HEADERS)
    assert all(f.severity == "Low" for f in findings)


def test_headers_negative_all_present(base_url):
    """/api/secure-headers sends all six headers -> no finding."""
    scanner = _probe(base_url, [base_url + "/api/secure-headers"])
    assert [f for f in scanner.findings if f.check == "missing-header"] == []


def test_headers_default_probe_uses_root(base_url):
    """With no explicit URL the check audits the site root."""
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [])
    asyncio.run(scanner.check_security_headers())
    assert len([f for f in scanner.findings if f.check == "missing-header"]) == 6
