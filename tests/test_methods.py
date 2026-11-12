"""Check (f): dangerous HTTP methods -- positive + negative cases."""

import asyncio

from api_security_scanner.scanner import ScanConfig, Scanner


def _probe(base_url, path):
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [])
    asyncio.run(scanner.check_dangerous_methods(probe_path=path))
    return scanner


def test_methods_positive_resource_allows_all_three(base_url):
    """PUT, DELETE and TRACE all return 200 on /api/resource -> 3 findings."""
    scanner = _probe(base_url, "/api/resource")
    findings = [f for f in scanner.findings if f.check == "dangerous-method"]
    assert len(findings) == 3
    assert {f.method for f in findings} == {"PUT", "DELETE", "TRACE"}
    assert all(f.severity == "Medium" for f in findings)


def test_methods_negative_locked_resource_405(base_url):
    """/api/locked-resource returns 405 for all three -> no finding."""
    scanner = _probe(base_url, "/api/locked-resource")
    assert [f for f in scanner.findings if f.check == "dangerous-method"] == []
