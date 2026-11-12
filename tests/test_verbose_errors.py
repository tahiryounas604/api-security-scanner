"""Check (d): verbose error / stack-trace disclosure -- positive + negative."""

import asyncio

from api_security_scanner.scanner import Endpoint, ScanConfig, Scanner


def _probe(base_url, paths):
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [])
    asyncio.run(scanner.check_verbose_errors(probe_paths=paths))
    return scanner


def test_verbose_error_positive_traceback_endpoint(base_url):
    """/api/debug/error returns a Python traceback -> Medium finding."""
    scanner = _probe(base_url, ["/api/debug/error"])
    findings = [f for f in scanner.findings if f.check == "verbose-error"]
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert "Traceback" in findings[0].evidence


def test_verbose_error_positive_malformed_id(base_url):
    """Malformed id on /api/users/{id} triggers a traceback -> finding."""
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [Endpoint("GET", "/api/users/{id}")])
    asyncio.run(scanner.check_verbose_errors())  # default probes incl. malformed id
    findings = [f for f in scanner.findings if f.check == "verbose-error"]
    assert len(findings) == 1
    assert "'--" in findings[0].endpoint


def test_verbose_error_negative_generic_500(base_url):
    """/api/debug/clean-error is a generic 500 -> no finding."""
    scanner = _probe(base_url, ["/api/debug/clean-error"])
    assert [f for f in scanner.findings if f.check == "verbose-error"] == []


def test_verbose_error_negative_404(base_url):
    """A plain 404 with no markers -> no finding."""
    scanner = _probe(base_url, ["/__api_security_scanner_probe_nonexistent__"])
    assert [f for f in scanner.findings if f.check == "verbose-error"] == []
