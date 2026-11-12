"""Check (c): rate-limit probe -- positive + negative cases."""

import asyncio

from api_security_scanner.scanner import ScanConfig, Scanner


def _probe(base_url, path, requests=10):
    config = ScanConfig(base_url=base_url, token_a="token-user-1",
                        rate_limit_requests=requests)
    scanner = Scanner(config, [])
    asyncio.run(scanner.check_rate_limit(probe_path=path))
    return scanner


def test_rate_limit_positive_never_limited(base_url):
    """/api/no-limit answers 200 to every rapid request -> Medium finding."""
    scanner = _probe(base_url, "/api/no-limit", requests=10)
    findings = [f for f in scanner.findings if f.check == "rate-limit"]
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert "10 rapid" in findings[0].evidence
    assert "429" in findings[0].evidence


def test_rate_limit_negative_429_seen(base_url, fixture_server):
    """/api/rate-limited returns 429 after 5 requests -> no finding."""
    fixture_server.reset_rate_limit()
    scanner = _probe(base_url, "/api/rate-limited", requests=10)
    assert [f for f in scanner.findings if f.check == "rate-limit"] == []
    assert any("429" in note for note in scanner.notes)


def test_rate_limit_counter_resets(fixture_server):
    """Fixture helper really resets the counter (test isolation proof)."""
    fixture_server.reset_rate_limit()
    assert fixture_server.httpd.state["rate_limited_hits"] == 0
