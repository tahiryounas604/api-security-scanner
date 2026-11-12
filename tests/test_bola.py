"""Check (b): BOLA / IDOR -- positive + negative cases."""

import asyncio

from api_security_scanner.scanner import Endpoint, ScanConfig, Scanner


def _run(base_url, endpoints, **kwargs):
    config = ScanConfig(base_url=base_url, token_a="token-user-1",
                        token_b="token-user-2", **kwargs)
    scanner = Scanner(config, endpoints)
    asyncio.run(scanner.run())
    return scanner


def test_bola_positive_any_token_reads_any_user(base_url):
    """/api/users/{id}: user A's token reads user 2, user B's reads user 1."""
    scanner = _run(base_url, [Endpoint("GET", "/api/users/{id}")])
    findings = [f for f in scanner.findings if f.check == "bola"]
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert "user B's id" in findings[0].evidence
    assert "user A's id" in findings[0].evidence  # token-swap variant too


def test_bola_negative_ownership_enforced(base_url):
    """/api/users/{id}/secure returns 403 for another user's id -> no finding."""
    scanner = _run(base_url, [Endpoint("GET", "/api/users/{id}/secure")])
    assert [f for f in scanner.findings if f.check == "bola"] == []


def test_bola_skipped_without_token_a(base_url):
    """Without token A the check records a note and finds nothing."""
    config = ScanConfig(base_url=base_url)
    scanner = Scanner(config, [Endpoint("GET", "/api/users/{id}")])
    asyncio.run(scanner.run())
    assert [f for f in scanner.findings if f.check == "bola"] == []
    assert any("BOLA" in note for note in scanner.notes)


def test_bola_single_token_still_detects(base_url):
    """With only token A, the cross-id variant alone is enough to flag."""
    config = ScanConfig(base_url=base_url, token_a="token-user-1")
    scanner = Scanner(config, [Endpoint("GET", "/api/users/{id}")])
    asyncio.run(scanner.run())
    assert len([f for f in scanner.findings if f.check == "bola"]) == 1
