"""Check (a): broken authentication -- positive + negative cases."""

import asyncio

from api_security_scanner.scanner import Endpoint, ScanConfig, Scanner


def _scan(base_url, endpoints, **kwargs):
    config = ScanConfig(base_url=base_url, token_a="token-user-1",
                        token_b="token-user-2", **kwargs)
    return asyncio.run(Scanner(config, endpoints).run())


def _broken_auth_findings(result):
    return [f for f in result.findings if f.check == "broken-auth"]


def test_broken_auth_positive_user_list_without_token(base_url):
    """GET /api/users returns 200 with no token -> High finding."""
    result = _scan(base_url, [Endpoint("GET", "/api/users")])
    findings = _broken_auth_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert "/api/users" in findings[0].endpoint
    assert "200" in findings[0].evidence


def test_broken_auth_negative_rejects_anonymous(base_url):
    """GET /api/users/me and /api/admin/stats return 401 anon -> no finding."""
    result = _scan(base_url, [
        Endpoint("GET", "/api/users/me"),
        Endpoint("GET", "/api/admin/stats"),
    ])
    assert _broken_auth_findings(result) == []


def test_broken_auth_negative_public_endpoint_skipped(base_url):
    """Endpoints marked public are not flagged even though they return 200."""
    result = _scan(base_url, [Endpoint("GET", "/api/public/health", public=True)])
    assert _broken_auth_findings(result) == []
