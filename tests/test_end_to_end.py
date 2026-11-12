"""End-to-end: full scan against the local fixture, plus CLI behaviour."""

import json
import os
import subprocess
import sys

import pytest

from api_security_scanner.scanner import (
    Endpoint,
    ScanConfig,
    load_endpoints_file,
    run_scan,
)

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
EXAMPLES = os.path.join(PROJECT_ROOT, "examples")


def _checks(result):
    return {f.check for f in result.findings}


def test_full_scan_finds_all_vulnerabilities(base_url, fixture_server):
    """Every deliberate fixture flaw is found; every secure control is clean."""
    fixture_server.reset_rate_limit()
    endpoints = load_endpoints_file(os.path.join(EXAMPLES, "endpoints.txt"))
    config = ScanConfig(
        base_url=base_url,
        token_a="token-user-1",
        token_b="token-user-2",
        rate_limit_requests=10,
        methods_probe_path="/api/resource",
    )
    result = run_scan(config, endpoints)

    assert result.target == base_url
    assert result.summary["High"] == 2  # broken-auth + BOLA
    assert result.summary["Medium"] >= 4  # rate-limit, verbose-error, 3 methods
    assert result.summary["Low"] == 6  # six missing headers

    checks = _checks(result)
    assert "broken-auth" in checks
    assert "bola" in checks
    assert "rate-limit" in checks
    assert "verbose-error" in checks
    assert "missing-header" in checks
    assert "dangerous-method" in checks

    # Secure controls must NOT be flagged.
    flagged = {(f.method, f.endpoint) for f in result.findings}
    assert ("GET", "/api/users/me") not in flagged
    assert ("GET", "/api/admin/stats") not in flagged
    # /api/public/health IS flagged -- but only by the rate-limit probe
    # (it answers 200 to every rapid request); never for auth or BOLA.
    assert not any(f.check in ("broken-auth", "bola")
                    and f.endpoint == "/api/public/health"
                    for f in result.findings)
    bola = [f for f in result.findings if f.check == "bola"]
    assert all("/secure" not in f.endpoint for f in bola)
    assert not any(f.endpoint == "/api/debug/clean-error"
                    for f in result.findings if f.check == "verbose-error")


def test_full_scan_secure_only_target_is_clean(base_url, fixture_server):
    """Scanning only the secured endpoints: no High/Medium findings.

    The fixture root genuinely lacks security headers, so the six Low
    header findings remain -- that is the fixture's flaw, not the scan's.
    """
    fixture_server.reset_rate_limit()
    endpoints = [
        Endpoint("GET", "/api/users/me"),
        Endpoint("GET", "/api/users/{id}/secure"),
        Endpoint("GET", "/api/admin/stats"),
        Endpoint("GET", "/api/secure-headers", public=True),
    ]
    config = ScanConfig(
        base_url=base_url,
        token_a="token-user-1",
        token_b="token-user-2",
        rate_limit_requests=10,
        rate_limit_endpoint="/api/rate-limited",
        methods_probe_path="/api/locked-resource",
    )
    result = run_scan(config, endpoints)
    # Only the six missing security headers on the fixture root remain:
    # every auth / BOLA / rate-limit / error / method control is clean.
    assert result.summary["High"] == 0
    assert result.summary["Medium"] == 0
    assert result.summary["Low"] == 6
    assert all(f.check == "missing-header" for f in result.findings)


def _run_cli(base_url, tmp_path, extra_args):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(PROJECT_ROOT, "src")
    return subprocess.run(
        [sys.executable, "-m", "api_security_scanner",
         "--base-url", base_url, *extra_args,
         "--output-dir", str(tmp_path / "report")],
        capture_output=True, text=True, cwd=PROJECT_ROOT, env=env, timeout=120,
    )


def test_cli_full_scan_exit_code_2_and_reports(base_url, tmp_path):
    """CLI on the vulnerable fixture: exit 2, report.json + report.md exist."""
    proc = _run_cli(base_url, tmp_path, [
        "--endpoints", os.path.join(EXAMPLES, "endpoints.txt"),
        "--token-a", "token-user-1", "--token-b", "token-user-2",
        "--rate-limit-requests", "10",
        "--rate-limit-endpoint", "/api/no-limit",
        "--methods-path", "/api/resource",
    ])
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "High" in proc.stdout
    report_dir = tmp_path / "report"
    data = json.loads((report_dir / "report.json").read_text())
    assert data["summary"]["High"] == 2
    md = (report_dir / "report.md").read_text()
    assert "BOLA" in md and "Broken authentication" in md


def test_cli_clean_scan_exit_code_0(base_url, tmp_path):
    """CLI on secured endpoints only: exit 0, reports still written."""
    endpoints_file = tmp_path / "secure.txt"
    endpoints_file.write_text(
        "GET /api/users/me\n"
        "GET /api/users/{id}/secure\n"
        "GET /api/admin/stats\n"
    )
    proc = _run_cli(base_url, tmp_path, [
        "--endpoints", str(endpoints_file),
        "--token-a", "token-user-1", "--token-b", "token-user-2",
        "--rate-limit-requests", "10",
        "--rate-limit-endpoint", "/api/rate-limited",
        "--methods-path", "/api/locked-resource",
    ])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads((tmp_path / "report" / "report.json").read_text())
    # Only the fixture root's six missing headers remain; no High/Medium.
    assert data["summary"]["High"] == 0
    assert data["summary"]["Medium"] == 0
    assert data["summary"]["Low"] == 6


def test_cli_openapi_input(base_url, tmp_path):
    """CLI accepts an OpenAPI spec instead of an endpoint list."""
    proc = _run_cli(base_url, tmp_path, [
        "--openapi", os.path.join(EXAMPLES, "openapi.yaml"),
        "--token-a", "token-user-1", "--token-b", "token-user-2",
        "--rate-limit-requests", "10",
        "--rate-limit-endpoint", "/api/no-limit",
        "--methods-path", "/api/resource",
    ])
    # Spec's servers[0].url is port 8765, but --base-url overrides it.
    assert proc.returncode == 2, proc.stdout + proc.stderr
    data = json.loads((tmp_path / "report" / "report.json").read_text())
    assert data["summary"]["High"] == 2


def test_cli_missing_endpoints_file_errors(base_url, tmp_path):
    proc = _run_cli(base_url, tmp_path, ["--endpoints", "/nonexistent.txt"])
    assert proc.returncode == 1
    assert "error" in proc.stderr.lower()
