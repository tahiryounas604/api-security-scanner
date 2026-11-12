"""Report writers: JSON + Markdown structure and content."""

import json

from api_security_scanner.report import (
    report_to_dict,
    write_json_report,
    write_markdown_report,
)
from api_security_scanner.scanner import Finding, ScanResult


def _result():
    return ScanResult(
        target="http://127.0.0.1:8765",
        started_at="2026-11-12T04:00:00Z",
        finished_at="2026-11-12T04:00:01Z",
        duration_seconds=1.0,
        findings=[
            Finding(check="broken-auth", title="Broken authentication",
                    severity="High", endpoint="/api/users", method="GET",
                    evidence="Unauthenticated GET returned HTTP 200",
                    recommendation="Require authentication."),
            Finding(check="missing-header", title="Missing security header: X-Frame-Options",
                    severity="Low", endpoint="/", method="GET",
                    evidence="No 'X-Frame-Options' header.",
                    recommendation="Add 'X-Frame-Options: DENY'."),
        ],
        checked_endpoints=[{"method": "GET", "path": "/api/users", "public": False}],
        notes=["BOLA check skipped: no --token-a supplied."],
    )


def test_report_dict_summary_counts():
    data = report_to_dict(_result())
    assert data["summary"] == {"total": 2, "High": 1, "Medium": 0, "Low": 1}
    assert data["target"] == "http://127.0.0.1:8765"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] == "High"


def test_json_report_round_trips(tmp_path):
    path = tmp_path / "report.json"
    write_json_report(_result(), str(path))
    data = json.loads(path.read_text())
    assert data["summary"]["High"] == 1
    assert data["findings"][1]["check"] == "missing-header"


def test_markdown_report_contains_findings(tmp_path):
    path = tmp_path / "report.md"
    write_markdown_report(_result(), str(path))
    text = path.read_text()
    assert "# API Security Scan Report" in text
    assert "http://127.0.0.1:8765" in text
    assert "| High | 1 |" in text
    assert "Broken authentication" in text
    assert "Missing security header: X-Frame-Options" in text
    assert "Unauthenticated GET returned HTTP 200" in text
    assert "authorised to test" in text


def test_markdown_report_empty_findings(tmp_path):
    result = _result()
    result.findings = []
    path = tmp_path / "report.md"
    write_markdown_report(result, str(path))
    text = path.read_text()
    assert "No findings" in text
    assert "| **Total** | **0** |" in text
