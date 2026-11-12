"""CLI for api-security-scanner.

Usage example::

    python -m api_security_scanner --base-url http://127.0.0.1:8765 \\
        --endpoints examples/endpoints.txt \\
        --token-a token-user-1 --token-b token-user-2 \\
        --output-dir ./report

Exit codes: 0 = scan ran, no High findings; 2 = one or more High
findings; 1 = usage / scan error.

Scan only targets you are authorised to test.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .openapi import load_endpoints_from_spec
from .report import write_json_report, write_markdown_report
from .scanner import ScanConfig, load_endpoints_file, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-security-scanner",
        description="Async API security scanner: broken auth, BOLA/IDOR, "
                    "rate limiting, verbose errors, security headers, "
                    "dangerous HTTP methods.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--base-url", required=False,
                        help="Target base URL, e.g. http://127.0.0.1:8765 "
                             "(optional if the OpenAPI spec has servers[0].url)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--endpoints",
                        help="Endpoint list file: one 'METHOD /path [public]' per line")
    source.add_argument("--openapi",
                        help="OpenAPI spec file (JSON or YAML)")
    parser.add_argument("--token-a",
                        default=os.environ.get("APISCAN_TOKEN_A"),
                        help="Bearer token for user A (or APISCAN_TOKEN_A)")
    parser.add_argument("--token-b",
                        default=os.environ.get("APISCAN_TOKEN_B"),
                        help="Bearer token for user B, for BOLA checks (or APISCAN_TOKEN_B)")
    parser.add_argument("--user-a-id", default="1", help="User A's object id (default: 1)")
    parser.add_argument("--user-b-id", default="2", help="User B's object id (default: 2)")
    parser.add_argument("--rate-limit-requests", type=int, default=30,
                        help="Rapid requests sent in the rate-limit probe (default: 30)")
    parser.add_argument("--rate-limit-endpoint",
                        help="Endpoint to probe for rate limiting (default: first endpoint)")
    parser.add_argument("--methods-path",
                        help="Path to probe for PUT/DELETE/TRACE (default: first endpoint)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--output-dir", default="./api-scan-report",
                        help="Directory for report.json and report.md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.endpoints:
            endpoints = load_endpoints_file(args.endpoints)
            base_url = args.base_url
        else:
            endpoints, spec_base = load_endpoints_from_spec(args.openapi)
            base_url = args.base_url or spec_base
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not base_url:
        print("error: --base-url is required (no servers[0].url in the spec).",
              file=sys.stderr)
        return 1
    if not endpoints:
        print("error: no endpoints found to scan.", file=sys.stderr)
        return 1
    if args.rate_limit_requests < 1:
        print("error: --rate-limit-requests must be >= 1.", file=sys.stderr)
        return 1

    config = ScanConfig(
        base_url=base_url,
        token_a=args.token_a,
        token_b=args.token_b,
        user_a_id=args.user_a_id,
        user_b_id=args.user_b_id,
        rate_limit_requests=args.rate_limit_requests,
        rate_limit_endpoint=args.rate_limit_endpoint,
        methods_probe_path=args.methods_path,
        timeout=args.timeout,
    )
    try:
        result = run_scan(config, endpoints)
    except Exception as exc:  # target unreachable etc.
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "report.json")
    md_path = os.path.join(args.output_dir, "report.md")
    write_json_report(result, json_path)
    write_markdown_report(result, md_path)

    summary = result.summary
    print(f"api-security-scanner v{__version__} — target {result.target}")
    print(f"Endpoints checked: {len(result.checked_endpoints)} "
          f"in {result.duration_seconds}s")
    print(f"Findings: {summary['total']} total "
          f"({summary['High']} High, {summary['Medium']} Medium, "
          f"{summary['Low']} Low)")
    for finding in result.findings:
        print(f"  [{finding.severity}] {finding.title} "
              f"— {finding.method} {finding.endpoint}")
    print(f"Reports written: {json_path}, {md_path}")
    return 2 if summary["High"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
