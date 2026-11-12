# api-security-scanner

Async API security scanner (Python, `asyncio` + `httpx`). Give it a base URL
and an endpoint list — or an OpenAPI spec — and it tests the API for the
flaws that cause most real API breaches, then writes a JSON + Markdown report
with severity and evidence for every finding.

> **Scan only targets you are authorised to test.** Unauthorised scanning
> is illegal in most jurisdictions and will get your access revoked on bug
> bounty platforms. This tool is for your own APIs, client engagements with
> written scope, and authorised bug bounty targets.

## Features

- **(a) Broken authentication** — every endpoint is requested without a
  token; a `200` on an endpoint that should require auth is a High finding.
- **(b) BOLA / IDOR** — with two user identities (tokens + object ids), the
  scanner requests user B's object with user A's token and vice versa. A
  `200` on the other user's object is a High finding.
- **(c) Rate-limit probe** — sends N rapid requests (default 30) and reports
  when no `429` is ever returned.
- **(d) Verbose error / stack-trace disclosure** — probes a nonexistent path
  and a malformed `{id}` and flags responses containing stack traces or
  framework exception text.
- **(e) Security headers audit** — checks for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and `Permissions-Policy`.
- **(f) Dangerous HTTP methods** — sends `PUT`, `DELETE`, and `TRACE` and
  flags any that succeed (`200`/`201`/`204`) instead of `405`.
- **Reports** — `report.json` (machine-readable) and `report.md`
  (human-readable, grouped by severity) in the output directory.
- **Inputs** — a plain endpoint list (`METHOD /path [public]`, one per line)
  or an OpenAPI 3 JSON/YAML spec (operations with `security: []` are
  treated as public).
- **Local vulnerable test API** — a deliberately insecure `http.server`
  fixture (`src/api_security_scanner/fixture.py`) so every check can be
  verified against real positive and negative cases.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/tahiryounas604/api-security-scanner
cd api-security-scanner
pip install -r requirements.txt
# or: pip install -e .
```

## Usage

Start the test fixture (optional, for trying it out):

```bash
python -m api_security_scanner.fixture --port 8765
```

Scan with an endpoint list:

```bash
python -m api_security_scanner \
  --base-url http://127.0.0.1:8765 \
  --endpoints examples/endpoints.txt \
  --token-a token-user-1 --token-b token-user-2 \
  --rate-limit-endpoint /api/no-limit \
  --methods-path /api/resource \
  --output-dir ./report
```

Scan from an OpenAPI spec (uses `servers[0].url` if `--base-url` is omitted):

```bash
python -m api_security_scanner \
  --base-url https://api.example.com \
  --openapi examples/openapi.yaml \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  --output-dir ./report
```

Tokens can also come from the environment: `APISCAN_TOKEN_A`,
`APISCAN_TOKEN_B`.

Exit codes: `0` = scan ran, no High findings; `2` = one or more High
findings; `1` = usage or scan error.

### Endpoint list format

```
# lines starting with # are comments
GET /api/public/health public
GET /api/users
GET /api/users/{id}
```

`{id}` (or `{user_id}`) marks the object id used for BOLA testing
(`--user-a-id` / `--user-b-id`, defaults `1` / `2`). Endpoints marked
`public` are skipped by the broken-authentication check.

### Example report (against the local fixture)

```
Findings: 13 total (2 High, 5 Medium, 6 Low)
  [High] Broken authentication: endpoint reachable without a token — GET /api/users
  [High] BOLA / IDOR: another user's object is accessible — GET /api/users/{id}
  [Medium] No rate limiting observed on endpoint — GET /api/no-limit
  [Medium] Verbose error / stack trace disclosed — GET /api/users/'--
  [Medium] Dangerous HTTP method allowed: PUT — PUT /api/resource
  ...
```

## Tests

```bash
python3 -m pytest -v
```

Every check has positive and negative tests against the local fixture
(`tests/`). The suite must be fully green before any release is reported
as done.

## Known limits

- **Go prober: not included.** Go is not installed in the build environment,
  so v0.1 is pure Python. The Python prober is concurrent via `asyncio`;
  a Go concurrent prober is a future addition, not a silent gap.
- **No authenticated scanning beyond Bearer tokens.** Cookie/session auth,
  OAuth flows, and signed requests are not supported in v0.1.
- **BOLA needs two identities.** Without `--token-b` only the cross-id
  variant runs; without `--token-a` the BOLA check is skipped entirely.
- **Rate-limit probe is timing-blind.** It counts `429` responses over N
  rapid requests; slow or token-bucket limits with high thresholds may be
  missed, and a low `--rate-limit-requests` value weakens the test.
- **Header audit covers the site root** (falling back to the first endpoint
  if the root errors); it does not audit every endpoint's headers.
- **No proxy support.** The scanner ignores `HTTP(S)_PROXY` environment
  variables (`trust_env=False`) so localhost targets always connect
  directly.
- **No vulnerability database / CVE matching, no fuzzing, no auth bypass
  payloads beyond the six checks above.** A clean report means these six
  checks passed — it is not a guarantee the API is secure.
- **Only tested against the bundled local fixture** (Python 3.12,
  `httpx` 0.28, `pytest` 9). Real-world APIs have not been scanned with
  v0.1 yet.

## License

GPL-3.0. See [LICENSE](LICENSE).

## Author

Built by Tahir Younas — Penetration Tester & Application Security Engineer — https://www.linkedin.com/in/tahiryounas604 | Tytechlabs
