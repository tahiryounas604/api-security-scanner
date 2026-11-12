"""Core scanner: endpoint model, scan configuration, and the six checks.

Checks
  (a) broken authentication -- endpoints reachable without a token
  (b) BOLA / IDOR -- one user's token fetching another user's object
  (c) rate-limit probe -- N rapid requests, look for a 429
  (d) verbose error / stack-trace disclosure
  (e) security headers audit
  (f) dangerous HTTP methods (PUT / DELETE / TRACE)

All checks are real HTTP requests against the target. Nothing is mocked
here; the local test fixture (fixture.py) is only a target to run them
against. Scan only targets you are authorised to test.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

import httpx

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

SEVERITIES = ("High", "Medium", "Low", "Info")


@dataclass
class Endpoint:
    """One API operation to test."""

    method: str = "GET"
    path: str = "/"
    public: bool = False  # True = reachable without auth by design

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path


@dataclass
class Finding:
    check: str
    title: str
    severity: str  # High / Medium / Low
    endpoint: str
    method: str
    evidence: str
    recommendation: str

    @property
    def id(self) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", self.endpoint.lower()).strip("-")
        return f"{self.check}:{self.method}:{slug or 'root'}"


@dataclass
class ScanConfig:
    base_url: str
    token_a: str | None = None
    token_b: str | None = None
    user_a_id: str = "1"
    user_b_id: str = "2"
    rate_limit_requests: int = 30
    rate_limit_endpoint: str | None = None
    methods_probe_path: str | None = None
    timeout: float = 10.0
    concurrency: int = 5


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    checked_endpoints: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {"total": len(self.findings), "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Endpoint-list file parsing
# ---------------------------------------------------------------------------

def parse_endpoints_file(text: str) -> list[Endpoint]:
    """Parse an endpoint list file.

    One endpoint per line::

        METHOD /path [public]

    Blank lines and lines starting with ``#`` are ignored. ``{id}`` style
    path parameters are kept verbatim for BOLA testing.
    """
    endpoints: list[Endpoint] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"Bad endpoint line (need 'METHOD /path'): {raw_line!r}")
        method, path = parts[0], parts[1]
        public = len(parts) > 2 and parts[2].lower() == "public"
        endpoints.append(Endpoint(method=method, path=path, public=public))
    return endpoints


def load_endpoints_file(path: str) -> list[Endpoint]:
    with open(path, encoding="utf-8") as handle:
        return parse_endpoints_file(handle.read())


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

# Response-body markers that indicate a verbose error / stack trace leak.
ERROR_MARKERS = (
    "traceback (most recent call last)",
    "stack trace",
    "exception in thread",
    "java.lang.",
    "at com.",
    "at org.",
    "sql syntax",
    "psycopg2.",
    "valueerror:",
    "uncaught exception",
    "fatal error",
)

# Headers every API response should carry.
REQUIRED_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

HEADER_RECOMMENDATIONS = {
    "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    "Content-Security-Policy": "Add a restrictive 'Content-Security-Policy' header.",
    "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff'.",
    "X-Frame-Options": "Add 'X-Frame-Options: DENY' (or SAMEORIGIN).",
    "Referrer-Policy": "Add 'Referrer-Policy: no-referrer' (or strict-origin-when-cross-origin).",
    "Permissions-Policy": "Add a restrictive 'Permissions-Policy' header.",
}

DANGEROUS_METHODS = ("PUT", "DELETE", "TRACE")


class Scanner:
    """Runs the six checks against a live target."""

    def __init__(self, config: ScanConfig, endpoints: list[Endpoint]) -> None:
        self.config = config
        self.endpoints = endpoints
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self._client: httpx.AsyncClient | None = None
        self._owns_client = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Create a client on demand so individual checks work standalone.

        ``run()`` manages its own client; direct check calls (as the tests
        do) get a lazily created one, closed via :meth:`close`.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout, trust_env=False,
                follow_redirects=False)
            self._owns_client = True
        return self._client

    async def close(self) -> None:
        """Close a lazily created client, if any."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
        self._client = None
        self._owns_client = False

    # -- helpers ---------------------------------------------------------
    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + path

    def _auth_headers(self, token: str | None) -> dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _substitute_id(self, path: str, user_id: str) -> str:
        return path.replace("{id}", user_id).replace("{user_id}", user_id)

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)

    async def _request(self, method: str, path: str,
                       token: str | None = None) -> httpx.Response:
        client = await self._ensure_client()
        return await client.request(
            method, self._url(path),
            headers=self._auth_headers(token),
        )

    # -- check (a): broken authentication --------------------------------
    async def check_broken_auth(self) -> None:
        """An endpoint that requires auth must reject anonymous requests."""
        for endpoint in self.endpoints:
            if endpoint.public:
                continue
            path = self._substitute_id(endpoint.path, self.config.user_a_id)
            try:
                response = await self._request(endpoint.method, path)
            except httpx.HTTPError as exc:
                self.notes.append(f"Broken-auth probe {endpoint.method} {path} failed: {exc}")
                continue
            if response.status_code in (200, 201, 204):
                self._add(Finding(
                    check="broken-auth",
                    title="Broken authentication: endpoint reachable without a token",
                    severity="High",
                    endpoint=path,
                    method=endpoint.method,
                    evidence=(f"Unauthenticated {endpoint.method} {path} returned "
                              f"HTTP {response.status_code} with a "
                              f"{len(response.content)}-byte body."),
                    recommendation=("Require authentication on this endpoint and "
                                    "return 401/403 for anonymous requests."),
                ))

    # -- check (b): BOLA / IDOR ------------------------------------------
    async def check_bola(self) -> None:
        """One user's token must not fetch another user's object."""
        if not self.config.token_a:
            self.notes.append("BOLA check skipped: no --token-a supplied.")
            return
        for endpoint in self.endpoints:
            if "{id}" not in endpoint.path and "{user_id}" not in endpoint.path:
                continue
            own_path = self._substitute_id(endpoint.path, self.config.user_a_id)
            other_path = self._substitute_id(endpoint.path, self.config.user_b_id)
            try:
                baseline = await self._request(endpoint.method, own_path,
                                               token=self.config.token_a)
            except httpx.HTTPError as exc:
                self.notes.append(f"BOLA baseline {own_path} failed: {exc}")
                continue
            if baseline.status_code != 200:
                self.notes.append(
                    f"BOLA skipped for {endpoint.path}: baseline request as user A "
                    f"returned HTTP {baseline.status_code}, not 200.")
                continue
            variants: list[tuple[str, str]] = [
                ("user A's token + user B's id", other_path),
            ]
            evidence_lines = []
            leaked = False
            try:
                cross = await self._request(endpoint.method, other_path,
                                            token=self.config.token_a)
                if cross.status_code == 200 and cross.content:
                    leaked = True
                    evidence_lines.append(
                        f"User A's token + user B's id: HTTP 200, body "
                        f"{cross.text[:200]!r}")
            except httpx.HTTPError as exc:
                self.notes.append(f"BOLA cross-user probe {other_path} failed: {exc}")
            if self.config.token_b:
                variants.append(("user B's token + user A's id", own_path))
                try:
                    swapped = await self._request(endpoint.method, own_path,
                                                  token=self.config.token_b)
                    if swapped.status_code == 200 and swapped.content:
                        leaked = True
                        evidence_lines.append(
                            f"User B's token + user A's id: HTTP 200, body "
                            f"{swapped.text[:200]!r}")
                except httpx.HTTPError as exc:
                    self.notes.append(f"BOLA token-swap probe {own_path} failed: {exc}")
            if leaked:
                self._add(Finding(
                    check="bola",
                    title="BOLA / IDOR: another user's object is accessible",
                    severity="High",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence="; ".join(evidence_lines),
                    recommendation=("Enforce object-level authorisation on every "
                                    "request: verify the authenticated user owns "
                                    "the requested object id before returning it."),
                ))

    # -- check (c): rate limiting ----------------------------------------
    async def check_rate_limit(self, probe_path: str | None = None) -> None:
        """Send N rapid requests; a 429 means rate limiting works."""
        path = probe_path or self.config.rate_limit_endpoint
        if not path:
            if not self.endpoints:
                self.notes.append("Rate-limit check skipped: no endpoints given.")
                return
            path = self.endpoints[0].path
        path = self._substitute_id(path, self.config.user_a_id)
        total = self.config.rate_limit_requests
        statuses: list[int] = []
        for _ in range(total):
            try:
                response = await self._request("GET", path,
                                               token=self.config.token_a)
                statuses.append(response.status_code)
            except httpx.HTTPError as exc:
                self.notes.append(f"Rate-limit probe failed: {exc}")
                break
        saw_429 = 429 in statuses
        ok_count = sum(1 for status in statuses if status == 200)
        # Only flag when the endpoint actually answered (mostly 200s):
        # an endpoint returning 401/404 to every probe is not evidence
        # about rate limiting at all.
        if statuses and not saw_429 and ok_count * 2 >= len(statuses):
            self._add(Finding(
                check="rate-limit",
                title="No rate limiting observed on endpoint",
                severity="Medium",
                endpoint=path,
                method="GET",
                evidence=(f"Sent {len(statuses)} rapid GET requests to {path}: "
                          f"{ok_count} returned HTTP 200 and none returned 429."),
                recommendation=("Enforce per-user / per-IP rate limiting on this "
                                "endpoint and return HTTP 429 with Retry-After "
                                "when the limit is exceeded."),
            ))
        elif saw_429:
            self.notes.append(
                f"Rate limiting works on {path}: HTTP 429 seen after "
                f"{statuses.index(429) + 1} rapid requests.")

    # -- check (d): verbose errors ----------------------------------------
    async def check_verbose_errors(self, probe_paths: list[str] | None = None) -> None:
        """Look for stack traces / verbose errors in responses."""
        paths = probe_paths if probe_paths is not None else []
        if not paths:
            paths = ["/__api_security_scanner_probe_nonexistent__"]
            for endpoint in self.endpoints:
                if "{id}" in endpoint.path or "{user_id}" in endpoint.path:
                    # A malformed id often triggers an unhandled exception.
                    paths.append(self._substitute_id(endpoint.path, "'--"))
        for path in paths:
            try:
                response = await self._request("GET", path,
                                               token=self.config.token_a)
            except httpx.HTTPError as exc:
                self.notes.append(f"Verbose-error probe {path} failed: {exc}")
                continue
            body_lower = response.text.lower()
            hits = [marker for marker in ERROR_MARKERS if marker in body_lower]
            if hits and response.status_code >= 400:
                snippet = response.text[:300].replace("\n", " ")
                self._add(Finding(
                    check="verbose-error",
                    title="Verbose error / stack trace disclosed",
                    severity="Medium",
                    endpoint=path,
                    method="GET",
                    evidence=(f"GET {path} returned HTTP {response.status_code} "
                              f"containing {hits}: {snippet!r}"),
                    recommendation=("Return a generic error message to clients "
                                    "and log the full stack trace server-side only."),
                ))

    # -- check (e): security headers --------------------------------------
    async def check_security_headers(self, probe_urls: list[str] | None = None) -> None:
        """Every response should carry the standard security headers."""
        urls = probe_urls
        if urls is None:
            urls = [self._url("/")]
            try:
                root = await self._request("GET", "/")
                if root.status_code >= 400 and self.endpoints:
                    urls = [self._url(self._substitute_id(
                        self.endpoints[0].path, self.config.user_a_id))]
            except httpx.HTTPError as exc:
                self.notes.append(f"Security-header probe of / failed: {exc}")
                if self.endpoints:
                    urls = [self._url(self._substitute_id(
                        self.endpoints[0].path, self.config.user_a_id))]
        client = await self._ensure_client()
        for url in urls:
            try:
                response = await client.get(
                    url, headers=self._auth_headers(self.config.token_a))
            except httpx.HTTPError as exc:
                self.notes.append(f"Security-header probe {url} failed: {exc}")
                continue
            for header in REQUIRED_HEADERS:
                if header not in response.headers:
                    self._add(Finding(
                        check="missing-header",
                        title=f"Missing security header: {header}",
                        severity="Low",
                        endpoint=url.replace(self.config.base_url.rstrip("/"), "") or "/",
                        method="GET",
                        evidence=(f"GET {url} returned HTTP {response.status_code} "
                                  f"without a '{header}' header."),
                        recommendation=HEADER_RECOMMENDATIONS[header],
                    ))

    # -- check (f): dangerous HTTP methods --------------------------------
    async def check_dangerous_methods(self, probe_path: str | None = None) -> None:
        """PUT / DELETE / TRACE should not succeed on read-only resources."""
        path = probe_path or self.config.methods_probe_path
        if not path:
            if not self.endpoints:
                self.notes.append("Dangerous-methods check skipped: no endpoints given.")
                return
            path = self.endpoints[0].path
        path = self._substitute_id(path, self.config.user_a_id)
        for method in DANGEROUS_METHODS:
            try:
                response = await self._request(method, path,
                                               token=self.config.token_a)
            except httpx.HTTPError as exc:
                self.notes.append(f"{method} probe {path} failed: {exc}")
                continue
            if response.status_code in (200, 201, 204):
                self._add(Finding(
                    check="dangerous-method",
                    title=f"Dangerous HTTP method allowed: {method}",
                    severity="Medium",
                    endpoint=path,
                    method=method,
                    evidence=(f"{method} {path} returned HTTP {response.status_code} "
                              f"with a {len(response.content)}-byte body."),
                    recommendation=(f"Disable {method} on this resource (return 405) "
                                    "unless the API genuinely needs it, and require "
                                    "authentication + authorisation for state-changing methods."),
                ))

    # -- full run ----------------------------------------------------------
    async def run(self) -> ScanResult:
        started = time.time()
        started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started))
        # trust_env=False: never route scan traffic through a local proxy
        # (proxies break localhost targets and leak scan traffic).
        async with httpx.AsyncClient(timeout=self.config.timeout,
                                     trust_env=False,
                                     follow_redirects=False) as client:
            self._client = client
            await self.check_broken_auth()
            await self.check_bola()
            await self.check_rate_limit()
            await self.check_verbose_errors()
            await self.check_security_headers()
            await self.check_dangerous_methods()
        self._client = None
        finished = time.time()
        return ScanResult(
            target=self.config.base_url,
            started_at=started_iso,
            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
            duration_seconds=round(finished - started, 2),
            findings=self.findings,
            checked_endpoints=[
                {"method": ep.method, "path": ep.path, "public": ep.public}
                for ep in self.endpoints
            ],
            notes=self.notes,
        )


def run_scan(config: ScanConfig, endpoints: list[Endpoint]) -> ScanResult:
    """Synchronous wrapper: run the full async scan."""
    return asyncio.run(Scanner(config, endpoints).run())
