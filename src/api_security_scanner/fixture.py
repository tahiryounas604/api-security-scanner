"""Local vulnerable test API (test fixture only).

A deliberately insecure API built on Python's stdlib ``http.server`` so the
scanner's checks have real positive and negative cases to run against.
It is NOT a product and must never be exposed to a network: run it only on
127.0.0.1 while testing.

Run standalone::

    python -m api_security_scanner.fixture [--port 8765]

Or from tests::

    from api_security_scanner.fixture import start_test_server
    server, base_url = start_test_server()  # ephemeral port
    ...
    server.stop()

Users: id 1 (token ``token-user-1``), id 2 (token ``token-user-2``).

Deliberate vulnerabilities (positive cases):
  * GET /api/users            -- user list returned WITHOUT any token
  * GET /api/users/{id}       -- any valid token reads ANY user's record (BOLA)
  * GET /api/users/'--        -- malformed id -> 500 with a Python traceback
  * GET /api/debug/error      -- 500 with a Python traceback
  * GET /api/no-limit         -- never rate limited
  * PUT/DELETE/TRACE /api/resource -- all succeed (200)
  * Most responses carry NONE of the six security headers

Correctly-secured controls (negative cases):
  * GET /api/users/me, /api/admin/stats -- 401 without a token
  * GET /api/users/{id}/secure -- 403 when the id is not the caller's own
  * GET /api/debug/clean-error -- generic 500, no stack trace
  * GET /api/rate-limited      -- HTTP 429 after 5 rapid requests
  * GET /api/secure-headers    -- all six security headers present
  * PUT/DELETE/TRACE /api/locked-resource -- 405 Method Not Allowed
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

TOKEN_TO_USER = {"token-user-1": 1, "token-user-2": 2}

USERS = {
    1: {"id": 1, "name": "User One", "email": "one@example.test",
        "ssn": "111-11-1111"},
    2: {"id": 2, "name": "User Two", "email": "two@example.test",
        "ssn": "222-22-2222"},
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}

TRACEBACK_BODY = (
    "Traceback (most recent call last):\n"
    '  File "/app/api/users.py", line 42, in get_user\n'
    "    user_id = int(user_id)\n"
    "ValueError: invalid literal for int() with base 10: \"'--\"\n"
)

RATE_LIMIT_AFTER = 5


class FixtureHandler(BaseHTTPRequestHandler):
    """Request handler. Deliberately insecure in the places documented above."""

    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------
    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, status: int, payload, extra_headers: dict | None = None,
              content_type: str = "application/json") -> None:
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload).encode()
        elif isinstance(payload, str):
            body = payload.encode()
        else:
            body = payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _caller(self) -> int | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return TOKEN_TO_USER.get(auth[len("Bearer "):].strip())
        return None

    def _require_auth(self) -> int | None:
        user = self._caller()
        if user is None:
            self._send(401, {"error": "Unauthorized"})
            return None
        return user

    # -- routing ---------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, {"service": "api-security-scanner test fixture",
                             "version": "0.1.0"})
        elif path == "/api/public/health":
            self._send(200, {"status": "ok"})
        elif path == "/api/users":
            # VULN (broken auth): user list without any token.
            self._send(200, {"users": list(USERS.values())})
        elif path == "/api/users/me":
            user = self._require_auth()
            if user is not None:
                self._send(200, USERS[user])
        elif path == "/api/admin/stats":
            user = self._require_auth()
            if user is not None:
                self._send(200, {"users": 2, "requests": 1234})
        elif path == "/api/debug/error":
            # VULN (verbose error): full traceback in the response.
            self._send(500, TRACEBACK_BODY, content_type="text/plain")
        elif path == "/api/debug/clean-error":
            self._send(500, {"error": "Internal Server Error"})
        elif path == "/api/no-limit":
            # VULN (no rate limiting): always 200.
            self._send(200, {"ok": True})
        elif path == "/api/rate-limited":
            count = self.server.state["rate_limited_hits"]  # type: ignore[attr-defined]
            self.server.state["rate_limited_hits"] = count + 1  # type: ignore[attr-defined]
            if count >= RATE_LIMIT_AFTER:
                self._send(429, {"error": "Too Many Requests"},
                           extra_headers={"Retry-After": "60"})
            else:
                self._send(200, {"ok": True})
        elif path == "/api/secure-headers":
            self._send(200, {"ok": True}, extra_headers=SECURITY_HEADERS)
        elif path.startswith("/api/users/"):
            self._handle_user(path)
        else:
            self._send(404, {"error": "Not Found"})

    def _handle_user(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        # /api/users/{id} or /api/users/{id}/secure
        raw_id = parts[2] if len(parts) > 2 else ""
        secure = len(parts) > 3 and parts[3] == "secure"
        if not raw_id.isdigit():
            if secure:
                # SECURE control: the hardened route validates input first.
                self._send(400, {"error": "Invalid id"})
                return
            # VULN (verbose error): malformed id -> unhandled exception text.
            self._send(500, TRACEBACK_BODY, content_type="text/plain")
            return
        user_id = int(raw_id)
        caller = self._require_auth()
        if caller is None:
            return
        if user_id not in USERS:
            self._send(404, {"error": "User not found"})
            return
        if secure and caller != user_id:
            # SECURE control: ownership enforced.
            self._send(403, {"error": "Forbidden"})
            return
        # VULN (BOLA) on the plain route: any valid token reads any user.
        self._send(200, USERS[user_id])

    def _handle_writable(self, path: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if path == "/api/resource":
            # VULN (dangerous methods): state-changing methods succeed.
            self._send(200, {"ok": True, "method": self.command})
        elif path == "/api/locked-resource":
            # SECURE control: 405.
            self._send(405, {"error": "Method Not Allowed"})
        else:
            self._send(404, {"error": "Not Found"})

    def do_PUT(self):
        self._handle_writable(urlparse(self.path).path)

    def do_DELETE(self):
        self._handle_writable(urlparse(self.path).path)

    def do_TRACE(self):
        self._handle_writable(urlparse(self.path).path)

    def do_POST(self):
        self._handle_writable(urlparse(self.path).path)


class FixtureServer:
    """A running fixture instance on an ephemeral (or chosen) port."""

    def __init__(self, port: int = 0) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)
        self.httpd.daemon_threads = True
        self.httpd.state = {"rate_limited_hits": 0}  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        daemon=True)

    def start(self) -> "FixtureServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def reset_rate_limit(self) -> None:
        self.httpd.state["rate_limited_hits"] = 0  # type: ignore[attr-defined]

    def __enter__(self) -> "FixtureServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def start_test_server(port: int = 0) -> FixtureServer:
    """Start the fixture and return it (already serving)."""
    return FixtureServer(port).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the vulnerable test API fixture.")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = FixtureServer(args.port).start()
    print(f"Test fixture running at {server.base_url} (Ctrl+C to stop)")
    print("Tokens: token-user-1 (user 1), token-user-2 (user 2)")
    try:
        server._thread.join()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
