"""Endpoint-list file + OpenAPI spec parsing."""

import json
import os

import pytest

from api_security_scanner.openapi import load_endpoints_from_spec, spec_to_endpoints
from api_security_scanner.scanner import parse_endpoints_file

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def test_parse_endpoints_file_basic():
    endpoints = parse_endpoints_file(
        "# comment\n\n"
        "GET /api/users\n"
        "POST /api/users\n"
        "GET /api/public/health public\n"
        "GET /api/users/{id}\n"
    )
    assert len(endpoints) == 4
    assert endpoints[0].method == "GET" and endpoints[0].path == "/api/users"
    assert endpoints[0].public is False
    assert endpoints[1].method == "POST"
    assert endpoints[2].public is True
    assert endpoints[3].path == "/api/users/{id}"


def test_parse_endpoints_file_rejects_bad_line():
    with pytest.raises(ValueError):
        parse_endpoints_file("GET\n")


def test_parse_endpoints_file_empty():
    assert parse_endpoints_file("# only comments\n") == []


def test_openapi_yaml_example():
    endpoints, base_url = load_endpoints_from_spec(
        os.path.join(EXAMPLES, "openapi.yaml"))
    assert base_url == "http://127.0.0.1:8765"
    by_path = {(e.method, e.path): e for e in endpoints}
    assert ("GET", "/api/users/{id}") in by_path
    assert ("GET", "/api/users/me") in by_path
    # security: [] in the spec means public by design.
    assert by_path[("GET", "/api/public/health")].public is True
    assert by_path[("GET", "/api/users")].public is False


def test_openapi_json_inline(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://127.0.0.1:9999"}],
        "paths": {
            "/api/items/{id}": {"get": {}, "delete": {}},
            "/api/open": {"get": {"security": []}},
        },
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec))
    endpoints, base_url = load_endpoints_from_spec(str(path))
    assert base_url == "http://127.0.0.1:9999"
    by_key = {(e.method, e.path): e for e in endpoints}
    assert ("DELETE", "/api/items/{id}") in by_key
    assert by_key[("GET", "/api/open")].public is True
    assert by_key[("GET", "/api/items/{id}")].public is False


def test_openapi_rejects_non_spec(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError):
        load_endpoints_from_spec(str(path))


def test_spec_to_endpoints_ignores_non_operations():
    endpoints = spec_to_endpoints({"paths": {"/x": {"parameters": [], "get": {}}}})
    assert len(endpoints) == 1
    assert endpoints[0].path == "/x"
