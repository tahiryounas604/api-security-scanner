"""OpenAPI (Swagger) spec parsing: spec file -> endpoint list.

Supports JSON specs natively and YAML specs when PyYAML is installed.
An operation is treated as public only when it explicitly sets
``security: []``; everything else is assumed to require authentication.
"""

from __future__ import annotations

import json

from .scanner import Endpoint

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dependency
    yaml = None  # type: ignore[assignment]


def load_spec(path: str) -> dict:
    """Load an OpenAPI spec from a JSON or YAML file."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if path.endswith((".yaml", ".yml")):
        if yaml is None:
            raise RuntimeError(
                "YAML OpenAPI spec needs PyYAML: pip install pyyaml "
                "(or convert the spec to JSON).")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict) or "paths" not in data:
        raise ValueError(f"{path} does not look like an OpenAPI spec (no 'paths').")
    return data


def spec_to_endpoints(spec: dict) -> list[Endpoint]:
    """Convert a parsed OpenAPI spec dict into endpoints."""
    endpoints: list[Endpoint] = []
    http_methods = ("get", "put", "post", "delete", "patch", "head", "options")
    for path, operations in (spec.get("paths") or {}).items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue
            # Explicit empty security list = public by design.
            public = operation.get("security") == []
            endpoints.append(Endpoint(method=method, path=path, public=public))
    return endpoints


def load_endpoints_from_spec(path: str) -> tuple[list[Endpoint], str | None]:
    """Return (endpoints, base_url_hint). The hint comes from servers[0].url."""
    spec = load_spec(path)
    base_url = None
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        base_url = servers[0].get("url")
    return spec_to_endpoints(spec), base_url
