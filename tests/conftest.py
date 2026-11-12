"""Shared pytest fixtures: one local vulnerable API server per test session."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from api_security_scanner.fixture import start_test_server  # noqa: E402


@pytest.fixture(scope="session")
def fixture_server():
    server = start_test_server()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def base_url(fixture_server):
    return fixture_server.base_url
