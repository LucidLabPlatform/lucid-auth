"""Shared fixtures for lucid-auth tests."""
import pytest
from unittest.mock import MagicMock
from auth_client import EMQXClient


@pytest.fixture
def mock_client():
    """A mock EMQXClient that returns configurable responses."""
    client = MagicMock(spec=EMQXClient)
    return client


def make_response(status_code: int, json_body=None):
    """Build a mock httpx.Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp
