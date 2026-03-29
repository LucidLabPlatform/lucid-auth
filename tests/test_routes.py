"""Tests for FastAPI REST API routes."""
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from api import app
from auth_client import EMQXClient


@pytest.fixture
def client():
    """TestClient with a mocked EMQXClient on app.state."""
    mock_emqx = MagicMock(spec=EMQXClient)
    app.state.emqx = mock_emqx
    with TestClient(app) as c:
        yield c, mock_emqx


def test_health(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_agent_returns_password(client):
    c, mock_emqx = client
    with patch("api.provision_agent", return_value="abc123") as mock_provision:
        resp = c.post("/agents/pi-001")
    assert resp.status_code == 201
    body = resp.json()
    assert body["agent_id"] == "pi-001"
    assert body["password"] == "abc123"


def test_create_agent_502_on_emqx_error(client):
    c, _ = client
    with patch("api.provision_agent", side_effect=Exception("EMQX down")):
        resp = c.post("/agents/pi-001")
    assert resp.status_code == 502


def test_delete_agent_returns_204(client):
    c, _ = client
    with patch("api.revoke_agent"):
        resp = c.delete("/agents/pi-001")
    assert resp.status_code == 204


def test_get_agents(client):
    c, _ = client
    with patch("api.list_agents", return_value=[{"user_id": "pi-001"}]):
        resp = c.get("/agents")
    assert resp.status_code == 200
    assert resp.json()[0]["user_id"] == "pi-001"


def test_create_cc_returns_password(client):
    c, _ = client
    with patch("api.provision_cc", return_value="secret123"):
        resp = c.post("/cc")
    assert resp.status_code == 201
    assert resp.json()["username"] == "lucid-cc"
    assert resp.json()["password"] == "secret123"


def test_delete_cc_returns_204(client):
    c, _ = client
    with patch("api.revoke_cc"):
        resp = c.delete("/cc")
    assert resp.status_code == 204


def test_create_user_returns_username(client):
    c, _ = client
    with patch("api.provision_user"):
        resp = c.post("/users/alice")
    assert resp.status_code == 201
    assert resp.json()["username"] == "alice"


def test_delete_user_returns_204(client):
    c, _ = client
    with patch("api.revoke_user"):
        resp = c.delete("/users/alice")
    assert resp.status_code == 204


def test_get_users(client):
    c, _ = client
    with patch("api.list_users", return_value=[{"username": "alice"}]):
        resp = c.get("/users")
    assert resp.status_code == 200
    assert resp.json()[0]["username"] == "alice"
