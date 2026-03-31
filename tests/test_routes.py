"""Route tests for broker-native ``lucid-auth``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import api
from api import app


@pytest.fixture
def client(monkeypatch):
    emqx = MagicMock()
    monkeypatch.setattr(api, "EMQXClient", lambda: emqx)
    monkeypatch.setattr(api, "maybe_bootstrap_cc", lambda client: None)
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_agent_returns_password(client, monkeypatch):
    monkeypatch.setattr(api, "provision_agent", lambda emqx, agent_id: "generated-secret")
    resp = client.post("/agents/robot_01")
    assert resp.status_code == 201
    assert resp.json() == {"agent_id": "robot_01", "password": "generated-secret"}


def test_create_agent_returns_400_for_invalid_agent_id(client, monkeypatch):
    def bad_agent(_emqx, _agent_id):
        raise ValueError("agent_id may only contain lowercase letters, numbers or '_'")

    monkeypatch.setattr(api, "provision_agent", bad_agent)
    resp = client.post("/agents/robot-01")
    assert resp.status_code == 400
    assert resp.json() == {"detail": "agent_id may only contain lowercase letters, numbers or '_'"}


def test_get_agents(client, monkeypatch):
    monkeypatch.setattr(api, "list_agents", lambda emqx: [{"user_id": "robot-01"}])
    resp = client.get("/agents")
    assert resp.status_code == 200
    assert resp.json() == [{"user_id": "robot-01"}]


def test_create_cc_returns_password(client, monkeypatch):
    monkeypatch.setattr(api, "BOOTSTRAP_CC_USER", "mission-control")
    monkeypatch.setattr(api, "provision_cc", lambda emqx: "generated-secret")
    resp = client.post("/cc")
    assert resp.status_code == 201
    assert resp.json() == {"username": "mission-control", "password": "generated-secret"}


def test_create_user_returns_topic_prefix(client, monkeypatch):
    monkeypatch.setattr(
        api,
        "provision_user",
        lambda emqx, username: {"username": username, "topic_prefix": f"lucid/researcher/{username}/#"},
    )
    resp = client.post("/users/forfaly")
    assert resp.status_code == 201
    assert resp.json() == {"username": "forfaly", "topic_prefix": "lucid/researcher/forfaly/#"}


def test_get_users(client, monkeypatch):
    monkeypatch.setattr(api, "list_users", lambda emqx: [{"username": "forfaly"}])
    resp = client.get("/users")
    assert resp.status_code == 200
    assert resp.json() == [{"username": "forfaly"}]


def test_get_mqtt_state(client, monkeypatch):
    monkeypatch.setattr(
        api,
        "get_mqtt_state",
        lambda emqx: {"principals": [{"username": "robot_01"}], "acl_rules": []},
    )
    resp = client.get("/mqtt-state")
    assert resp.status_code == 200
    assert resp.json() == {"principals": [{"username": "robot_01"}], "acl_rules": []}
