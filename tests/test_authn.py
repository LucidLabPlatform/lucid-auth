"""Provisioning tests for EMQX-native users and ACLs."""

from __future__ import annotations

from unittest.mock import MagicMock

import auth_client


def make_response(status_code: int, payload=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload or {}
    if status_code >= 400 and status_code != 409:
        resp.raise_for_status.side_effect = RuntimeError(f"HTTP {status_code}")
    else:
        resp.raise_for_status.return_value = None
    return resp


def test_provision_agent_creates_password_user_and_acl():
    client = MagicMock()
    client.post.return_value = make_response(201)
    client.put.return_value = make_response(200)

    password = auth_client.provision_agent(client, "robot-01")

    assert len(password) == 32
    client.post.assert_called_once_with(
        "/api/v5/authentication/password_based:built_in_database/users",
        {"user_id": "robot-01", "password": password, "is_superuser": False},
    )
    acl_path, acl_body = client.put.call_args.args
    assert acl_path == "/api/v5/authorization/sources/built_in_database/rules/users/robot-01"
    assert {"topic": "lucid/agents/robot-01/cmd/#", "action": "subscribe", "permission": "allow"} in acl_body["rules"]


def test_provision_agent_updates_existing_user_on_conflict():
    client = MagicMock()
    client.post.return_value = make_response(409)
    client.put.side_effect = [make_response(200), make_response(200)]

    password = auth_client.provision_agent(client, "robot-01")

    assert len(password) == 32
    update_path, update_body = client.put.call_args_list[0].args
    assert update_path == "/api/v5/authentication/password_based:built_in_database/users/robot-01"
    assert update_body == {"password": password}


def test_provision_cc_uses_bootstrap_username(monkeypatch):
    client = MagicMock()
    client.post.return_value = make_response(201)
    client.put.return_value = make_response(200)
    monkeypatch.setattr(auth_client, "BOOTSTRAP_CC_USER", "mission-control")

    password = auth_client.provision_cc(client, password="fixed-secret")

    assert password == "fixed-secret"
    client.post.assert_called_once_with(
        "/api/v5/authentication/password_based:built_in_database/users",
        {"user_id": "mission-control", "password": "fixed-secret", "is_superuser": False},
    )
    acl_path, acl_body = client.put.call_args.args
    assert acl_path == "/api/v5/authorization/sources/built_in_database/rules/users/mission-control"
    assert {"topic": "lucid/agents/+/cmd/#", "action": "publish", "permission": "allow"} in acl_body["rules"]


def test_provision_user_returns_namespace_acl():
    client = MagicMock()
    client.put.return_value = make_response(200)

    entry = auth_client.provision_user(client, "forfaly")

    assert entry == {"username": "forfaly", "topic_prefix": "lucid/researcher/forfaly/#"}
    client.put.assert_called_once()
    acl_path, acl_body = client.put.call_args.args
    assert acl_path == "/api/v5/authorization/sources/built_in_database/rules/users/forfaly"
    assert {"topic": "lucid/researcher/forfaly/#", "action": "all", "permission": "allow"} in acl_body["rules"]


def test_list_users_filters_to_researcher_entries(monkeypatch):
    client = MagicMock()
    client.get.return_value = make_response(
        200,
        {
            "data": [
                {"username": "robot-01", "rules": [{"topic": "lucid/agents/robot-01/status"}]},
                {"username": "central-command", "rules": [{"topic": "lucid/agents/+/cmd/#"}]},
                {"username": "forfaly", "rules": [{"topic": "lucid/researcher/forfaly/#"}]},
            ]
        },
    )
    monkeypatch.setattr(auth_client, "BOOTSTRAP_CC_USER", "central-command")

    users = auth_client.list_users(client)

    assert users == [{"username": "forfaly", "rules": [{"topic": "lucid/researcher/forfaly/#"}]}]


def test_provision_user_rejects_bad_username():
    try:
        auth_client.provision_user(MagicMock(), "bad/name")
    except ValueError as exc:
        assert "may only contain" in str(exc)
    else:
        raise AssertionError("expected ValueError")
