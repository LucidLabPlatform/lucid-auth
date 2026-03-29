"""Tests for agent and CC credential provisioning."""
import pytest
from unittest.mock import call
from auth_client import provision_agent, provision_cc, revoke_agent, revoke_cc, list_agents
from tests.conftest import make_response


def test_provision_agent_creates_new_user(mock_client):
    mock_client.post.return_value = make_response(201)
    mock_client.put.return_value = make_response(200)

    password = provision_agent(mock_client, "pi-001")

    assert len(password) == 32
    mock_client.post.assert_called_once()
    post_args = mock_client.post.call_args
    assert "pi-001" in post_args[0][0]
    assert post_args[1]["user_id"] == "pi-001" if len(post_args) > 1 else True


def test_provision_agent_upserts_on_conflict(mock_client):
    mock_client.post.return_value = make_response(409)
    mock_client.put.return_value = make_response(200)

    password = provision_agent(mock_client, "pi-001")

    assert len(password) == 32
    # Should fall back to PUT on 409
    mock_client.put.assert_called()


def test_provision_agent_sets_acl(mock_client):
    mock_client.post.return_value = make_response(201)
    mock_client.put.return_value = make_response(200)

    provision_agent(mock_client, "pi-002")

    acl_call = mock_client.put.call_args
    acl_body = acl_call[0][1] if len(acl_call[0]) > 1 else acl_call[1]
    rules = acl_body.get("rules", []) if isinstance(acl_body, dict) else []
    topics = [r["topic"] for r in rules]
    assert "lucid/agents/pi-002/#" in topics


def test_provision_cc_sets_full_namespace_acl(mock_client):
    mock_client.post.return_value = make_response(201)
    mock_client.put.return_value = make_response(200)

    password = provision_cc(mock_client)

    assert len(password) == 32
    acl_call = mock_client.put.call_args
    acl_body = acl_call[0][1] if len(acl_call[0]) > 1 else acl_call[1]
    rules = acl_body.get("rules", []) if isinstance(acl_body, dict) else []
    topics = [r["topic"] for r in rules]
    assert "lucid/#" in topics


def test_revoke_agent_handles_404(mock_client):
    mock_client.delete.return_value = make_response(404)
    # Should not raise
    revoke_agent(mock_client, "pi-001")


def test_revoke_cc_handles_404(mock_client):
    mock_client.delete.return_value = make_response(404)
    revoke_cc(mock_client)


def test_list_agents_excludes_lucid_cc(mock_client):
    mock_client.get.return_value = make_response(200, {
        "data": [
            {"user_id": "pi-001"},
            {"user_id": "pi-002"},
            {"user_id": "lucid-cc"},
        ]
    })

    agents = list_agents(mock_client)

    assert len(agents) == 2
    assert all(a["user_id"] != "lucid-cc" for a in agents)
