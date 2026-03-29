"""Tests for researcher ACL management."""
from auth_client import provision_user, revoke_user, list_users
from tests.conftest import make_response


def test_provision_user_sets_subscribe_only_acl(mock_client):
    mock_client.put.return_value = make_response(200)

    provision_user(mock_client, "alice")

    acl_call = mock_client.put.call_args
    acl_body = acl_call[0][1] if len(acl_call[0]) > 1 else acl_call[1]
    rules = acl_body.get("rules", []) if isinstance(acl_body, dict) else []
    assert any(r["action"] == "subscribe" and r["topic"] == "lucid/#" for r in rules)


def test_provision_user_does_not_store_password(mock_client):
    mock_client.put.return_value = make_response(200)
    provision_user(mock_client, "alice")
    # Only PUT (ACL), no POST (auth database)
    mock_client.post.assert_not_called()


def test_revoke_user_handles_404(mock_client):
    mock_client.delete.return_value = make_response(404)
    revoke_user(mock_client, "alice")


def test_list_users_excludes_agents_and_cc(mock_client):
    mock_client.get.return_value = make_response(200, {
        "data": [
            {"username": "alice",    "rules": [{"topic": "lucid/#", "action": "subscribe"}]},
            {"username": "lucid-cc", "rules": [{"topic": "lucid/#", "action": "all"}]},
            {"username": "pi-001",   "rules": [{"topic": "lucid/agents/pi-001/#", "action": "all"}]},
        ]
    })

    users = list_users(mock_client)

    assert len(users) == 1
    assert users[0]["username"] == "alice"
