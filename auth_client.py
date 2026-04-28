"""EMQX credential and ACL management helpers for split ``lucid-auth``.

This service does not participate in MQTT auth at connection time.
Instead, it provisions EMQX-native resources so the broker can do:
- password auth from its built-in database for local users
- LDAP auth as the next authenticator in the chain
- built-in database authorization rules for per-user ACLs
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

EMQX_URL = os.environ.get("EMQX_URL", "http://localhost:18083").rstrip("/")
EMQX_USERNAME = os.environ.get("EMQX_USERNAME", "lucid")
EMQX_PASSWORD = os.environ.get("EMQX_PASSWORD", "REDACTED")
BOOTSTRAP_CC_USER = os.environ.get("BOOTSTRAP_CC_USER", "central-command")
BOOTSTRAP_CC_PASSWORD = os.environ.get("BOOTSTRAP_CC_PASSWORD", "")

AUTHN_SOURCE = "password_based:built_in_database"
AUTHZ_SOURCE = "built_in_database"
RESEARCH_TOPIC_ROOT = "lucid/researcher"
USERNAME_RE = r"^[A-Za-z0-9._-]+$"
AGENT_ID_RE = r"^[a-z0-9_]+$"


class EMQXClient:
    """Thin EMQX management API client with bearer-token auth."""

    def __init__(self) -> None:
        self._base = EMQX_URL
        self._token = self._login()

    def _login(self) -> str:
        last_error: Exception | None = None
        for _ in range(20):
            try:
                resp = httpx.post(
                    f"{self._base}/api/v5/login",
                    json={"username": EMQX_USERNAME, "password": EMQX_PASSWORD},
                    timeout=30,
                )
                resp.raise_for_status()
                payload = resp.json()
                return payload["token"]
            except Exception as exc:
                last_error = exc
                time.sleep(3)
        raise RuntimeError(f"Could not log in to EMQX after 20 attempts: {last_error}")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        resp = httpx.request(method, f"{self._base}{path}", headers=self._headers(), timeout=30, **kwargs)
        if resp.status_code == 401:
            self._token = self._login()
            resp = httpx.request(method, f"{self._base}{path}", headers=self._headers(), timeout=30, **kwargs)
        return resp

    def get(self, path: str) -> httpx.Response:
        return self._request("GET", path)

    def post(self, path: str, body: dict | list) -> httpx.Response:
        return self._request("POST", path, json=body)

    def put(self, path: str, body: dict) -> httpx.Response:
        return self._request("PUT", path, json=body)

    def delete(self, path: str) -> httpx.Response:
        return self._request("DELETE", path)


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _validate_principal_name(value: str, kind: str) -> str:
    if not value:
        raise ValueError(f"{kind} must not be empty")
    if not re.fullmatch(USERNAME_RE, value):
        raise ValueError(f"{kind} may only contain letters, numbers, '.', '_' or '-'")
    return value


def _validate_agent_id(value: str) -> str:
    if not value:
        raise ValueError("agent_id must not be empty")
    if not re.fullmatch(AGENT_ID_RE, value):
        raise ValueError("agent_id may only contain lowercase letters, numbers or '_'")
    return value


def _agent_rules(agent_id: str) -> list[dict]:
    base = f"lucid/agents/{agent_id}"
    comp = f"{base}/components/+"
    rules: list[dict] = [
        {"topic": f"{base}/cmd/#", "action": "subscribe", "permission": "allow"},
        {"topic": f"{comp}/cmd/#", "action": "subscribe", "permission": "allow"},
    ]
    for pattern in (
        f"{base}/status",
        f"{base}/state",
        f"{base}/metadata",
        f"{base}/cfg",
        f"{base}/cfg/logging",
        f"{base}/cfg/telemetry",
        f"{base}/schema",
        f"{base}/logs",
        f"{base}/telemetry/#",
        f"{base}/evt/#",
        f"{comp}/status",
        f"{comp}/state",
        f"{comp}/metadata",
        f"{comp}/cfg",
        f"{comp}/cfg/logging",
        f"{comp}/cfg/telemetry",
        f"{comp}/schema",
        f"{comp}/logs",
        f"{comp}/telemetry/#",
        f"{comp}/evt/#",
    ):
        rules.append({"topic": pattern, "action": "publish", "permission": "allow"})
    return rules


def _cc_rules(username: str) -> list[dict]:
    agent_ns = "lucid/agents/+"
    comp_ns = f"{agent_ns}/components/+"
    rules: list[dict] = []

    for pattern in (
        f"{agent_ns}/cmd/#",
        f"{comp_ns}/cmd/#",
        f"{RESEARCH_TOPIC_ROOT}/#",
    ):
        rules.append({"topic": pattern, "action": "publish", "permission": "allow"})

    for pattern in (
        f"{agent_ns}/status",
        f"{agent_ns}/state",
        f"{agent_ns}/metadata",
        f"{agent_ns}/cfg",
        f"{agent_ns}/cfg/logging",
        f"{agent_ns}/cfg/telemetry",
        f"{agent_ns}/schema",
        f"{agent_ns}/logs",
        f"{agent_ns}/telemetry/#",
        f"{agent_ns}/evt/#",
        f"{comp_ns}/status",
        f"{comp_ns}/state",
        f"{comp_ns}/metadata",
        f"{comp_ns}/cfg",
        f"{comp_ns}/cfg/logging",
        f"{comp_ns}/cfg/telemetry",
        f"{comp_ns}/schema",
        f"{comp_ns}/logs",
        f"{comp_ns}/telemetry/#",
        f"{comp_ns}/evt/#",
        f"{RESEARCH_TOPIC_ROOT}/#",
    ):
        rules.append({"topic": pattern, "action": "subscribe", "permission": "allow"})

    return rules


def _observer_rules(username: str) -> list[dict]:
    """Subscribe-only view of all agent/component data — no publish rights."""
    agent_ns = "lucid/agents/+"
    comp_ns = f"{agent_ns}/components/+"
    rules: list[dict] = []

    for pattern in (
        f"{agent_ns}/status",
        f"{agent_ns}/state",
        f"{agent_ns}/metadata",
        f"{agent_ns}/cfg",
        f"{agent_ns}/cfg/logging",
        f"{agent_ns}/cfg/telemetry",
        f"{agent_ns}/schema",
        f"{agent_ns}/logs",
        f"{agent_ns}/telemetry/#",
        f"{agent_ns}/evt/#",
        f"{comp_ns}/status",
        f"{comp_ns}/state",
        f"{comp_ns}/metadata",
        f"{comp_ns}/cfg",
        f"{comp_ns}/cfg/logging",
        f"{comp_ns}/cfg/telemetry",
        f"{comp_ns}/schema",
        f"{comp_ns}/logs",
        f"{comp_ns}/telemetry/#",
        f"{comp_ns}/evt/#",
        f"{RESEARCH_TOPIC_ROOT}/#",
    ):
        rules.append({"topic": pattern, "action": "subscribe", "permission": "allow"})

    return rules


def _researcher_rules(username: str) -> list[dict]:
    topic_root = f"{RESEARCH_TOPIC_ROOT}/{username}"
    return [
        {"topic": topic_root, "action": "all", "permission": "allow"},
        {"topic": f"{topic_root}/#", "action": "all", "permission": "allow"},
    ]


def _upsert_password_user(
    client: EMQXClient, username: str, password: str, is_superuser: bool = False
) -> None:
    path = f"/api/v5/authentication/{AUTHN_SOURCE}/users"
    resp = client.post(path, {"user_id": username, "password": password, "is_superuser": is_superuser})
    if resp.status_code == 409:
        resp = client.put(
            f"/api/v5/authentication/{AUTHN_SOURCE}/users/{_quote(username)}",
            {"password": password, "is_superuser": is_superuser},
        )
    resp.raise_for_status()


def _delete_password_user(client: EMQXClient, username: str) -> None:
    resp = client.delete(f"/api/v5/authentication/{AUTHN_SOURCE}/users/{_quote(username)}")
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


def _upsert_acl_rules(client: EMQXClient, username: str, rules: list[dict]) -> None:
    _delete_acl_rules(client, username)
    resp = client.post(
        f"/api/v5/authorization/sources/{AUTHZ_SOURCE}/rules/users",
        [{"username": username, "rules": rules}],
    )
    resp.raise_for_status()


def _delete_acl_rules(client: EMQXClient, username: str) -> None:
    resp = client.delete(f"/api/v5/authorization/sources/{AUTHZ_SOURCE}/rules/users/{_quote(username)}")
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


def provision_agent(client: EMQXClient, agent_id: str, password: str | None = None) -> str:
    agent_id = _validate_agent_id(agent_id)
    password = password or secrets.token_hex(16)
    _upsert_password_user(client, agent_id, password)
    _upsert_acl_rules(client, agent_id, _agent_rules(agent_id))
    return password


def revoke_agent(client: EMQXClient, agent_id: str) -> None:
    agent_id = _validate_principal_name(agent_id, "agent_id")
    _delete_password_user(client, agent_id)
    _delete_acl_rules(client, agent_id)


def list_agents(client: EMQXClient) -> list[dict]:
    resp = client.get(f"/api/v5/authentication/{AUTHN_SOURCE}/users")
    resp.raise_for_status()
    payload = resp.json()
    users = payload.get("data", payload) if isinstance(payload, dict) else payload
    rules_by_username = _extract_rules_by_username(client)
    return [
        item
        for item in users
        if isinstance(item, dict)
        and _infer_role(
            item.get("user_id") or item.get("username", ""),
            rules_by_username.get(item.get("user_id") or item.get("username", ""), []),
        )
        == "agent"
    ]


def provision_cc(client: EMQXClient, username: str | None = None, password: str | None = None) -> str:
    cc_username = _validate_principal_name(username or BOOTSTRAP_CC_USER, "username")
    password = password or secrets.token_hex(16)
    _upsert_password_user(client, cc_username, password)
    _upsert_acl_rules(client, cc_username, _cc_rules(cc_username))
    return password


def revoke_cc(client: EMQXClient, username: str | None = None) -> None:
    cc_username = _validate_principal_name(username or BOOTSTRAP_CC_USER, "username")
    _delete_password_user(client, cc_username)
    _delete_acl_rules(client, cc_username)


def provision_observer(client: EMQXClient, username: str, password: str | None = None) -> str:
    username = _validate_principal_name(username, "username")
    password = password or secrets.token_hex(16)
    _upsert_password_user(client, username, password)
    _upsert_acl_rules(client, username, _observer_rules(username))
    return password


def revoke_observer(client: EMQXClient, username: str) -> None:
    username = _validate_principal_name(username, "username")
    _delete_password_user(client, username)
    _delete_acl_rules(client, username)



def provision_superuser(client: EMQXClient, username: str, password: str | None = None) -> str:
    """Provision an MQTT superuser — bypasses all ACL."""
    username = _validate_principal_name(username, "username")
    password = password or secrets.token_hex(16)
    _upsert_password_user(client, username, password, is_superuser=True)
    return password


def revoke_superuser(client: EMQXClient, username: str) -> None:
    username = _validate_principal_name(username, "username")
    _delete_password_user(client, username)
    _delete_acl_rules(client, username)


def provision_user(client: EMQXClient, username: str) -> dict:
    username = _validate_principal_name(username, "username")
    _upsert_acl_rules(client, username, _researcher_rules(username))
    return {"username": username, "topic_prefix": f"{RESEARCH_TOPIC_ROOT}/{username}/#"}


def revoke_user(client: EMQXClient, username: str) -> None:
    username = _validate_principal_name(username, "username")
    _delete_acl_rules(client, username)


def list_users(client: EMQXClient) -> list[dict]:
    resp = client.get(f"/api/v5/authorization/sources/{AUTHZ_SOURCE}/rules/users")
    resp.raise_for_status()
    payload = resp.json()
    entries = payload.get("data", payload) if isinstance(payload, dict) else payload

    result: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        username = entry.get("username") or entry.get("user_id", "")
        if username == BOOTSTRAP_CC_USER:
            continue
        rules = entry.get("rules", [])
        topics = [rule.get("topic", "") for rule in rules if isinstance(rule, dict)]
        if any(topic.startswith(f"{RESEARCH_TOPIC_ROOT}/") for topic in topics):
            result.append(entry)
    return result


def _extract_rules_by_username(client: EMQXClient) -> dict[str, list[dict]]:
    resp = client.get(f"/api/v5/authorization/sources/{AUTHZ_SOURCE}/rules/users")
    resp.raise_for_status()
    payload = resp.json()
    entries = payload.get("data", payload) if isinstance(payload, dict) else payload

    rules_by_username: dict[str, list[dict]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        username = entry.get("username") or entry.get("user_id")
        if not username:
            continue
        rules = entry.get("rules", [])
        rules_by_username[username] = [rule for rule in rules if isinstance(rule, dict)]
    return rules_by_username


def _infer_role(username: str, rules: list[dict]) -> str:
    """Classify an EMQX user into the LUCID role taxonomy.

    Valid roles: agent, central-command, other.
    Superusers are not classified here — caller checks is_superuser first.
    """
    if username == BOOTSTRAP_CC_USER:
        return "central-command"

    topics = [str(rule.get("topic", "")) for rule in rules]

    # Agent: ACL rules scoped to its own subtree lucid/agents/<username>/
    if any(topic.startswith(f"lucid/agents/{username}/") for topic in topics):
        return "agent"

    # Central-command: rules covering fleet-wide command publish lucid/agents/+/cmd/
    if any(topic.startswith("lucid/agents/+/cmd/") for topic in topics):
        return "central-command"

    # Anything else (manual dashboard creates, observers, researchers — all
    # quarantined as 'other' for human review).
    return "other"


def get_mqtt_state(client: EMQXClient) -> dict:
    """Return a broker snapshot of password users and ACL rules.

    EMQX's built-in database remains the source of truth. This snapshot is
    intended to drive a synchronized Postgres mirror for UI/backend use.
    """

    users_resp = client.get(f"/api/v5/authentication/{AUTHN_SOURCE}/users")
    users_resp.raise_for_status()
    users_payload = users_resp.json()
    authn_users = users_payload.get("data", users_payload) if isinstance(users_payload, dict) else users_payload

    rules_by_username = _extract_rules_by_username(client)

    principals: list[dict] = []
    seen: set[str] = set()
    for item in authn_users:
        if not isinstance(item, dict):
            continue
        username = item.get("user_id") or item.get("username")
        if not username:
            continue
        rules = rules_by_username.get(username, [])
        # is_superuser overrides any ACL-pattern inference.
        if bool(item.get("is_superuser")):
            role = "superuser"
        else:
            role = _infer_role(username, rules)
        principals.append(
            {
                "username": username,
                "role": role,
                "has_password_user": True,
            }
        )
        seen.add(username)

    for username, rules in rules_by_username.items():
        if username in seen:
            continue
        principals.append(
            {
                "username": username,
                "role": _infer_role(username, rules),
                "has_password_user": False,
            }
        )

    acl_rules: list[dict] = []
    for principal in principals:
        username = principal["username"]
        for priority, rule in enumerate(rules_by_username.get(username, [])):
            acl_rules.append(
                {
                    "username": username,
                    "priority": priority,
                    "topic": rule.get("topic", ""),
                    "action": rule.get("action", ""),
                    "permission": rule.get("permission", ""),
                }
            )

    principals.sort(key=lambda item: (item["role"], item["username"]))
    acl_rules.sort(key=lambda item: (item["username"], item["priority"]))
    return {"principals": principals, "acl_rules": acl_rules}


def maybe_bootstrap_cc(client: EMQXClient) -> None:
    if BOOTSTRAP_CC_USER and BOOTSTRAP_CC_PASSWORD:
        provision_cc(client, username=BOOTSTRAP_CC_USER, password=BOOTSTRAP_CC_PASSWORD)
