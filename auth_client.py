"""EMQX credential management client for LUCID.

Thin wrapper around the EMQX management API (v5).  Handles login with retry
and exposes idempotent helper functions for managing agent, central-command,
and researcher credentials.

Environment variables:
    EMQX_URL        EMQX management API base URL  (default: http://localhost:18083)
    EMQX_USERNAME   EMQX dashboard username        (default: lucid)
    EMQX_PASSWORD   EMQX dashboard password        (default: REDACTED)
"""

import os
import secrets
import time

import httpx

EMQX_URL = os.environ.get("EMQX_URL", "http://localhost:18083")
EMQX_USERNAME = os.environ.get("EMQX_USERNAME", "lucid")
EMQX_PASSWORD = os.environ.get("EMQX_PASSWORD", "REDACTED")

_AUTH_SOURCE = "password_based:built_in_database"


# ---------------------------------------------------------------------------
# EMQXClient
# ---------------------------------------------------------------------------


class EMQXClient:
    """Thin EMQX management API client with Bearer-token auth."""

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
                return resp.json()["token"]
            except Exception as exc:
                last_error = exc
                time.sleep(3)
        raise RuntimeError(f"Could not log in to EMQX after 20 attempts: {last_error}")

    def _h(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def get(self, path: str) -> httpx.Response:
        return httpx.get(f"{self._base}{path}", headers=self._h(), timeout=30)

    def post(self, path: str, body: dict) -> httpx.Response:
        return httpx.post(f"{self._base}{path}", json=body, headers=self._h(), timeout=30)

    def put(self, path: str, body: dict) -> httpx.Response:
        return httpx.put(f"{self._base}{path}", json=body, headers=self._h(), timeout=30)

    def delete(self, path: str) -> httpx.Response:
        return httpx.delete(f"{self._base}{path}", headers=self._h(), timeout=30)


# ---------------------------------------------------------------------------
# Helpers — agents
# ---------------------------------------------------------------------------


def provision_agent(client: EMQXClient, agent_id: str) -> str:
    """Create or update agent credentials in EMQX built-in database.

    Generates a fresh 32-char hex password, upserts the user record, then
    writes a per-user ACL rule restricting the agent to its own namespace.

    Args:
        client:   Authenticated EMQXClient.
        agent_id: Unique agent identifier (used as MQTT username).

    Returns:
        The newly generated plaintext password (shown once — not stored).
    """
    password = secrets.token_hex(16)

    # Upsert user — try create first, update on conflict
    resp = client.post(
        f"/api/v5/authentication/{_AUTH_SOURCE}/users",
        {"user_id": agent_id, "password": password, "is_superuser": False},
    )
    if resp.status_code == 409:
        resp = client.put(
            f"/api/v5/authentication/{_AUTH_SOURCE}/users/{agent_id}",
            {"password": password},
        )
    resp.raise_for_status()

    # Upsert per-user ACL
    client.put(
        f"/api/v5/authorization/sources/built_in_database/rules/users/{agent_id}",
        {
            "rules": [
                {
                    "topic": f"lucid/agents/{agent_id}/#",
                    "action": "all",
                    "permission": "allow",
                }
            ]
        },
    ).raise_for_status()

    return password


def revoke_agent(client: EMQXClient, agent_id: str) -> None:
    """Remove agent credentials and ACL from EMQX.

    Idempotent — ignores 404 responses.

    Args:
        client:   Authenticated EMQXClient.
        agent_id: Agent identifier to remove.
    """
    resp = client.delete(
        f"/api/v5/authentication/{_AUTH_SOURCE}/users/{agent_id}"
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()

    resp = client.delete(
        f"/api/v5/authorization/sources/built_in_database/rules/users/{agent_id}"
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


def list_agents(client: EMQXClient) -> list[dict]:
    """List all users in the EMQX built-in database, excluding lucid-cc.

    Args:
        client: Authenticated EMQXClient.

    Returns:
        List of user dicts as returned by the EMQX API.
    """
    resp = client.get(f"/api/v5/authentication/{_AUTH_SOURCE}/users")
    resp.raise_for_status()
    data = resp.json()
    users = data.get("data", data) if isinstance(data, dict) else data
    return [u for u in users if u.get("user_id") != "lucid-cc"]


# ---------------------------------------------------------------------------
# Helpers — central command
# ---------------------------------------------------------------------------


def provision_cc(client: EMQXClient) -> str:
    """Create or update central-command credentials in EMQX built-in database.

    The CC user is stored under the fixed username ``lucid-cc`` and is granted
    publish+subscribe access to the entire ``lucid/#`` namespace.

    Args:
        client: Authenticated EMQXClient.

    Returns:
        The newly generated plaintext password.
    """
    password = secrets.token_hex(16)

    resp = client.post(
        f"/api/v5/authentication/{_AUTH_SOURCE}/users",
        {"user_id": "lucid-cc", "password": password, "is_superuser": False},
    )
    if resp.status_code == 409:
        resp = client.put(
            f"/api/v5/authentication/{_AUTH_SOURCE}/users/lucid-cc",
            {"password": password},
        )
    resp.raise_for_status()

    client.put(
        "/api/v5/authorization/sources/built_in_database/rules/users/lucid-cc",
        {
            "rules": [
                {
                    "topic": "lucid/#",
                    "action": "all",
                    "permission": "allow",
                }
            ]
        },
    ).raise_for_status()

    return password


def revoke_cc(client: EMQXClient) -> None:
    """Remove central-command credentials and ACL from EMQX.

    Idempotent — ignores 404 responses.

    Args:
        client: Authenticated EMQXClient.
    """
    resp = client.delete(
        f"/api/v5/authentication/{_AUTH_SOURCE}/users/lucid-cc"
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()

    resp = client.delete(
        "/api/v5/authorization/sources/built_in_database/rules/users/lucid-cc"
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Helpers — researchers (LDAP-backed, ACL only)
# ---------------------------------------------------------------------------


def provision_user(client: EMQXClient, username: str) -> None:
    """Add a subscribe-only ACL entry for an LDAP-backed researcher.

    No password is stored in EMQX — authentication is handled by EMQX calling
    LDAP directly on each connect.  This function only writes the authorisation
    rule.

    Args:
        client:   Authenticated EMQXClient.
        username: LDAP username to grant researcher access.
    """
    client.put(
        f"/api/v5/authorization/sources/built_in_database/rules/users/{username}",
        {
            "rules": [
                {
                    "topic": "lucid/#",
                    "action": "subscribe",
                    "permission": "allow",
                }
            ]
        },
    ).raise_for_status()


def revoke_user(client: EMQXClient, username: str) -> None:
    """Remove a researcher's ACL entry from EMQX.

    Idempotent — ignores 404 responses.

    Args:
        client:   Authenticated EMQXClient.
        username: LDAP username whose ACL should be removed.
    """
    resp = client.delete(
        f"/api/v5/authorization/sources/built_in_database/rules/users/{username}"
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


def list_users(client: EMQXClient) -> list[dict]:
    """List researcher ACL entries from the EMQX built-in database.

    Filters out ``lucid-cc`` and any entry whose username matches an agent
    (i.e. has an ACL topic of ``lucid/agents/{id}/#``).

    Args:
        client: Authenticated EMQXClient.

    Returns:
        List of per-user ACL rule dicts for researchers.
    """
    resp = client.get(
        "/api/v5/authorization/sources/built_in_database/rules/users"
    )
    resp.raise_for_status()
    data = resp.json()
    entries = data.get("data", data) if isinstance(data, dict) else data

    result = []
    for entry in entries:
        uname = entry.get("username") or entry.get("user_id", "")
        if uname == "lucid-cc":
            continue
        # Skip agents — their ACL topic is lucid/agents/<id>/#
        rules = entry.get("rules", [])
        if any(
            r.get("topic", "").startswith("lucid/agents/")
            for r in rules
        ):
            continue
        result.append(entry)
    return result
