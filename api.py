"""LUCID Auth — EMQX credential management REST API.

Internal/trusted service — no authentication required on the API itself.
Exposes endpoints for provisioning and revoking MQTT credentials via the
EMQX management API.

A single EMQXClient is created at startup (via FastAPI lifespan) and shared
across all requests as ``request.app.state.emqx``.

Endpoints:
    GET    /health              Liveness check.

    POST   /agents/{agent_id}  Provision agent; returns generated password.
    DELETE /agents/{agent_id}  Revoke agent credentials.
    GET    /agents             List all provisioned agents.

    POST   /cc                 Provision central-command; returns password.
    DELETE /cc                 Revoke central-command credentials.

    POST   /users/{username}   Provision LDAP researcher ACL.
    DELETE /users/{username}   Revoke researcher ACL.
    GET    /users              List all researcher ACL entries.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response

from auth_client import (
    EMQXClient,
    list_agents,
    list_users,
    provision_agent,
    provision_cc,
    provision_user,
    revoke_agent,
    revoke_cc,
    revoke_user,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create a single shared EMQXClient on startup."""
    app.state.emqx = EMQXClient()
    yield


app = FastAPI(title="lucid-auth", lifespan=lifespan)


def _emqx(request: Request) -> EMQXClient:
    return request.app.state.emqx


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    """Liveness check."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


@app.post("/agents/{agent_id}", status_code=201)
def create_agent(agent_id: str, request: Request):
    """Provision (or rotate) MQTT credentials for an agent.

    Returns the generated password — copy it to the Pi's AGENT_PASSWORD env var.
    """
    try:
        password = provision_agent(_emqx(request), agent_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"agent_id": agent_id, "password": password}


@app.delete("/agents/{agent_id}", status_code=204)
def delete_agent(agent_id: str, request: Request):
    """Revoke an agent's credentials and ACL."""
    try:
        revoke_agent(_emqx(request), agent_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


@app.get("/agents")
def get_agents(request: Request):
    """List all provisioned agents in the EMQX built-in database."""
    try:
        return list_agents(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ---------------------------------------------------------------------------
# Central Command
# ---------------------------------------------------------------------------


@app.post("/cc", status_code=201)
def create_cc(request: Request):
    """Provision (or rotate) central-command credentials.

    Returns the generated password for the ``lucid-cc`` MQTT user.
    """
    try:
        password = provision_cc(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"username": "lucid-cc", "password": password}


@app.delete("/cc", status_code=204)
def delete_cc(request: Request):
    """Revoke central-command credentials and ACL."""
    try:
        revoke_cc(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Researchers (LDAP-backed)
# ---------------------------------------------------------------------------


@app.post("/users/{username}", status_code=201)
def create_user(username: str, request: Request):
    """Provision subscribe-only ACL for an LDAP researcher.

    No password is stored in EMQX — EMQX authenticates the user via LDAP
    on each connect.  This endpoint only writes the authorisation rule.
    """
    try:
        provision_user(_emqx(request), username)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"username": username}


@app.delete("/users/{username}", status_code=204)
def delete_user(username: str, request: Request):
    """Revoke a researcher's ACL entry."""
    try:
        revoke_user(_emqx(request), username)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


@app.get("/users")
def get_users(request: Request):
    """List all researcher ACL entries."""
    try:
        return list_users(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
