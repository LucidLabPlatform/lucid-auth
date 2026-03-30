"""REST API for provisioning EMQX-native MQTT users and ACLs."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response

from auth_client import (
    BOOTSTRAP_CC_USER,
    EMQXClient,
    list_agents,
    list_users,
    maybe_bootstrap_cc,
    provision_agent,
    provision_cc,
    provision_user,
    revoke_agent,
    revoke_cc,
    revoke_user,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.emqx = None
    app.state.cc_bootstrapped = False
    yield


app = FastAPI(title="lucid-auth", lifespan=lifespan)


def _emqx(request: Request) -> EMQXClient:
    client = getattr(request.app.state, "emqx", None)
    if client is None:
        client = EMQXClient()
        request.app.state.emqx = client
    if not getattr(request.app.state, "cc_bootstrapped", False):
        maybe_bootstrap_cc(client)
        request.app.state.cc_bootstrapped = True
    return client


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/agents/{agent_id}", status_code=201)
def create_agent(agent_id: str, request: Request):
    try:
        password = provision_agent(_emqx(request), agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"agent_id": agent_id, "password": password}


@app.delete("/agents/{agent_id}", status_code=204)
def delete_agent(agent_id: str, request: Request):
    try:
        revoke_agent(_emqx(request), agent_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


@app.get("/agents")
def get_agents(request: Request):
    try:
        return list_agents(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/cc", status_code=201)
def create_cc(request: Request):
    try:
        password = provision_cc(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"username": BOOTSTRAP_CC_USER, "password": password}


@app.delete("/cc", status_code=204)
def delete_cc(request: Request):
    try:
        revoke_cc(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


@app.post("/users/{username}", status_code=201)
def create_user(username: str, request: Request):
    try:
        return provision_user(_emqx(request), username)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.delete("/users/{username}", status_code=204)
def delete_user(username: str, request: Request):
    try:
        revoke_user(_emqx(request), username)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return Response(status_code=204)


@app.get("/users")
def get_users(request: Request):
    try:
        return list_users(_emqx(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
