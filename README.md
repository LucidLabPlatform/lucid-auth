# lucid-auth

MQTT credential management service for the LUCID IoT fleet management platform.

Manages EMQX authentication and authorization via the EMQX management API (v5). Provides both a CLI (`manage.py`) and a REST API (`api.py`) for provisioning and revoking credentials.

---

## Credential Types

### 1. Agents

- **Auth:** EMQX built-in database (username + password)
- **Username:** `{agent_id}` (e.g. `pi-lab-01`)
- **Password:** Auto-generated 32-character hex string
- **ACL:** Publish and subscribe to `lucid/agents/{agent_id}/#` only

### 2. Central Command (`lucid-cc`)

- **Auth:** EMQX built-in database (username + password)
- **Username:** `lucid-cc` (fixed)
- **Password:** Auto-generated 32-character hex string
- **ACL:** Publish and subscribe to `lucid/#`

### 3. Researchers (LDAP-backed)

- **Auth:** LDAP — EMQX calls your LDAP server on each connect. No password stored here.
- **ACL:** Subscribe-only to `lucid/#`
- This service only writes the ACL rule; LDAP configuration is managed directly in EMQX.

---

## CLI

```bash
# Agents
python manage.py add-agent pi-lab-01       # provision → prints password (copy to Pi)
python manage.py revoke-agent pi-lab-01    # revoke credentials + ACL
python manage.py list-agents               # list all provisioned agents

# Central Command
python manage.py add-cc                    # provision lucid-cc → prints password
python manage.py revoke-cc                 # revoke lucid-cc

# Researchers (LDAP ACL only)
python manage.py add-user alice            # grant alice subscribe-only access
python manage.py revoke-user alice         # revoke alice's ACL
python manage.py list-users                # list all researcher ACL entries
```

Each command is **idempotent** — re-running `add-agent` rotates the password.

---

## REST API

Internal/trusted service — no authentication on the API itself.

| Method   | Path                 | Status | Body / Description                              |
|----------|----------------------|--------|-------------------------------------------------|
| `GET`    | `/health`            | 200    | `{"status": "ok"}`                              |
| `POST`   | `/agents/{agent_id}` | 201    | `{"agent_id": str, "password": str}`            |
| `DELETE` | `/agents/{agent_id}` | 204    | Revoke agent credentials                        |
| `GET`    | `/agents`            | 200    | `list[dict]` — all provisioned agents           |
| `POST`   | `/cc`                | 201    | `{"username": "lucid-cc", "password": str}`     |
| `DELETE` | `/cc`                | 204    | Revoke central-command credentials              |
| `POST`   | `/users/{username}`  | 201    | `{"username": str}` — provision LDAP ACL        |
| `DELETE` | `/users/{username}`  | 204    | Revoke researcher ACL                           |
| `GET`    | `/users`             | 200    | `list[dict]` — all researcher ACL entries       |

EMQX errors surface as `502` with a detail message.

---

## Environment Variables

| Variable        | Default                   | Description                        |
|-----------------|---------------------------|------------------------------------|
| `EMQX_URL`      | `http://localhost:18083`  | EMQX management API base URL       |
| `EMQX_USERNAME` | `lucid`                   | EMQX dashboard username            |
| `EMQX_PASSWORD` | `REDACTED`             | EMQX dashboard password            |

Copy `.env.example` to `.env` and fill in values for your deployment.

---

## Running the REST API

### Docker

```bash
docker build -t lucid-auth .
docker run --rm -p 8000:8000 \
  -e EMQX_URL=http://emqx:18083 \
  -e EMQX_USERNAME=lucid \
  -e EMQX_PASSWORD=REDACTED \
  lucid-auth
```

### Local (development)

```bash
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
```

API docs available at `http://localhost:8000/docs`.

---

## LDAP Note

LDAP authentication is configured **directly in EMQX** (not in this service). This service only manages the ACL rules for LDAP-authenticated users in the EMQX built-in authorization database. To grant a researcher MQTT access:

1. Ensure their account exists in your LDAP directory.
2. Configure EMQX to use your LDAP server as an authentication source.
3. Run `python manage.py add-user <username>` (or `POST /users/{username}`) to write their ACL rule.
