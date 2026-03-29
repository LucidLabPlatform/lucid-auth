#!/usr/bin/env python3
"""LUCID Auth — EMQX credential management CLI.

Manages MQTT credentials directly via the EMQX management API.

Usage:
    python manage.py add-agent <agent_id>       Provision agent credentials
    python manage.py revoke-agent <agent_id>    Revoke agent credentials
    python manage.py list-agents                List all provisioned agents

    python manage.py add-cc                     Provision central-command credentials
    python manage.py revoke-cc                  Revoke central-command credentials

    python manage.py add-user <username>        Provision LDAP researcher ACL
    python manage.py revoke-user <username>     Revoke researcher ACL
    python manage.py list-users                 List all researcher ACL entries

Environment variables:
    EMQX_URL        EMQX management API base URL  (default: http://localhost:18083)
    EMQX_USERNAME   EMQX dashboard username        (default: lucid)
    EMQX_PASSWORD   EMQX dashboard password        (default: REDACTED)
"""

import sys

import click

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


def _client() -> EMQXClient:
    """Create and return an authenticated EMQXClient, exiting on failure."""
    try:
        return EMQXClient()
    except Exception as exc:
        click.echo(f"ERROR: Could not connect to EMQX: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


@click.group()
def cli():
    """LUCID Auth — EMQX credential management."""


@cli.command("add-agent")
@click.argument("agent_id")
def cmd_add_agent(agent_id: str):
    """Provision MQTT credentials for an agent.

    Creates (or rotates) the built-in-database user and writes a per-user ACL
    restricting the agent to its own ``lucid/agents/<agent_id>/#`` namespace.
    Prints the generated password — copy it to the Pi's AGENT_PASSWORD env var.
    """
    client = _client()
    try:
        password = provision_agent(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' provisioned.")
    click.echo(f"Password: {password}")
    click.echo("(copy to Pi .env as AGENT_PASSWORD — shown only once)")


@cli.command("revoke-agent")
@click.argument("agent_id")
def cmd_revoke_agent(agent_id: str):
    """Revoke credentials and ACL for an agent."""
    client = _client()
    try:
        revoke_agent(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' revoked.")


@cli.command("list-agents")
def cmd_list_agents():
    """List all provisioned agents in the EMQX built-in database."""
    client = _client()
    try:
        agents = list_agents(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    if not agents:
        click.echo("(no agents)")
        return
    for agent in agents:
        user_id = agent.get("user_id") or agent.get("username", "?")
        click.echo(user_id)


# ---------------------------------------------------------------------------
# Central Command
# ---------------------------------------------------------------------------


@cli.command("add-cc")
def cmd_add_cc():
    """Provision MQTT credentials for central command (lucid-cc).

    Creates (or rotates) the lucid-cc built-in-database user with full
    publish+subscribe access to ``lucid/#``.
    """
    client = _client()
    try:
        password = provision_cc(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo("Central-command user 'lucid-cc' provisioned.")
    click.echo(f"Password: {password}")
    click.echo("(copy to .env as MQTT_PASSWORD — shown only once)")


@cli.command("revoke-cc")
def cmd_revoke_cc():
    """Revoke central-command credentials and ACL."""
    client = _client()
    try:
        revoke_cc(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo("Central-command user 'lucid-cc' revoked.")


# ---------------------------------------------------------------------------
# Researchers (LDAP-backed)
# ---------------------------------------------------------------------------


@cli.command("add-user")
@click.argument("username")
def cmd_add_user(username: str):
    """Provision subscribe-only ACL for an LDAP researcher.

    No password is stored in EMQX — authentication is handled by EMQX calling
    your LDAP server on each connect.  This command only writes the ACL entry.
    """
    client = _client()
    try:
        provision_user(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Researcher '{username}' ACL provisioned (subscribe lucid/#).")


@cli.command("revoke-user")
@click.argument("username")
def cmd_revoke_user(username: str):
    """Revoke a researcher's ACL entry."""
    client = _client()
    try:
        revoke_user(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Researcher '{username}' ACL revoked.")


@cli.command("list-users")
def cmd_list_users():
    """List all researcher ACL entries."""
    client = _client()
    try:
        users = list_users(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    if not users:
        click.echo("(no researchers)")
        return
    for user in users:
        uname = user.get("username") or user.get("user_id", "?")
        click.echo(uname)


if __name__ == "__main__":
    cli()
