#!/usr/bin/env python3
"""CLI for provisioning EMQX-native MQTT users and ACLs."""

from __future__ import annotations

import sys

import click

from auth_client import (
    BOOTSTRAP_CC_USER,
    EMQXClient,
    list_agents,
    list_users,
    provision_agent,
    provision_cc,
    provision_langsam_client,
    provision_superuser,
    provision_observer,
    provision_user,
    provision_voice_agent,
    refresh_agent_acl,
    refresh_cc_acl,
    refresh_langsam_client_acl,
    refresh_voice_agent_acl,
    revoke_agent,
    revoke_cc,
    revoke_superuser,
    revoke_observer,
    revoke_user,
)


def _client() -> EMQXClient:
    try:
        return EMQXClient()
    except Exception as exc:
        click.echo(f"ERROR: Could not connect to EMQX: {exc}", err=True)
        sys.exit(1)


@click.group()
def cli():
    """LUCID auth provisioning CLI."""


@cli.command("add-agent")
@click.argument("agent_id")
@click.option(
    "--role",
    type=click.Choice(["agent", "voice", "langsam_client"]),
    default="agent",
    show_default=True,
    help=(
        "Role to provision under. "
        "'voice' adds the ai_session/voice_round_trip carve-out. "
        "'langsam_client' adds publish/subscribe rights to the langsam segmentation server."
    ),
)
def cmd_add_agent(agent_id: str, role: str):
    client = _client()
    try:
        if role == "voice":
            password = provision_voice_agent(client, agent_id)
        elif role == "langsam_client":
            password = provision_langsam_client(client, agent_id)
        else:
            password = provision_agent(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    role_label = {"voice": "voice-agent", "langsam_client": "langsam-client"}.get(role, "agent")
    click.echo(f"Agent '{agent_id}' provisioned. role={role_label}")
    click.echo(f"Password: {password}")
    click.echo(f"MQTT username: {agent_id}")
    click.echo(f"Typical MQTT clientid: lucid.agent.{agent_id}")
    click.echo("Auth: EMQX built-in database")
    if role == "voice":
        click.echo("ACL: standard agent rules + ai_session/voice_round_trip carve-out")
    elif role == "langsam_client":
        click.echo("ACL: standard agent rules + langsam cmd/segment publish + evt/segment/result subscribe")
    else:
        click.echo(f"ACL: publish own lucid/agents/{agent_id}/... and subscribe own cmd topics")


@cli.command("refresh-agent-acl")
@click.argument("agent_id")
def cmd_refresh_agent_acl(agent_id: str):
    """Reapply standard agent ACL rules without rotating the password."""
    client = _client()
    try:
        refresh_agent_acl(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' ACL refreshed (role=agent).")


@cli.command("refresh-voice-agent-acl")
@click.argument("agent_id")
def cmd_refresh_voice_agent_acl(agent_id: str):
    """Reapply voice-agent ACL rules without rotating the password."""
    client = _client()
    try:
        refresh_voice_agent_acl(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' ACL refreshed (role=voice-agent).")


@cli.command("refresh-langsam-client-acl")
@click.argument("agent_id")
def cmd_refresh_langsam_client_acl(agent_id: str):
    """Reapply langsam-client ACL rules without rotating the password."""
    client = _client()
    try:
        refresh_langsam_client_acl(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' ACL refreshed (role=langsam-client).")


@cli.command("refresh-cc-acl")
def cmd_refresh_cc_acl():
    """Reapply cc ACL rules without rotating the password."""
    client = _client()
    try:
        refresh_cc_acl(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"cc user '{BOOTSTRAP_CC_USER}' ACL refreshed.")


@cli.command("revoke-agent")
@click.argument("agent_id")
def cmd_revoke_agent(agent_id: str):
    client = _client()
    try:
        revoke_agent(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' revoked.")


@cli.command("list-agents")
def cmd_list_agents():
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
        click.echo(agent.get("user_id") or agent.get("username", "?"))


@cli.command("add-cc")
def cmd_add_cc():
    client = _client()
    try:
        password = provision_cc(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Central-command user '{BOOTSTRAP_CC_USER}' provisioned.")
    click.echo(f"Password: {password}")


@cli.command("revoke-cc")
def cmd_revoke_cc():
    client = _client()
    try:
        revoke_cc(client)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Central-command user '{BOOTSTRAP_CC_USER}' revoked.")


@cli.command("add-observer")
@click.argument("username")
def cmd_add_observer(username: str):
    client = _client()
    try:
        password = provision_observer(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Observer '{username}' provisioned.")
    click.echo(f"Password: {password}")
    click.echo(f"MQTT username: {username}")
    click.echo("Auth: EMQX built-in database")
    click.echo("ACL: subscribe-only to all agent/component data (no publish)")


@cli.command("revoke-observer")
@click.argument("username")
def cmd_revoke_observer(username: str):
    client = _client()
    try:
        revoke_observer(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Observer '{username}' revoked.")


@cli.command("add-superuser")
@click.argument("username")
@click.option("--password", default=None, help="Password (auto-generated if omitted)")
def cmd_add_superuser(username: str, password: str | None):
    """Provision a superuser MQTT account (bypasses all ACL)."""
    client = _client()
    try:
        password = provision_superuser(client, username, password)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Superuser '{username}' provisioned.")
    click.echo(f"Password: {password}")
    click.echo(f"MQTT username: {username}")
    click.echo("Auth: EMQX built-in database (is_superuser=true — bypasses all ACL)")


@cli.command("revoke-superuser")
@click.argument("username")
def cmd_revoke_superuser(username: str):
    """Revoke a superuser MQTT account."""
    client = _client()
    try:
        revoke_superuser(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Superuser '{username}' revoked.")


@cli.command("add-user")
@click.argument("username")
def cmd_add_user(username: str):
    client = _client()
    try:
        entry = provision_user(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Researcher '{username}' ACL provisioned.")
    click.echo("Auth: EMQX LDAP authenticator")
    click.echo(f"ACL namespace: {entry['topic_prefix']}")


@cli.command("revoke-user")
@click.argument("username")
def cmd_revoke_user(username: str):
    client = _client()
    try:
        revoke_user(client, username)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Researcher '{username}' revoked.")


@cli.command("list-users")
def cmd_list_users():
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
        click.echo(user.get("username") or user.get("user_id", "?"))


if __name__ == "__main__":
    cli()
