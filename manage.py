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
    provision_user,
    revoke_agent,
    revoke_cc,
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
def cmd_add_agent(agent_id: str):
    client = _client()
    try:
        password = provision_agent(client, agent_id)
    except Exception as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Agent '{agent_id}' provisioned.")
    click.echo(f"Password: {password}")
    click.echo(f"MQTT username/clientid: {agent_id}")
    click.echo("Auth: EMQX built-in database")
    click.echo(f"ACL: publish own lucid/agents/{agent_id}/... and subscribe own cmd topics")


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
