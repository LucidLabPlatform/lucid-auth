"""Rule-generation tests for broker-native ACLs."""

from auth_client import _agent_rules, _cc_rules, _researcher_rules


def test_agent_rules_subscribe_only_to_own_cmd():
    rules = _agent_rules("robot-01")
    assert {"topic": "lucid/agents/robot-01/cmd/#", "action": "subscribe", "permission": "allow"} in rules
    assert {
        "topic": "lucid/agents/robot-01/components/+/cmd/#",
        "action": "subscribe",
        "permission": "allow",
    } in rules


def test_agent_rules_publish_own_status_only():
    rules = _agent_rules("robot-01")
    assert {"topic": "lucid/agents/robot-01/status", "action": "publish", "permission": "allow"} in rules
    assert {"topic": "lucid/agents/robot-01/telemetry/#", "action": "publish", "permission": "allow"} in rules


def test_cc_rules_cover_global_cmd_and_data_paths():
    rules = _cc_rules("central-command")
    assert {"topic": "lucid/agents/+/cmd/#", "action": "publish", "permission": "allow"} in rules
    assert {"topic": "lucid/agents/+/status", "action": "subscribe", "permission": "allow"} in rules
    assert {"topic": "lucid/researcher/#", "action": "subscribe", "permission": "allow"} in rules


def test_researcher_rules_are_scoped_to_namespace():
    rules = _researcher_rules("forfaly")
    assert {"topic": "lucid/researcher/forfaly", "action": "all", "permission": "allow"} in rules
    assert {"topic": "lucid/researcher/forfaly/#", "action": "all", "permission": "allow"} in rules
