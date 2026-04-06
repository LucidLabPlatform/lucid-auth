"""Rule-generation tests for broker-native ACLs."""

from auth_client import _agent_rules, _cc_rules, _observer_rules, _researcher_rules


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


def test_observer_rules_subscribe_only():
    rules = _observer_rules("dashboard")
    actions = {rule["action"] for rule in rules}
    assert actions == {"subscribe"}, "Observer must only have subscribe rules"


def test_observer_rules_cover_same_topics_as_cc():
    observer = _observer_rules("dashboard")
    cc = _cc_rules("central-command")
    cc_sub_topics = {rule["topic"] for rule in cc if rule["action"] == "subscribe"}
    observer_topics = {rule["topic"] for rule in observer}
    assert observer_topics == cc_sub_topics


def test_researcher_rules_are_scoped_to_namespace():
    rules = _researcher_rules("forfaly")
    assert {"topic": "lucid/researcher/forfaly", "action": "all", "permission": "allow"} in rules
    assert {"topic": "lucid/researcher/forfaly/#", "action": "all", "permission": "allow"} in rules
