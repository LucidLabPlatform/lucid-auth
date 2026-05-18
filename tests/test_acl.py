"""Rule-generation tests for broker-native ACLs."""

from auth_client import (
    _agent_rules,
    _cc_rules,
    _infer_role,
    _observer_rules,
    _researcher_rules,
    _voice_agent_extra_rules,
    _voice_agent_rules,
)


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
    # Invariant: observer subscribes to exactly the set of topics cc subscribes
    # to.  Voice-agent adds a subscribe rule to both (observer + cc) and a
    # publish-only rule to cc that observer does not get.
    observer = _observer_rules("dashboard")
    cc = _cc_rules("central-command")
    cc_sub_topics = {rule["topic"] for rule in cc if rule["action"] == "subscribe"}
    observer_topics = {rule["topic"] for rule in observer}
    assert observer_topics == cc_sub_topics


def test_researcher_rules_are_scoped_to_namespace():
    rules = _researcher_rules("forfaly")
    assert {"topic": "lucid/researcher/forfaly", "action": "all", "permission": "allow"} in rules
    assert {"topic": "lucid/researcher/forfaly/#", "action": "all", "permission": "allow"} in rules


def test_voice_agent_rules_include_standard_agent_rules():
    voice = _voice_agent_rules("esp_box")
    for rule in _agent_rules("esp_box"):
        assert rule in voice, f"missing standard agent rule in voice-agent: {rule}"


def test_voice_agent_rules_include_voice_carveouts():
    voice = _voice_agent_rules("esp_box")
    assert {
        "topic": "lucid/agents/esp_box/components/ai_session/cmd/voice_round_trip",
        "action": "publish",
        "permission": "allow",
    } in voice
    assert {
        "topic": "lucid/agents/esp_box/components/ai_session/evt/voice_round_trip/result",
        "action": "subscribe",
        "permission": "allow",
    } in voice


def test_voice_agent_extra_rules_are_exactly_two():
    extras = _voice_agent_extra_rules("esp_box")
    assert len(extras) == 2
    assert {r["action"] for r in extras} == {"publish", "subscribe"}


def test_cc_rules_include_voice_mirror():
    cc = _cc_rules("central-command")
    assert {
        "topic": "lucid/agents/+/components/ai_session/cmd/voice_round_trip",
        "action": "subscribe",
        "permission": "allow",
    } in cc
    assert {
        "topic": "lucid/agents/+/components/ai_session/evt/voice_round_trip/result",
        "action": "publish",
        "permission": "allow",
    } in cc


def test_observer_rules_include_voice_subscribe_but_not_publish():
    observer = _observer_rules("dashboard")
    assert {
        "topic": "lucid/agents/+/components/ai_session/cmd/voice_round_trip",
        "action": "subscribe",
        "permission": "allow",
    } in observer
    # observer must remain subscribe-only.
    assert {rule["action"] for rule in observer} == {"subscribe"}


def test_infer_role_returns_voice_agent_for_voice_rules():
    rules = _voice_agent_rules("esp_box")
    assert _infer_role("esp_box", rules) == "voice-agent"


def test_infer_role_returns_agent_for_standard_rules():
    rules = _agent_rules("robot_01")
    assert _infer_role("robot_01", rules) == "agent"


def test_infer_role_voice_check_precedes_agent_check():
    # voice-agent rules are a superset of agent rules; classification must
    # land on voice-agent, not agent.
    rules = _voice_agent_rules("esp_box")
    role = _infer_role("esp_box", rules)
    assert role == "voice-agent"
    assert role != "agent"
