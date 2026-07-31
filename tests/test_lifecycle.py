import pytest

from vheatm_control.lifecycle import AuditLifecycle, LifecycleError


def test_happy_path_requires_explicit_transitions() -> None:
    lifecycle = AuditLifecycle("AUD-1")
    for target in ["context_validated", "planned", "running", "complete", "attested"]:
        lifecycle.transition(target, actor="agent", reason=f"advance to {target}", occurred_at="2026-07-31T00:00:00Z")
    document = lifecycle.to_document()
    assert document["state"] == "attested"
    assert [event["sequence"] for event in document["events"]] == [1, 2, 3, 4, 5]
    assert len({event["id"] for event in document["events"]}) == 5


def test_invalid_transition_is_rejected() -> None:
    lifecycle = AuditLifecycle("AUD-2")
    with pytest.raises(LifecycleError, match="invalid lifecycle transition"):
        lifecycle.transition("complete", actor="agent", reason="skip controls")


def test_replay_rejects_mutation_and_state_spoofing() -> None:
    lifecycle = AuditLifecycle("AUD-3")
    lifecycle.transition("context_validated", actor="agent", reason="validated", occurred_at="2026-07-31T00:00:00Z")
    document = lifecycle.to_document()
    assert AuditLifecycle.from_document(document).state == "context_validated"

    document["events"][0]["reason"] = "changed"
    with pytest.raises(LifecycleError, match="id mismatch"):
        AuditLifecycle.from_document(document)
