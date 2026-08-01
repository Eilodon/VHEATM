from __future__ import annotations

import json

import pytest

from vheatm_control.session_store import SessionStore, SessionStoreError


def _digest(letter: str) -> str:
    return letter * 64


def test_cas_is_immutable_and_session_replays_with_idempotency(tmp_path) -> None:
    store = SessionStore(tmp_path / "evidence")
    object_id = store.put_object("test_artifact", {"value": 1})
    assert store.get_object(object_id) == {"value": 1}

    session_id = store.create_session(
        context_digest=_digest("a"), bundle_root=_digest("b"), session_root=_digest("c"),
        created_at="2026-08-01T00:00:00Z",
    )
    first = store.append_event(
        session_id, event_type="module_started", actor="test", data={"module_id": "MOD-TEST"},
        idempotency_key="module:MOD-TEST:start",
    )
    duplicate = store.append_event(
        session_id, event_type="module_started", actor="test", data={"module_id": "MOD-TEST"},
        idempotency_key="module:MOD-TEST:start",
    )
    assert duplicate == first
    with pytest.raises(SessionStoreError, match="reused"):
        store.append_event(
            session_id, event_type="module_finished", actor="test", data={"module_id": "MOD-TEST"},
            idempotency_key="module:MOD-TEST:start",
        )
    store.transition(session_id, "context_validated", actor="test", reason="validated", idempotency_key="state:validated")
    snapshot = store.resume(session_id, expected_session_root=_digest("c"))
    assert snapshot["state"] == "context_validated"
    assert snapshot["sequence"] == 3
    assert snapshot["events"][-1]["event_type"] == "state_transition"


def test_replay_detects_cas_tamper_and_journal_tamper(tmp_path) -> None:
    root = tmp_path / "evidence"
    store = SessionStore(root)
    object_id = store.put_object("test_artifact", {"value": 1})
    session_id = store.create_session(context_digest=_digest("a"), bundle_root=_digest("b"), session_root=_digest("c"))

    cas_path = root / "cas" / f"{object_id}.json"
    cas_path.write_text(json.dumps({"object_type": "test_artifact", "payload": {"value": 2}}), encoding="utf-8")
    with pytest.raises(SessionStoreError, match="integrity"):
        store.get_object(object_id)

    snapshot_id = store._session_row(session_id)["snapshot_id"]
    snapshot_path = root / "cas" / f"{snapshot_id}.json"
    snapshot_path.write_text(snapshot_path.read_text(encoding="utf-8").replace('"state":"created"', '"state":"blocked"'), encoding="utf-8")
    with pytest.raises(SessionStoreError, match="integrity"):
        store.resume(session_id)

    with store._connect() as connection:  # exercise the persisted journal tamper detector
        connection.execute("UPDATE events SET event_hash = ? WHERE session_id = ? AND sequence = 1", ("F" * 64, session_id))
    with pytest.raises(SessionStoreError, match="integrity"):
        store.resume(session_id)


def test_plan_attachment_is_monotonic_and_bound_to_session(tmp_path) -> None:
    store = SessionStore(tmp_path / "evidence")
    session_id = store.create_session(context_digest=_digest("a"), bundle_root=_digest("b"), session_root=_digest("c"))
    plan = {"plan_id": "PLN-" + "d" * 64, "plan_digest": _digest("d"), "session_root": _digest("c"), "plan_revision": 0}
    store.attach_plan(session_id, plan)
    assert store.resume(session_id)["current_plan_id"] is not None
    with pytest.raises(SessionStoreError, match="same plan revision"):
        store.attach_plan(session_id, {**plan, "plan_id": "PLN-" + "e" * 64, "plan_digest": _digest("e"), "plan_revision": 0})
    with pytest.raises(SessionStoreError, match="session_root"):
        store.attach_plan(session_id, {**plan, "plan_id": "PLN-" + "f" * 64, "plan_digest": _digest("f"), "session_root": _digest("x"), "plan_revision": 1})
