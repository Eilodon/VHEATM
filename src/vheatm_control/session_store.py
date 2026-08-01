from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .lifecycle import ALLOWED_TRANSITIONS


class SessionStoreError(ValueError):
    """Raised when a CAS object or resumable session is invalid or tampered with."""


_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_CAS_ID = re.compile(r"^CAS-[A-F0-9]{64}$")
_SESSION_ID = re.compile(r"^SES-[A-F0-9]{64}$")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SessionStoreError(f"value is not canonical JSON: {exc}") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _timestamp(value: str | None = None) -> str:
    result = value or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise SessionStoreError(f"invalid RFC 3339 timestamp: {result!r}") from exc
    if parsed.tzinfo is None:
        raise SessionStoreError("timestamps must include a timezone")
    return result


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SessionStoreError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _hash_event(event: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest().upper()


class SessionStore:
    """Local-first immutable CAS plus SQLite-WAL journal for resumable audits.

    The database is an index and concurrency coordinator. Canonical object bytes
    live in the filesystem CAS and are written with a temp-file/fsync/rename
    sequence. Journal events are committed atomically with the session snapshot.
    No provider, tool, network, or user instruction is executed by this class.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if self.root.exists() and not self.root.is_dir():
            raise SessionStoreError(f"session store root is not a directory: {self.root}")
        self.root.mkdir(parents=True, exist_ok=True)
        self.cas_root = self.root / "cas"
        self.cas_root.mkdir(exist_ok=True)
        self.database = self.root / "sessions.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    object_id TEXT PRIMARY KEY,
                    object_type TEXT NOT NULL,
                    content BLOB NOT NULL,
                    sha256 TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    context_digest TEXT NOT NULL,
                    bundle_root TEXT NOT NULL,
                    session_root TEXT NOT NULL,
                    state TEXT NOT NULL,
                    current_plan_id TEXT,
                    current_plan_digest TEXT,
                    plan_revision INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    last_event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    snapshot_id TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    data TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    PRIMARY KEY(session_id, sequence),
                    UNIQUE(session_id, idempotency_key)
                );
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(sessions)")}
            if "snapshot_id" not in columns:
                connection.execute("ALTER TABLE sessions ADD COLUMN snapshot_id TEXT")

    def _object_path(self, object_id: str) -> Path:
        if not _CAS_ID.fullmatch(object_id):
            raise SessionStoreError(f"invalid CAS object id: {object_id!r}")
        return self.cas_root / f"{object_id}.json"

    def _write_immutable(self, path: Path, content: bytes) -> None:
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
                raise SessionStoreError(f"immutable CAS collision or tampering: {path.name}")
            return
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=self.cas_root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(temporary, path)
            except FileNotFoundError:
                raise
            if self.cas_root.exists():
                directory_fd = os.open(self.cas_root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _put_object_tx(self, connection: sqlite3.Connection, object_type: str, payload: Mapping[str, Any]) -> str:
        if not isinstance(object_type, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", object_type):
            raise SessionStoreError("object_type must be a lowercase type name")
        if not isinstance(payload, Mapping):
            raise SessionStoreError("CAS payload must be an object")
        document = {"object_type": object_type, "payload": deepcopy(dict(payload))}
        content = _canonical_bytes(document)
        object_id = f"CAS-{hashlib.sha256(content).hexdigest().upper()}"
        path = self._object_path(object_id)
        self._write_immutable(path, content)
        created_at = _timestamp()
        connection.execute(
            "INSERT OR IGNORE INTO objects(object_id, object_type, content, sha256, created_at) VALUES (?, ?, ?, ?, ?)",
            (object_id, object_type, content, object_id[4:].lower(), created_at),
        )
        row = connection.execute("SELECT content, object_type FROM objects WHERE object_id = ?", (object_id,)).fetchone()
        if row is None or bytes(row[0]) != content or row[1] != object_type:
            raise SessionStoreError("CAS index does not match immutable object bytes")
        return object_id

    def put_object(self, object_type: str, payload: Mapping[str, Any]) -> str:
        with self._connect() as connection:
            return self._put_object_tx(connection, object_type, payload)

    def get_object(self, object_id: str) -> dict[str, Any]:
        path = self._object_path(object_id)
        with self._connect() as connection:
            row = connection.execute("SELECT content, object_type FROM objects WHERE object_id = ?", (object_id,)).fetchone()
        if row is None:
            raise SessionStoreError(f"unknown CAS object: {object_id}")
        if path.is_symlink() or not path.is_file():
            raise SessionStoreError(f"CAS object file is missing or unsafe: {object_id}")
        content = path.read_bytes()
        if content != bytes(row[0]) or f"CAS-{hashlib.sha256(content).hexdigest().upper()}" != object_id:
            raise SessionStoreError(f"CAS object integrity check failed: {object_id}")
        try:
            document = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionStoreError(f"CAS object is not valid JSON: {object_id}") from exc
        if document.get("object_type") != row[1] or not isinstance(document.get("payload"), dict):
            raise SessionStoreError(f"CAS object envelope is malformed: {object_id}")
        return deepcopy(document["payload"])

    def create_session(
        self,
        *,
        context_digest: str,
        bundle_root: str,
        session_root: str,
        created_at: str | None = None,
    ) -> str:
        context_digest = _require_digest(context_digest, "context_digest")
        bundle_root = _require_digest(bundle_root, "bundle_root")
        session_root = _require_digest(session_root, "session_root")
        timestamp = _timestamp(created_at)
        descriptor = {
            "schema_version": "1.0.0",
            "context_digest": context_digest,
            "bundle_root": bundle_root,
            "session_root": session_root,
        }
        session_id = f"SES-{hashlib.sha256(_canonical_bytes(descriptor)).hexdigest().upper()}"
        session_document = {
            **descriptor,
            "session_id": session_id,
            "state": "created",
            "current_plan_id": None,
            "current_plan_digest": None,
            "plan_revision": -1,
            "sequence": 1,
            "last_event_hash": "0" * 64,
            "created_at": timestamp,
        }
        event = self._build_event(
            session_id=session_id,
            sequence=1,
            event_type="session_created",
            actor="session_store",
            occurred_at=timestamp,
            idempotency_key="session-created",
            from_state="created",
            to_state="created",
            data={"context_digest": context_digest, "bundle_root": bundle_root, "session_root": session_root},
            prev_hash="0" * 64,
        )
        session_document["last_event_hash"] = event["event_hash"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute("SELECT session_id FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if existing is not None:
                    self._assert_replay_tx(connection, session_id)
                    connection.execute("COMMIT")
                    return session_id
                snapshot_id = self._put_object_tx(connection, "audit_session", session_document)
                connection.execute(
                    "INSERT INTO sessions(session_id, context_digest, bundle_root, session_root, state, current_plan_id, current_plan_digest, plan_revision, sequence, last_event_hash, created_at, snapshot_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (session_id, context_digest, bundle_root, session_root, "created", None, None, -1, 1, event["event_hash"], timestamp, snapshot_id),
                )
                self._insert_event_tx(connection, event)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return session_id

    @staticmethod
    def _build_event(
        *, session_id: str, sequence: int, event_type: str, actor: str, occurred_at: str,
        idempotency_key: str, from_state: str, to_state: str, data: Mapping[str, Any], prev_hash: str,
    ) -> dict[str, Any]:
        if not _SESSION_ID.fullmatch(session_id):
            raise SessionStoreError("invalid session_id")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", event_type):
            raise SessionStoreError("event_type is invalid")
        if not actor.strip() or not idempotency_key.strip() or not isinstance(data, Mapping):
            raise SessionStoreError("journal event requires actor, idempotency_key and object data")
        if not re.fullmatch(r"[A-F0-9]{64}", prev_hash):
            raise SessionStoreError("prev_hash must be uppercase SHA-256 or the zero hash")
        core = {
            "schema_version": "1.0.0", "session_id": session_id, "sequence": sequence,
            "event_type": event_type, "actor": actor, "occurred_at": occurred_at,
            "idempotency_key": idempotency_key, "from_state": from_state, "to_state": to_state,
            "data": deepcopy(dict(data)), "prev_hash": prev_hash,
        }
        event_id = f"EVT-{hashlib.sha256(_canonical_bytes(core)).hexdigest().upper()}"
        event = {"event_id": event_id, **core}
        event["event_hash"] = _hash_event(event)
        return event

    @staticmethod
    def _insert_event_tx(connection: sqlite3.Connection, event: Mapping[str, Any]) -> None:
        connection.execute(
            "INSERT INTO events(session_id, sequence, event_id, event_type, actor, occurred_at, idempotency_key, from_state, to_state, data, prev_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event["session_id"], event["sequence"], event["event_id"], event["event_type"], event["actor"],
                event["occurred_at"], event["idempotency_key"], event["from_state"], event["to_state"],
                json.dumps(event["data"], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                event["prev_hash"], event["event_hash"],
            ),
        )

    def append_event(
        self,
        session_id: str,
        *,
        event_type: str,
        actor: str,
        data: Mapping[str, Any],
        idempotency_key: str,
        to_state: str | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        if not _SESSION_ID.fullmatch(session_id):
            raise SessionStoreError("invalid session_id")
        timestamp = _timestamp(occurred_at)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if row is None:
                    raise SessionStoreError(f"unknown session: {session_id}")
                existing = connection.execute("SELECT * FROM events WHERE session_id = ? AND idempotency_key = ?", (session_id, idempotency_key)).fetchone()
                if existing is not None:
                    event = self._row_event(existing)
                    requested = self._build_event(
                        session_id=session_id, sequence=int(existing["sequence"]), event_type=event_type, actor=actor,
                        occurred_at=event["occurred_at"], idempotency_key=idempotency_key,
                        from_state=event["from_state"], to_state=event["to_state"], data=data, prev_hash=event["prev_hash"],
                    )
                    if requested["event_id"] != event["event_id"] or requested["event_hash"] != event["event_hash"]:
                        raise SessionStoreError("idempotency key was reused with different event content")
                    connection.execute("COMMIT")
                    return event
                current = str(row["state"])
                target = to_state or current
                if target != current and target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
                    raise SessionStoreError(f"invalid session transition: {current} -> {target}")
                event = self._build_event(
                    session_id=session_id, sequence=int(row["sequence"]) + 1, event_type=event_type, actor=actor,
                    occurred_at=timestamp, idempotency_key=idempotency_key, from_state=current,
                    to_state=target, data=data, prev_hash=str(row["last_event_hash"]),
                )
                self._insert_event_tx(connection, event)
                snapshot_payload = self._snapshot_payload(
                    row, state=target, sequence=int(event["sequence"]), last_event_hash=str(event["event_hash"]),
                )
                snapshot_id = self._put_object_tx(connection, "audit_session", snapshot_payload)
                connection.execute(
                    "UPDATE sessions SET state = ?, sequence = ?, last_event_hash = ?, snapshot_id = ? WHERE session_id = ?",
                    (target, event["sequence"], event["event_hash"], snapshot_id, session_id),
                )
                connection.execute("COMMIT")
                return event
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def attach_plan(self, session_id: str, plan: Mapping[str, Any], *, actor: str = "planner") -> dict[str, Any]:
        if not isinstance(plan, Mapping):
            raise SessionStoreError("plan must be an object")
        for field in ("plan_id", "plan_digest", "session_root", "plan_revision"):
            if field not in plan:
                raise SessionStoreError(f"plan is missing {field}")
        if plan["session_root"] != self._session_row(session_id)["session_root"]:
            raise SessionStoreError("plan session_root does not match session")
        if not isinstance(plan["plan_revision"], int) or isinstance(plan["plan_revision"], bool) or plan["plan_revision"] < 0:
            raise SessionStoreError("plan_revision must be a non-negative integer")
        data = {"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"], "plan_revision": plan["plan_revision"]}
        idempotency_key = f"plan:{plan['plan_id']}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if row is None:
                    raise SessionStoreError(f"unknown session: {session_id}")
                current_revision = int(row["plan_revision"])
                if current_revision >= 0 and int(plan["plan_revision"]) < current_revision:
                    raise SessionStoreError("plan revision cannot move backwards")
                if current_revision >= 0 and int(plan["plan_revision"]) == current_revision and plan["plan_id"] != row["current_plan_id"]:
                    raise SessionStoreError("same plan revision cannot replace the current plan")
                existing = connection.execute(
                    "SELECT * FROM events WHERE session_id = ? AND idempotency_key = ?", (session_id, idempotency_key)
                ).fetchone()
                if existing is not None:
                    event = self._row_event(existing)
                    if event["event_type"] != "plan_attached" or event["data"] != data:
                        raise SessionStoreError("idempotent plan attachment content does not match")
                else:
                    event = self._build_event(
                        session_id=session_id, sequence=int(row["sequence"]) + 1, event_type="plan_attached", actor=actor,
                        occurred_at=_timestamp(), idempotency_key=idempotency_key, from_state=str(row["state"]),
                        to_state=str(row["state"]), data=data, prev_hash=str(row["last_event_hash"]),
                    )
                    self._insert_event_tx(connection, event)
                snapshot_payload = self._snapshot_payload(
                    row, current_plan_id=str(plan["plan_id"]), current_plan_digest=str(plan["plan_digest"]),
                    plan_revision=int(plan["plan_revision"]), sequence=int(event["sequence"]), last_event_hash=str(event["event_hash"]),
                )
                snapshot_id = self._put_object_tx(connection, "audit_session", snapshot_payload)
                connection.execute(
                    "UPDATE sessions SET current_plan_id = ?, current_plan_digest = ?, plan_revision = ?, sequence = ?, last_event_hash = ?, snapshot_id = ? WHERE session_id = ?",
                    (plan["plan_id"], plan["plan_digest"], plan["plan_revision"], event["sequence"], event["event_hash"], snapshot_id, session_id),
                )
                connection.execute("COMMIT")
                return event
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def transition(self, session_id: str, target: str, *, actor: str, reason: str, idempotency_key: str) -> dict[str, Any]:
        return self.append_event(
            session_id, event_type="state_transition", actor=actor,
            data={"reason": reason}, idempotency_key=idempotency_key, to_state=target,
        )

    def _session_row(self, session_id: str) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if row is None:
            raise SessionStoreError(f"unknown session: {session_id}")
        return row

    @staticmethod
    def _snapshot_payload(
        row: sqlite3.Row,
        *,
        state: str | None = None,
        current_plan_id: str | None = None,
        current_plan_digest: str | None = None,
        plan_revision: int | None = None,
        sequence: int | None = None,
        last_event_hash: str | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0", "session_id": row["session_id"], "context_digest": row["context_digest"],
            "bundle_root": row["bundle_root"], "session_root": row["session_root"], "state": state or row["state"],
            "current_plan_id": current_plan_id if current_plan_id is not None else row["current_plan_id"],
            "current_plan_digest": current_plan_digest if current_plan_digest is not None else row["current_plan_digest"],
            "plan_revision": int(plan_revision if plan_revision is not None else row["plan_revision"]),
            "sequence": int(sequence if sequence is not None else row["sequence"]),
            "last_event_hash": last_event_hash or row["last_event_hash"], "created_at": row["created_at"],
        }

    @staticmethod
    def _row_event(row: sqlite3.Row) -> dict[str, Any]:
        try:
            data = json.loads(str(row["data"]))
        except json.JSONDecodeError as exc:
            raise SessionStoreError("journal event data is not valid JSON") from exc
        if not isinstance(data, dict):
            raise SessionStoreError("journal event data must be an object")
        return {
            "schema_version": "1.0.0", "event_id": row["event_id"], "session_id": row["session_id"],
            "sequence": int(row["sequence"]), "event_type": row["event_type"], "actor": row["actor"],
            "occurred_at": row["occurred_at"], "idempotency_key": row["idempotency_key"],
            "from_state": row["from_state"], "to_state": row["to_state"], "data": data,
            "prev_hash": row["prev_hash"], "event_hash": row["event_hash"],
        }

    def _assert_replay_tx(self, connection: sqlite3.Connection, session_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        row = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if row is None:
            raise SessionStoreError(f"unknown session: {session_id}")
        events = [self._row_event(item) for item in connection.execute("SELECT * FROM events WHERE session_id = ? ORDER BY sequence", (session_id,))]
        if not events:
            raise SessionStoreError("session journal is empty")
        state = "created"
        previous_hash = "0" * 64
        seen_ids: set[str] = set()
        for index, event in enumerate(events, start=1):
            if event["sequence"] != index or event["event_id"] in seen_ids:
                raise SessionStoreError("session journal sequence or event identity is invalid")
            if event["session_id"] != session_id or event["prev_hash"] != previous_hash:
                raise SessionStoreError("session journal hash chain has a gap")
            expected_id = f"EVT-{hashlib.sha256(_canonical_bytes({key: value for key, value in event.items() if key not in {"event_id", "event_hash"}})).hexdigest().upper()}"
            if event["event_id"] != expected_id or event["event_hash"] != _hash_event(event):
                raise SessionStoreError(f"session journal event integrity failed at sequence {index}")
            if event["from_state"] != state:
                raise SessionStoreError(f"session journal state mismatch at sequence {index}")
            target = event["to_state"]
            if target != state and target not in ALLOWED_TRANSITIONS.get(state, frozenset()):
                raise SessionStoreError(f"session journal contains invalid transition at sequence {index}")
            state = target
            previous_hash = event["event_hash"]
            seen_ids.add(event["event_id"])
        if str(row["state"]) != state or int(row["sequence"]) != len(events) or str(row["last_event_hash"]) != previous_hash:
            raise SessionStoreError("session snapshot does not match journal replay")
        snapshot = {
            "schema_version": "1.0.0", "session_id": session_id, "context_digest": row["context_digest"],
            "bundle_root": row["bundle_root"], "session_root": row["session_root"], "state": state,
            "current_plan_id": row["current_plan_id"], "current_plan_digest": row["current_plan_digest"],
            "plan_revision": int(row["plan_revision"]), "sequence": len(events), "last_event_hash": previous_hash,
            "created_at": row["created_at"],
        }
        return snapshot, events

    def resume(self, session_id: str, *, expected_session_root: str | None = None, expected_plan_id: str | None = None) -> dict[str, Any]:
        with self._connect() as connection:
            snapshot, events = self._assert_replay_tx(connection, session_id)
        row = self._session_row(session_id)
        if row["snapshot_id"]:
            if self.get_object(str(row["snapshot_id"])) != snapshot:
                raise SessionStoreError("session CAS snapshot does not match journal replay")
        if expected_session_root is not None and snapshot["session_root"] != expected_session_root:
            raise SessionStoreError("session root does not match resume request")
        if expected_plan_id is not None and snapshot["current_plan_id"] != expected_plan_id:
            raise SessionStoreError("current plan does not match resume request")
        snapshot["events"] = events
        return snapshot

    def repair_check(self, session_id: str) -> dict[str, Any]:
        """Replay without mutating state; useful as a crash/recovery health check."""

        snapshot = self.resume(session_id)
        return {"session_id": session_id, "healthy": True, "sequence": snapshot["sequence"], "last_event_hash": snapshot["last_event_hash"]}
