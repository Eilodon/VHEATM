from __future__ import annotations

import hashlib
import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .bundle import build_bundle


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_supply_chain_attestation(root: Path, *, generated_at: str | None = None) -> dict[str, Any]:
    bundle = build_bundle(root)
    sbom = [{"path": entry["path"], "sha256": entry["sha256"]} for entry in bundle["entries"]]
    sbom_digest = hashlib.sha256(_canonical(sbom)).hexdigest()
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = []
    in_dependencies = False
    for line in text.splitlines():
        if line.strip() == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies and line.strip() == "]":
            in_dependencies = False
            continue
        if in_dependencies:
            match = re.search(r'"([^">=<!~]+)([^" ]*)"', line)
            if match:
                dependencies.append({"name": match.group(1).strip(), "specifier": match.group(2).strip() or "*"})
    lock_path = root / "uv.lock"
    lock_valid = False
    lock_digest: str | None = None
    lock_relative_path: str | None = None
    if lock_path.is_file() and not lock_path.is_symlink():
        try:
            lock_document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
            lock_valid = lock_document.get("version") == 1 and isinstance(lock_document.get("package"), list) and bool(lock_document["package"])
        except (OSError, tomllib.TOMLDecodeError):
            lock_valid = False
        if lock_valid:
            lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            lock_relative_path = "uv.lock"
    identity = {"bundle_root": bundle["bundle_root"], "sbom": sbom, "sbom_digest": sbom_digest, "dependencies": dependencies, "dependency_lock_present": lock_valid, "dependency_lock_path": lock_relative_path, "dependency_lock_digest": lock_digest, "signed_release": False, "signature_key_id": None, "verification_state": "partial"}
    timestamp = generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {"schema_version": "1.0.0", "attestation_id": "SCA-" + hashlib.sha256(_canonical(identity)).hexdigest().upper(), **identity, "generated_at": timestamp}
