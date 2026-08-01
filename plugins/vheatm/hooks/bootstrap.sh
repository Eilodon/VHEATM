#!/usr/bin/env bash
# Best-effort self-bootstrap for the VHEATM plugin. Never blocks the session:
# every step is allowed to fail silently, since this only runs opportunistically
# on SessionStart in whatever project the plugin happens to be installed into.
set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0

# Only act in projects that actually look like a VHEATM control-plane checkout.
if [ ! -f "manifests/vheatm-v17.yaml" ]; then
  exit 0
fi

if [ ! -f "context.yaml" ] && command -v vheatm-init >/dev/null 2>&1; then
  vheatm-init --root . >/dev/null 2>&1 || true
fi

if command -v vheatm-doctor >/dev/null 2>&1; then
  vheatm-doctor --fix --root . >/dev/null 2>&1 || true
fi

exit 0
