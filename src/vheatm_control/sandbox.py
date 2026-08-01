from __future__ import annotations

import hashlib
import json
import os
import resource
import selectors
import shlex
import signal
import subprocess
import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .tool_broker import ToolBroker, action_digest, build_tool_receipt, expected_tool_receipt_id, request_digest, validate_policy_decision


class SandboxConfigurationError(ValueError):
    """Raised when a reference-monitor configuration is not trustworthy."""


class SandboxExecutionError(RuntimeError):
    """Raised only for malformed adapter inputs, never for an untrusted action."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SandboxExecutionError("sandbox timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise SandboxExecutionError("sandbox timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def expected_sandbox_run_id(run: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in run.items() if key != "run_id"}
    return "SBR-" + _digest(identity).upper()


def build_sandbox_run(
    *,
    request: Mapping[str, Any],
    backend_digest: str,
    argv: Sequence[str],
    status: str,
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    started_at: str,
    finished_at: str,
    sandbox_controls: Sequence[str] = (),
    policy_decision: Mapping[str, Any] | None = None,
    tool_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in {"completed", "failed", "blocked"}:
        raise SandboxExecutionError("sandbox status must be completed, failed, or blocked")
    if len(backend_digest) != 64 or any(char not in "0123456789abcdef" for char in backend_digest):
        raise SandboxExecutionError("sandbox backend digest must be lowercase SHA-256")
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise SandboxExecutionError("sandbox argv must be non-empty strings")
    started = _timestamp(started_at)
    finished = _timestamp(finished_at)
    if datetime.fromisoformat(finished.replace("Z", "+00:00")) < datetime.fromisoformat(started.replace("Z", "+00:00")):
        raise SandboxExecutionError("sandbox finished_at cannot precede started_at")
    authorization: dict[str, Any] = {}
    if policy_decision is not None or tool_receipt is not None:
        if not isinstance(policy_decision, Mapping) or not isinstance(tool_receipt, Mapping):
            raise SandboxExecutionError("sandbox authorization evidence must include a policy decision and tool receipt")
        try:
            validate_policy_decision(policy_decision, request)
        except Exception as exc:
            raise SandboxExecutionError(f"sandbox policy decision is invalid: {exc}") from exc
        if tool_receipt.get("request_id") != request.get("request_id") or tool_receipt.get("request_digest") != request_digest(request):
            raise SandboxExecutionError("sandbox tool receipt is not bound to the request")
        if tool_receipt.get("tool_class") != request.get("tool_class") or tool_receipt.get("decision") != policy_decision.get("decision"):
            raise SandboxExecutionError("sandbox tool receipt is not bound to the policy decision")
        if tool_receipt.get("action_digest") != action_digest(request) or tool_receipt.get("id") != expected_tool_receipt_id(tool_receipt):
            raise SandboxExecutionError("sandbox tool receipt action binding is invalid")
        authorization = {
            "policy_decision_digest": request_digest(policy_decision),
            "action_digest": action_digest(request),
            "tool_receipt": dict(tool_receipt),
        }
    if status in {"completed", "failed"} and (not authorization or policy_decision.get("decision") != "allow"):
        raise SandboxExecutionError("sandbox execution requires allow decision authorization evidence")
    identity: dict[str, Any] = {
        "schema_version": "1.0.0",
        "request_id": str(request.get("request_id", "")),
        "request_digest": request_digest(request),
        "backend": "bubblewrap",
        "backend_digest": backend_digest,
        "workspace_root": str(request.get("workspace_path", "")),
        "scope": str(request.get("scope", "")),
        "argv": list(argv),
        "status": status,
        "exit_code": exit_code,
        "stdout_digest": hashlib.sha256(stdout).hexdigest(),
        "stderr_digest": hashlib.sha256(stderr).hexdigest(),
        "sandbox_controls": list(dict.fromkeys(sandbox_controls)) or ["reference-monitor:bubblewrap"],
        "started_at": started,
        "finished_at": finished,
        "policy_decision_digest": authorization.get("policy_decision_digest"),
        "action_digest": authorization.get("action_digest"),
        "tool_receipt": authorization.get("tool_receipt"),
    }
    return {"run_id": expected_sandbox_run_id(identity), **identity}


def _scope_path(scope: str) -> PurePosixPath:
    if not scope.startswith("workspace:"):
        raise ValueError("scope must start with 'workspace:'")
    suffix = scope[len("workspace:") :]
    if suffix == "":
        return PurePosixPath(".")
    path = PurePosixPath(suffix)
    if path.is_absolute() or str(path) != suffix or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("scope must be a normalized workspace-relative path")
    return path


def _safe_command(command: object) -> list[str]:
    if not isinstance(command, str) or not command or command != command.strip() or "\x00" in command:
        raise ValueError("command must be a normalized non-null string")
    argv = shlex.split(command, posix=True)
    if not argv or any(not item for item in argv):
        raise ValueError("command must produce a non-empty argv")
    return argv


def _limit_resources(*, cpu_seconds: int, memory_bytes: int, file_size_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))


@dataclass(frozen=True)
class _ProcessOutcome:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_exceeded: bool = False


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()


def _run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    output_bytes: int,
    cpu_seconds: int,
    memory_bytes: int,
) -> _ProcessOutcome:
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
        preexec_fn=lambda: _limit_resources(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            file_size_bytes=output_bytes,
        ),
    )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        process.wait(timeout=1)
        raise SandboxExecutionError("sandbox subprocess pipes were not created")
    selector = selectors.DefaultSelector()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    buffers: dict[int, bytearray] = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    timed_out = False
    output_exceeded = False
    try:
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(process)
                break
            for key, _ in selector.select(remaining):
                fileobj = key.fileobj
                fd = fileobj.fileno()
                data = os.read(fd, min(65536, output_bytes + 1))
                if not data:
                    selector.unregister(fileobj)
                    fileobj.close()
                    continue
                buffers[fd].extend(data)
                if len(buffers[fd]) > output_bytes:
                    output_exceeded = True
                    _kill_process_group(process)
                    break
            if timed_out or output_exceeded:
                break
        if timed_out or output_exceeded:
            selector.close()
            process.wait(timeout=1)
        else:
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        _kill_process_group(process)
        process.wait(timeout=1)
        timed_out = True
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()
    stdout = bytes(buffers[stdout_fd])[:output_bytes]
    stderr = bytes(buffers[stderr_fd])[:output_bytes]
    return _ProcessOutcome(process.returncode, stdout, stderr, timed_out, output_exceeded)


@dataclass
class SandboxExecutor:
    """Reference-monitor adapter for broker-approved, read-only execution.

    The adapter owns the only subprocess boundary for execute requests. It does
    not run a host fallback when bubblewrap, network isolation, or the broker is
    unavailable. The backend binary is content-bound at construction time.
    """

    backend_path: Path
    backend_sha256: str | None
    broker: ToolBroker | None = None
    timeout_seconds: float = 30.0
    memory_bytes: int = 512 * 1024 * 1024
    output_bytes: int = 1024 * 1024
    cpu_seconds: int = 20

    def __post_init__(self) -> None:
        if os.name != "posix":
            raise SandboxConfigurationError("bubblewrap reference monitor requires a POSIX host")
        try:
            path = self.backend_path.resolve(strict=True)
        except OSError as exc:
            raise SandboxConfigurationError("sandbox backend is unavailable") from exc
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SandboxConfigurationError("sandbox backend must be an executable file")
        if not isinstance(self.backend_sha256, str) or len(self.backend_sha256) != 64:
            raise SandboxConfigurationError("sandbox backend digest is required")
        if any(char not in "0123456789abcdef" for char in self.backend_sha256):
            raise SandboxConfigurationError("sandbox backend digest must be lowercase SHA-256")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != self.backend_sha256:
            raise SandboxConfigurationError("sandbox backend digest does not match executable")
        if self.timeout_seconds <= 0 or self.memory_bytes <= 0 or self.output_bytes <= 0 or self.cpu_seconds <= 0:
            raise SandboxConfigurationError("sandbox resource limits must be positive")
        self.backend_path = path

    @classmethod
    def from_system(
        cls,
        *,
        broker: ToolBroker | None = None,
        backend_path: str | Path | None = None,
        backend_sha256: str | None = None,
        **limits: Any,
    ) -> "SandboxExecutor":
        selected = Path(backend_path) if backend_path is not None else Path(shutil.which("bwrap") or "")
        return cls(backend_path=selected, backend_sha256=backend_sha256, broker=broker, **limits)

    def run(self, request: Mapping[str, Any], approval_token: Mapping[str, Any] | None = None) -> dict[str, Any]:
        started = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        try:
            argv = _safe_command(request.get("command"))
        except ValueError as exc:
            argv = ["<invalid-command>"]
            return self._blocked(request, argv, str(exc), started)

        try:
            workspace = Path(str(request.get("workspace_path", "")))
            if not workspace.is_absolute() or workspace.is_symlink():
                raise ValueError("workspace_path must be an absolute non-symlink directory")
            workspace = workspace.resolve(strict=True)
            if not workspace.is_dir() or workspace == Path(workspace.anchor or "/"):
                raise ValueError("workspace_path must be a directory")
            scope = _scope_path(str(request.get("scope", "")))
            cwd = workspace if scope == PurePosixPath(".") else workspace.joinpath(*scope.parts)
            current = workspace
            for part in scope.parts if scope != PurePosixPath(".") else ():
                current = current / part
                if current.is_symlink():
                    raise ValueError("workspace scope may not traverse symlinks")
            if not cwd.is_dir():
                raise ValueError("workspace scope must resolve to a real directory")
            cwd.relative_to(workspace)
        except (OSError, ValueError) as exc:
            return self._blocked(request, argv, str(exc), started, controls=("scope:workspace",))

        if self.broker is None:
            return self._blocked(request, argv, "reference monitor has no policy broker", started, controls=("broker:unavailable",))
        try:
            decision = self.broker.evaluate(request, approval_token)
        except Exception as exc:  # a failed policy boundary must not become host execution
            return self._blocked(request, argv, f"policy broker unavailable: {exc}", started, controls=("broker:error",))
        try:
            validate_policy_decision(decision, request)
            authorization_receipt = build_tool_receipt(request, decision, recorded_at=started)
        except Exception as exc:  # a malformed authorization boundary must not become host execution
            return self._blocked(request, argv, f"authorization receipt unavailable: {exc}", started, controls=("authorization:receipt-failed",))
        if decision.get("decision") != "allow":
            return self._blocked(
                request,
                argv,
                str(decision.get("reason", "policy denied execute request")),
                started,
                controls=("policy:deny", "approval:verified-or-denied"),
                policy_decision=decision,
                tool_receipt=authorization_receipt,
            )

        # Probe the exact reference-monitor mode before accepting the action.
        # In particular, bubblewrap may be installed while the host forbids
        # creation of the required network namespace. That is an unavailable
        # monitor, not a command failure and must remain blocked.
        probe = self._probe(workspace, cwd)
        if probe is not None:
            return self._blocked(request, argv, probe, started, controls=("backend:preflight-failed",), policy_decision=decision, tool_receipt=authorization_receipt)

        command = self._command(workspace, cwd, argv)
        try:
            completed = _run_bounded_process(
                command, cwd=workspace, timeout_seconds=self.timeout_seconds, output_bytes=self.output_bytes,
                cpu_seconds=self.cpu_seconds, memory_bytes=self.memory_bytes,
            )
        except OSError as exc:
            return self._blocked(request, argv, f"reference monitor unavailable: {exc}", started, controls=("backend:unavailable",), policy_decision=decision, tool_receipt=authorization_receipt)
        if completed.timed_out:
            return build_sandbox_run(
                request=request, backend_digest=self.backend_sha256 or "", argv=argv,
                status="blocked", exit_code=None, stdout=completed.stdout, stderr=completed.stderr + b"sandbox timeout",
                started_at=started, finished_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                sandbox_controls=self._controls() + ("timeout:enforced",),
                policy_decision=decision,
                tool_receipt=authorization_receipt,
            )
        stdout = completed.stdout
        stderr = completed.stderr
        if completed.output_exceeded:
            return build_sandbox_run(
                request=request, backend_digest=self.backend_sha256 or "", argv=argv,
                status="blocked", exit_code=None, stdout=stdout[: self.output_bytes],
                stderr=stderr[: self.output_bytes] + b"output limit exceeded",
                started_at=started, finished_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                sandbox_controls=self._controls() + ("output:bounded",),
                policy_decision=decision,
                tool_receipt=authorization_receipt,
            )
        return build_sandbox_run(
            request=request, backend_digest=self.backend_sha256 or "", argv=argv,
            status="completed" if completed.returncode == 0 else "failed", exit_code=completed.returncode,
            stdout=stdout, stderr=stderr, started_at=started,
            finished_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            sandbox_controls=self._controls(),
            policy_decision=decision,
            tool_receipt=authorization_receipt,
        )

    def _probe(self, workspace: Path, cwd: Path) -> str | None:
        try:
            completed = _run_bounded_process(
                self._command(workspace, cwd, ["/bin/true"]), cwd=workspace,
                timeout_seconds=min(self.timeout_seconds, 5.0), output_bytes=self.output_bytes,
                cpu_seconds=self.cpu_seconds, memory_bytes=self.memory_bytes,
            )
        except OSError as exc:
            return f"reference monitor preflight unavailable: {exc}"
        if completed.timed_out or completed.output_exceeded or completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            return "reference monitor preflight failed" + (f": {detail}" if detail else "")
        return None

    def _command(self, workspace: Path, cwd: Path, argv: Sequence[str]) -> list[str]:
        command: list[str] = [
            str(self.backend_path),
            "--die-with-parent",
            "--new-session",
            "--unshare-user-try",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-net",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--ro-bind", str(workspace), "/workspace",
        ]
        for runtime_path in ("/usr", "/usr/local", "/bin", "/lib", "/lib64", "/etc"):
            source = Path(runtime_path)
            if source.exists():
                command.extend(("--ro-bind", runtime_path, runtime_path))
        command.extend((
            "--clearenv",
            "--setenv", "PATH", "/workspace/.venv/bin:/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "LANG", "C.UTF-8",
            "--cap-drop", "ALL",
            "--chdir", "/workspace" + ("" if cwd == workspace else "/" + cwd.relative_to(workspace).as_posix()),
            "--",
        ))
        command.extend(argv)
        return command

    def _controls(self) -> tuple[str, ...]:
        return (
            "reference-monitor:bubblewrap",
            "backend:digest-bound",
            "filesystem:workspace-read-only",
            "network:unshare-net",
            "environment:clearenv-no-secrets",
            "process:namespace-isolated",
            "resource:rlimits",
        )

    def _blocked(
        self,
        request: Mapping[str, Any],
        argv: Sequence[str],
        reason: str,
        started: str,
        *,
        controls: Sequence[str] = (),
        policy_decision: Mapping[str, Any] | None = None,
        tool_receipt: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_sandbox_run(
            request=request, backend_digest=self.backend_sha256 or "0" * 64, argv=argv,
            status="blocked", exit_code=None, stdout=b"", stderr=reason.encode("utf-8", errors="replace"),
            started_at=started, finished_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            sandbox_controls=tuple(self._controls()) + tuple(controls) + ("fail-closed",),
            policy_decision=policy_decision,
            tool_receipt=tool_receipt,
        )
