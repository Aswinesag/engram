"""Unix Domain Socket JSON-RPC 2.0 listener for Engram's Evolution Compiler."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import sqlite3
import sys
import tempfile
import threading
import tomllib
from pathlib import Path
from typing import Any

from engram_compiler import __version__
from engram_compiler.detector import (
    FrictionEvent,
    analyze_session,
    merge_friction_events,
)
from engram_compiler.shadow_eval import ShadowEvalResult, ShadowEvaluator
from engram_compiler.synthesizer import (
    KIND_HOOK,
    KIND_RULE,
    KIND_TOOL,
    SynthesizedArtifact,
    Synthesizer,
    materialize_artifact,
)

JSONRPC_VERSION = "2.0"
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603


def repo_hash(repo_root: str | Path) -> str:
    """Compute a short deterministic hash of repo_root for socket naming."""
    canonical = str(Path(repo_root).resolve()).replace("\\", "/")
    if os.name == "nt":
        canonical = canonical.lower()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def socket_path_for_repo(repo_root: str | Path) -> Path:
    """Return /tmp/engram-<repo_hash>.sock on POSIX and <temp>/engram-<repo_hash>.sock on Windows."""
    h = repo_hash(repo_root)
    if os.name == "posix":
        return Path("/tmp") / f"engram-{h}.sock"
    return Path(tempfile.gettempdir()) / f"engram-{h}.sock"


class EvolutionService:
    """Handles JSON-RPC 2.0 requests (compiler.ping, compiler.synthesize)."""

    def __init__(
        self,
        *,
        synthesizer: Synthesizer | None = None,
        evaluator: ShadowEvaluator | None = None,
    ) -> None:
        self._synthesizer = synthesizer or Synthesizer()
        self._evaluator = evaluator or ShadowEvaluator()

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict) or payload.get("jsonrpc") != JSONRPC_VERSION:
            return _rpc_error(None, ERR_INVALID_REQUEST, "invalid JSON-RPC 2.0 request")

        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params") or {}

        if not isinstance(method, str) or not method:
            return _rpc_error(req_id, ERR_INVALID_REQUEST, "missing method name")
        if not isinstance(params, dict):
            return _rpc_error(req_id, ERR_INVALID_PARAMS, "params must be a JSON object")

        if method == "compiler.ping":
            return _rpc_result(req_id, {"status": "ok", "version": __version__})

        if method == "compiler.synthesize":
            try:
                result = self._handle_synthesize(params)
                return _rpc_result(req_id, result)
            except ValueError as exc:
                return _rpc_error(req_id, ERR_INVALID_PARAMS, str(exc))
            except Exception as exc:  # noqa: BLE001
                return _rpc_error(req_id, ERR_INTERNAL, str(exc))

        return _rpc_error(req_id, ERR_METHOD_NOT_FOUND, f"unknown method: {method}")

    def _handle_synthesize(self, params: dict[str, Any]) -> dict[str, Any]:
        session_id = str(params.get("session_id", "")).strip()
        repo_root_raw = str(params.get("repo_root", "")).strip()
        base_commit_sha = str(params.get("base_commit_sha", "")).strip() or "HEAD"
        reported_events = params.get("friction_events")
        regression_cmd = params.get("regression_cmd")

        if not session_id:
            raise ValueError("params.session_id is required")
        if not repo_root_raw:
            raise ValueError("params.repo_root is required")

        repo_root = Path(repo_root_raw).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"repo_root does not exist: {repo_root}")

        db_path = repo_root / ".engram" / ".runtime" / "state.db"
        detected: list[FrictionEvent] = []
        if db_path.is_file():
            detected = analyze_session(db_path, session_id)

        merged = merge_friction_events(reported_events, detected)
        if not merged:
            raise ValueError(f"no friction events found for session {session_id!r}")

        primary_event = merged[0]

        # 1. Synthesize & AST-validate candidate engram.
        artifact = self._synthesizer.synthesize(
            repo_root=repo_root,
            event=primary_event,
        )

        # 2. Shadow replay at base_commit_sha inside an isolated detached worktree (Invariant #4).
        eval_result = self._evaluator.evaluate(
            repo_root=repo_root,
            base_commit_sha=base_commit_sha,
            artifact=artifact,
            event=primary_event,
            regression_cmd=str(regression_cmd) if regression_cmd else None,
        )

        # 3. Promote strictly if shadow verification passed.
        status = "rejected"
        if eval_result.verified:
            materialize_artifact(repo_root, artifact)
            auto_approve_threshold = _read_auto_approve_threshold(repo_root)
            status = "active" if eval_result.pass_rate >= auto_approve_threshold else "pending_approval"
            _update_manifest(repo_root, artifact, status, eval_result.pass_rate)

        if db_path.is_file():
            _persist_engram_sqlite(
                db_path=db_path,
                session_id=session_id,
                artifact=artifact,
                status=status,
                eval_result=eval_result,
            )

        return {
            "engram_id": artifact.engram_id,
            "kind": artifact.kind,
            "target_tool": artifact.target_tool,
            "command_regex": artifact.trigger_pattern,
            "file_path": artifact.file_path,
            "shadow_verified": eval_result.verified,
            "shadow_pass_rate": eval_result.pass_rate,
            "status": status,
            "failure_signature": artifact.failure_signature,
            "explanation": artifact.explanation,
        }


class UnixJSONRPCServer:
    """Cross-platform (Linux, macOS, Windows 10+) AF_UNIX newline-delimited JSON-RPC 2.0 server."""

    def __init__(self, socket_path: str | Path, service: EvolutionService | None = None) -> None:
        self.socket_path = Path(socket_path)
        self.service = service or EvolutionService()
        self._transport = "unix" if hasattr(socket, "AF_UNIX") else "tcp"
        self.bound_address = str(self.socket_path)
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._bg_thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    def bind(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()

        if self._transport == "unix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(self.socket_path))
            sock.listen(32)
            sock.settimeout(0.2)
            self._sock = sock
            self.bound_address = str(self.socket_path)
            return

        # Windows CPython lacks AF_UNIX; bind loopback 127.0.0.1:0 and atomically
        # publish the tcp://127.0.0.1:<port> descriptor at socket_path.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        sock.settimeout(0.2)
        host, port = sock.getsockname()
        self._sock = sock
        self.bound_address = f"tcp://{host}:{port}"

        tmp_path = self.socket_path.with_suffix(".sock.tmp")
        tmp_path.write_text(self.bound_address + "\n", encoding="utf-8")
        os.replace(tmp_path, self.socket_path)

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        assert self._sock is not None

        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            with self._lock:
                self._client_threads = [th for th in self._client_threads if th.is_alive()]
                self._client_threads.append(t)
            t.start()

    def start_background(self) -> threading.Thread:
        if self._sock is None:
            self.bind()
        t = threading.Thread(target=self.serve_forever, daemon=True)
        self._bg_thread = t
        t.start()
        return t

    def shutdown(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        if self._bg_thread is not None and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=3.0)

        with self._lock:
            threads = list(self._client_threads)
        for t in threads:
            t.join(timeout=1.0)

        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(60.0)
            reader = conn.makefile("r", encoding="utf-8", newline="\n")
            writer = conn.makefile("w", encoding="utf-8", newline="\n")
            try:
                for line in reader:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        req = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        resp = _rpc_error(None, ERR_PARSE, f"parse error: {exc}")
                    else:
                        resp = self.service.handle_request(req)
                    writer.write(json.dumps(resp) + "\n")
                    writer.flush()
            except OSError:
                return
            finally:
                try:
                    reader.close()
                except OSError:
                    pass
                try:
                    writer.close()
                except OSError:
                    pass


def _rpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "error": {"code": code, "message": message}}


def _read_auto_approve_threshold(repo_root: Path) -> float:
    cfg_path = repo_root / ".engram" / "config.toml"
    if not cfg_path.is_file():
        return 1.0
    try:
        with cfg_path.open("rb") as f:
            data = tomllib.load(f)
        return float(data.get("evolution", {}).get("auto_approve_threshold", 1.0))
    except (OSError, ValueError, KeyError):
        return 1.0


def _update_manifest(
    repo_root: Path,
    artifact: SynthesizedArtifact,
    status: str,
    pass_rate: float,
) -> None:
    manifest_path = repo_root / ".engram" / "manifest.json"
    manifest: dict[str, Any] = {"version": "1.0", "hooks": [], "tools": [], "rules": []}
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest.update(loaded)
        except json.JSONDecodeError:
            pass

    section = {
        KIND_HOOK: "hooks",
        KIND_TOOL: "tools",
        KIND_RULE: "rules",
    }[artifact.kind]
    entries = list(manifest.get(section) or [])
    entry = {
        "id": artifact.engram_id,
        "kind": artifact.kind,
        "target_tool": artifact.target_tool,
        "trigger_pattern": artifact.trigger_pattern,
        "file_path": artifact.file_path,
        "status": status,
        "shadow_pass_rate": pass_rate,
        "explanation": artifact.explanation,
    }
    entries = [e for e in entries if e.get("id") != artifact.engram_id]
    entries.append(entry)
    manifest[section] = entries

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = manifest_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, manifest_path)


def _persist_engram_sqlite(
    *,
    db_path: Path,
    session_id: str,
    artifact: SynthesizedArtifact,
    status: str,
    eval_result: ShadowEvalResult,
) -> None:
    # Store relative path inside .engram/ matching Section 5 schema comment.
    rel_inside_engram = artifact.file_path.removeprefix(".engram/")
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # Only attach source_session_id if the session row exists in sessions.
        row = conn.execute("SELECT 1 FROM sessions WHERE id = ?", (session_id,)).fetchone()
        src_session = session_id if row is not None else None
        conn.execute(
            """
            INSERT INTO engrams (
                id, kind, trigger_pattern, file_path, source_session_id,
                failure_signature, status, shadow_pass_rate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                shadow_pass_rate = excluded.shadow_pass_rate
            """,
            (
                artifact.engram_id,
                artifact.kind,
                artifact.trigger_pattern,
                rel_inside_engram,
                src_session,
                artifact.failure_signature,
                status,
                eval_result.pass_rate,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Engram Python Evolution Compiler UDS JSON-RPC server")
    parser.add_argument("--repo", default=".", help="Path to target repository root")
    parser.add_argument("--socket", default="", help="Explicit Unix Domain Socket path override")
    args = parser.parse_args(argv)

    sock_path = Path(args.socket) if args.socket else socket_path_for_repo(args.repo)
    server = UnixJSONRPCServer(sock_path)
    server.bind()

    def _on_signal(_signum: int, _frame: Any) -> None:
        server.shutdown()

    signal.signal(signal.SIGINT, _on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _on_signal)

    print(f"engram-compiler listening on {sock_path}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())