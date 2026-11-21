"""Unix Domain Socket JSON-RPC 2.0 listener for Engram's Evolution Compiler."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import socketserver
import sqlite3
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from engram_compiler.detector import (
    FrictionEvent,
    analyze_session,
    merge_friction_events,
)
from engram_compiler.shadow_eval import ShadowEvaluator
from engram_compiler.synthesizer import (
    SynthesizedArtifact,
    Synthesizer,
    materialize_artifact,
)

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


def repo_hash(repo_root: str | Path) -> str:
    """Return the deterministic 12-char SHA-256 hash identifying a repository."""
    canonical = os.path.realpath(str(repo_root))
    if os.name == "nt":
        canonical = canonical.lower()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def socket_path_for_repo(repo_root: str | Path) -> str:
    """Compute /tmp/engram-<repo_hash>.sock on POSIX (or OS temp dir on Windows)."""
    h = repo_hash(repo_root)
    base_dir = "/tmp" if os.name != "nt" else tempfile.gettempdir()
    return os.path.join(base_dir, f"engram-{h}.sock")


class EvolutionService:
    """Handles JSON-RPC 2.0 requests for friction analysis, synthesis, and shadow verification."""

    def __init__(
        self,
        *,
        synthesizer: Synthesizer | None = None,
        evaluator: ShadowEvaluator | None = None,
    ) -> None:
        self._synthesizer = synthesizer or Synthesizer()
        self._evaluator = evaluator or ShadowEvaluator()

    def handle_rpc(self, raw_line: str) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 request line and return a response dict."""
        try:
            req = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            return _rpc_error(None, JSONRPC_PARSE_ERROR, f"Parse error: {exc}")

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
            return _rpc_error(req.get("id") if isinstance(req, dict) else None, JSONRPC_INVALID_REQUEST, "Invalid Request")

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        if not isinstance(method, str) or not method:
            return _rpc_error(req_id, JSONRPC_INVALID_REQUEST, "Missing method")
        if not isinstance(params, dict):
            return _rpc_error(req_id, JSONRPC_INVALID_PARAMS, "params must be an object")

        try:
            if method == "compiler.ping":
                result: dict[str, Any] = {"ok": True, "version": "1.0.0"}
            elif method == "compiler.synthesize":
                result = self.synthesize(params)
            else:
                return _rpc_error(req_id, JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}")
        except ValueError as exc:
            return _rpc_error(req_id, JSONRPC_INVALID_PARAMS, str(exc))
        except Exception as exc:
            return _rpc_error(req_id, JSONRPC_INTERNAL_ERROR, str(exc))

        if req_id is None:
            return None
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def synthesize(self, params: dict[str, Any]) -> dict[str, Any]:
        session_id = str(params.get("session_id", "")).strip()
        repo_root_raw = str(params.get("repo_root", "")).strip()
        base_commit_sha = str(params.get("base_commit_sha", "")).strip() or "HEAD"
        reported_events = params.get("friction_events")
        regression_cmd = str(params.get("regression_command", "")).strip()

        if not repo_root_raw:
            raise ValueError("repo_root is required")
        repo_root = Path(repo_root_raw).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"repo_root does not exist: {repo_root}")

        if reported_events is not None and not isinstance(reported_events, list):
            raise ValueError("friction_events must be a list")

        db_path = repo_root / ".engram" / ".runtime" / "state.db"
        detected: list[FrictionEvent] = []
        if session_id and db_path.is_file():
            detected = analyze_session(db_path, session_id)

        merged = merge_friction_events(reported_events, detected)
        if not merged:
            raise ValueError("no friction events found to synthesize")

        primary_event = merged[0]

        # Avoid duplicating an already active/verified engram with the exact same failure signature.
        existing = _find_existing_engram(db_path, primary_event.failure_signature)
        if existing is not None:
            return existing

        artifact = self._synthesizer.synthesize(
            repo_root=repo_root,
            event=primary_event,
        )

        eval_res = self._evaluator.evaluate(
            repo_root=repo_root,
            base_commit_sha=base_commit_sha,
            artifact=artifact,
            event=primary_event,
            session_id=session_id,
            regression_command=regression_cmd,
        )

        status = "rejected"
        if eval_res.verified:
            # Only materialize into .engram/ after AST + shadow worktree replay passes (Invariant #4).
            materialize_artifact(repo_root, artifact)
            auto_thresh, min_pass = _load_evolution_thresholds(repo_root)
            if eval_res.pass_rate >= max(auto_thresh, min_pass):
                status = "active"
            else:
                status = "pending_approval"

            _upsert_manifest_entry(repo_root, artifact, status, eval_res.pass_rate)

        _persist_engram_record(
            db_path=db_path,
            artifact=artifact,
            session_id=session_id,
            status=status,
            pass_rate=eval_res.pass_rate,
        )

        return {
            "engram_id": artifact.engram_id,
            "kind": artifact.kind,
            "target_tool": artifact.target_tool,
            "command_regex": artifact.trigger_pattern,
            "file_path": artifact.file_path,
            "shadow_verified": eval_res.verified,
            "shadow_pass_rate": eval_res.pass_rate,
            "status": status,
            "failure_signature": artifact.failure_signature,
            "explanation": artifact.explanation,
        }


class _ThreadedUnixStreamServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def create_uds_server(
    socket_path: str | Path,
    service: EvolutionService | None = None,
) -> _ThreadedUnixStreamServer:
    """Create and bind a threaded Unix Domain Socket JSON-RPC 2.0 server."""
    if not hasattr(socket, "AF_UNIX"):
        raise RuntimeError("AF_UNIX sockets are not supported on this Python platform")

    sock_str = str(socket_path)
    sock_p = Path(sock_str)
    sock_p.parent.mkdir(parents=True, exist_ok=True)
    if sock_p.exists():
        sock_p.unlink()

    svc = service or EvolutionService()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            while True:
                line_bytes = self.rfile.readline(4 * 1024 * 1024)
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                resp = svc.handle_rpc(line)
                if resp is not None:
                    encoded = (json.dumps(resp) + "\n").encode("utf-8")
                    self.wfile.write(encoded)
                    self.wfile.flush()

    return _ThreadedUnixStreamServer(sock_str, Handler)


def serve_forever(socket_path: str | Path, service: EvolutionService | None = None) -> None:
    """Run the UDS JSON-RPC server until SIGINT/SIGTERM."""
    srv = create_uds_server(socket_path, service=service)
    sock_p = Path(str(socket_path))

    def _handle_signal(_signum: int, _frame: Any) -> None:
        srv.shutdown()

    if threading_is_main():
        signal.signal(signal.SIGINT, _handle_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handle_signal)

    try:
        srv.serve_forever(poll_interval=0.2)
    finally:
        srv.server_close()
        if sock_p.exists():
            try:
                sock_p.unlink()
            except OSError:
                pass


def threading_is_main() -> bool:
    import threading
    return threading.current_thread() is threading.main_thread()


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _load_evolution_thresholds(repo_root: Path) -> tuple[float, float]:
    cfg_path = repo_root / ".engram" / "config.toml"
    if not cfg_path.is_file():
        return 1.0, 1.0
    try:
        with cfg_path.open("rb") as f:
            data = tomllib.load(f)
        evo = data.get("evolution", {})
        return (
            float(evo.get("auto_approve_threshold", 1.0)),
            float(evo.get("min_shadow_pass_rate", 1.0)),
        )
    except Exception:
        return 1.0, 1.0


def _find_existing_engram(db_path: Path, failure_signature: str) -> dict[str, Any] | None:
    if not failure_signature or not db_path.is_file():
        return None
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT id, kind, trigger_pattern, file_path, status, shadow_pass_rate, failure_signature
            FROM engrams
            WHERE failure_signature = ? AND status IN ('active', 'pending_approval')
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (failure_signature,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()

    if row is None:
        return None
    return {
        "engram_id": row["id"],
        "kind": row["kind"],
        "target_tool": "bash" if row["kind"] == "hook" else "",
        "command_regex": row["trigger_pattern"],
        "file_path": row["file_path"],
        "shadow_verified": float(row["shadow_pass_rate"] or 0.0) > 0.0,
        "shadow_pass_rate": float(row["shadow_pass_rate"] or 0.0),
        "status": row["status"],
        "failure_signature": row["failure_signature"],
        "explanation": "Reused existing shadow-verified engram for matching failure signature.",
    }


def _persist_engram_record(
    *,
    db_path: Path,
    artifact: SynthesizedArtifact,
    session_id: str,
    status: str,
    pass_rate: float,
) -> None:
    if not db_path.is_file():
        return
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        src_session: str | None = session_id or None
        if src_session is not None:
            exists = conn.execute("SELECT 1 FROM sessions WHERE id = ?", (src_session,)).fetchone()
            if exists is None:
                src_session = None

        conn.execute(
            """
            INSERT INTO engrams (
                id, kind, trigger_pattern, file_path, source_session_id,
                failure_signature, status, shadow_pass_rate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.engram_id,
                artifact.kind,
                artifact.trigger_pattern,
                artifact.file_path,
                src_session,
                artifact.failure_signature,
                status,
                pass_rate,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _upsert_manifest_entry(
    repo_root: Path,
    artifact: SynthesizedArtifact,
    status: str,
    pass_rate: float,
) -> None:
    manifest_path = repo_root / ".engram" / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {"version": "1.0", "hooks": [], "tools": [], "rules": []}
    else:
        manifest = {"version": "1.0", "hooks": [], "tools": [], "rules": []}

    bucket_map = {"hook": "hooks", "tool": "tools", "rule": "rules"}
    bucket_name = bucket_map[artifact.kind]
    entries = list(manifest.get(bucket_name) or [])
    entries = [e for e in entries if e.get("id") != artifact.engram_id]
    entries.append({
        "id": artifact.engram_id,
        "kind": artifact.kind,
        "target_tool": artifact.target_tool,
        "trigger_pattern": artifact.trigger_pattern,
        "file_path": artifact.file_path,
        "status": status,
        "shadow_pass_rate": pass_rate,
        "explanation": artifact.explanation,
    })
    manifest[bucket_name] = entries
    manifest.setdefault("version", "1.0")

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = manifest_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, manifest_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Engram Evolution Compiler JSON-RPC 2.0 UDS Server")
    parser.add_argument("--repo", default=".", help="Path inside target Git repository")
    parser.add_argument("--socket", default="", help="Override Unix Domain Socket path")
    args = parser.parse_args(argv)

    sock_path = args.socket.strip() or socket_path_for_repo(args.repo)
    serve_forever(sock_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())