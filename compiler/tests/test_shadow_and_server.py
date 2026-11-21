from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from engram_compiler.detector import (
    PATTERN_MULTI_STEP_COMMAND,
    PATTERN_REPEATED_TOOL_ERROR,
    FrictionEvent,
)
from engram_compiler.server import (
    EvolutionService,
    UnixJSONRPCServer,
    socket_path_for_repo,
)
from engram_compiler.shadow_eval import ShadowEvaluator
from engram_compiler.synthesizer import (
    KIND_HOOK,
    SynthesizedArtifact,
    Synthesizer,
)


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _init_git_repo(repo_dir: Path) -> str:
    def git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip()

    git("init")
    git("config", "user.email", "compiler-test@engram.local")
    git("config", "user.name", "Engram Compiler Test")
    git("config", "core.autocrlf", "false")

    (repo_dir / "README.md").write_text("# shadow test repo\n", encoding="utf-8")
    (repo_dir / "docker-compose.test.yml").write_text("services:\n  db: {}\n", encoding="utf-8")
    (repo_dir / ".engram").mkdir(parents=True, exist_ok=True)
    (repo_dir / ".engram" / ".gitignore").write_text(".runtime/\n", encoding="utf-8")
    git("add", "README.md", "docker-compose.test.yml", ".engram/.gitignore")
    git("commit", "-m", "initial commit")
    return git("rev-parse", "HEAD")


def _seed_sqlite_session(repo_dir: Path, session_id: str, base_sha: str, port: int) -> Path:
    db_path = repo_dir / ".engram" / ".runtime" / "state.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                task_prompt TEXT NOT NULL,
                base_commit_sha TEXT NOT NULL,
                worktree_path TEXT NOT NULL,
                status TEXT CHECK(status IN ('running', 'completed', 'failed', 'aborted')) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS steps (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                step_index INTEGER NOT NULL,
                git_commit_sha TEXT NOT NULL,
                thought TEXT,
                tool_name TEXT,
                tool_input_json TEXT,
                tool_output_summary TEXT,
                raw_artifact_path TEXT,
                exit_code INTEGER,
                duration_ms INTEGER,
                tokens_in INTEGER,
                tokens_out INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(session_id, step_index)
            );
            CREATE TABLE IF NOT EXISTS engrams (
                id TEXT PRIMARY KEY,
                kind TEXT CHECK(kind IN ('hook', 'tool', 'rule')) NOT NULL,
                trigger_pattern TEXT NOT NULL,
                file_path TEXT NOT NULL,
                source_session_id TEXT REFERENCES sessions(id),
                failure_signature TEXT NOT NULL,
                status TEXT CHECK(status IN ('shadow_testing', 'pending_approval', 'active', 'rejected')) NOT NULL,
                shadow_pass_rate REAL DEFAULT 0.0,
                times_triggered INTEGER DEFAULT 0,
                times_prevented_error INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            "INSERT INTO sessions (id, task_prompt, base_commit_sha, worktree_path, status) VALUES (?, ?, ?, ?, ?)",
            (session_id, "Run API tests", base_sha, str(repo_dir / ".engram" / ".runtime" / "worktrees" / session_id), "failed"),
        )
        for step_idx in (4, 5, 6):
            conn.execute(
                """
                INSERT INTO steps (
                    id, session_id, step_index, git_commit_sha,
                    tool_name, tool_input_json, tool_output_summary, exit_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"step_{step_idx}",
                    session_id,
                    step_idx,
                    base_sha,
                    "bash",
                    json.dumps({"command": "pytest tests/api"}),
                    f"ConnectionRefusedError on port {port}",
                    1,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path


def _send_uds_rpc(sock_path: Path, payload: dict) -> dict:
    if hasattr(socket, "AF_UNIX"):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target: str | tuple[str, int] = str(sock_path)
    else:
        endpoint = sock_path.read_text(encoding="utf-8").strip()
        addr = endpoint.removeprefix("tcp://")
        host, port_str = addr.rsplit(":", 1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target = (host, int(port_str))

    with client:
        client.settimeout(30.0)
        client.connect(target)
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8"))


class ShadowAndServerTests(unittest.TestCase):
    def test_shadow_evaluator_verifies_hook_without_mutating_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo(repo)
            unused_port = _unused_tcp_port()

            ev = FrictionEvent(
                step_range=[4, 6],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary=f"Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port {unused_port}.",
                failure_signature="repeated_tool_error:bash:deadbeef",
                command_sample="pytest tests/api",
                error_sample=f"ConnectionRefusedError on port {unused_port}",
                exit_codes=[1, 1, 1],
            )
            artifact = Synthesizer().synthesize(repo_root=repo, event=ev, engram_id="eng_SHADOW1")

            eval_res = ShadowEvaluator().evaluate(
                repo_root=repo,
                base_commit_sha=base_sha,
                artifact=artifact,
                event=ev,
            )
            self.assertTrue(eval_res.verified, msg=f"eval_res={eval_res}")
            self.assertEqual(eval_res.pass_rate, 1.0)

            # Invariant #1: host repo must remain completely clean and shadow worktree removed.
            status = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(status, "")

            wt_list = subprocess.run(
                ["git", "-C", str(repo), "worktree", "list"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertNotIn("shadow_eng_SHADOW1", wt_list)

    def test_shadow_evaluator_rejects_hook_that_fails_to_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo(repo)

            broken_hook = SynthesizedArtifact(
                engram_id="eng_BROKEN1",
                kind=KIND_HOOK,
                target_tool="bash",
                trigger_pattern=r"^pytest\b",
                file_path=".engram/hooks/eng_BROKEN1_noop.py",
                failure_signature="sig_broken",
                explanation="Broken hook that always exits 0.",
                content="import json, sys\n_ = json.load(sys.stdin)\nsys.exit(0)\n",
            )
            ev = FrictionEvent(
                step_range=[1, 3],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="pytest failed",
                failure_signature="sig_broken",
                command_sample="pytest tests/api",
            )
            eval_res = ShadowEvaluator().evaluate(
                repo_root=repo,
                base_commit_sha=base_sha,
                artifact=broken_hook,
                event=ev,
            )
            self.assertFalse(eval_res.verified)
            self.assertLess(eval_res.pass_rate, 1.0)

    def test_shadow_evaluator_verifies_synthesized_mcp_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo(repo)
            ev = FrictionEvent(
                step_range=[2, 5],
                pattern=PATTERN_MULTI_STEP_COMMAND,
                tool_name="bash",
                summary="Repeated 2-step sequence",
                failure_signature="sig_tool_shadow",
                command_sequence=["echo shadow_a", "echo shadow_b"],
            )
            artifact = Synthesizer().synthesize(repo_root=repo, event=ev, engram_id="eng_TOOL1")
            eval_res = ShadowEvaluator().evaluate(
                repo_root=repo,
                base_commit_sha=base_sha,
                artifact=artifact,
                event=ev,
            )
            self.assertTrue(eval_res.verified, msg=f"eval_res={eval_res}")
            self.assertEqual(eval_res.pass_rate, 1.0)

    def test_uds_jsonrpc_server_ping_and_synthesize_end_to_end(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("AF_UNIX not supported in this Python build")

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            base_sha = _init_git_repo(repo)
            unused_port = _unused_tcp_port()
            db_path = _seed_sqlite_session(repo, "sess_01J9W8K2", base_sha, unused_port)

            sock_path = Path(tmp) / "engram-test.sock"
            server = UnixJSONRPCServer(sock_path, service=EvolutionService())
            server.start_background()
            try:
                # 1. Ping check
                ping_resp = _send_uds_rpc(
                    sock_path,
                    {"jsonrpc": "2.0", "id": "req_ping", "method": "compiler.ping", "params": {}},
                )
                self.assertEqual(ping_resp["result"]["status"], "ok")

                # 2. Section 5 compiler.synthesize RPC call
                synth_resp = _send_uds_rpc(
                    sock_path,
                    {
                        "jsonrpc": "2.0",
                        "id": "req_8912",
                        "method": "compiler.synthesize",
                        "params": {
                            "session_id": "sess_01J9W8K2",
                            "repo_root": str(repo),
                            "base_commit_sha": base_sha,
                            "friction_events": [
                                {
                                    "step_range": [4, 6],
                                    "pattern": PATTERN_REPEATED_TOOL_ERROR,
                                    "tool_name": "bash",
                                    "summary": f"Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port {unused_port}.",
                                }
                            ],
                        },
                    },
                )
                self.assertEqual(synth_resp["id"], "req_8912")
                self.assertNotIn("error", synth_resp, msg=f"unexpected error: {synth_resp}")

                res = synth_resp["result"]
                self.assertEqual(res["kind"], "hook")
                self.assertEqual(res["target_tool"], "bash")
                self.assertEqual(res["command_regex"], r"^pytest\b")
                self.assertTrue(res["shadow_verified"])
                self.assertEqual(res["status"], "active")

                # Verify hook file materialized under .engram/hooks/
                hook_file = repo / res["file_path"]
                self.assertTrue(hook_file.is_file(), msg=f"missing {hook_file}")

                # Verify manifest.json updated
                manifest = json.loads((repo / ".engram" / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(len(manifest["hooks"]), 1)
                self.assertEqual(manifest["hooks"][0]["id"], res["engram_id"])

                # Verify SQLite engrams row persisted with shadow_pass_rate = 1.0 and status = active
                conn = sqlite3.connect(db_path)
                try:
                    row = conn.execute(
                        "SELECT kind, status, shadow_pass_rate FROM engrams WHERE id = ?",
                        (res["engram_id"],),
                    ).fetchone()
                finally:
                    conn.close()
                self.assertEqual(row, ("hook", "active", 1.0))
            finally:
                server.shutdown()

            # Verify socket_path_for_repo produces deterministic short paths.
            p1 = socket_path_for_repo(repo)
            p2 = socket_path_for_repo(repo)
            self.assertEqual(p1, p2)
            self.assertIn("engram-", p1.name)


if __name__ == "__main__":
    unittest.main()