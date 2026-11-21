from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from engram_compiler.detector import (
    PATTERN_MULTI_STEP_COMMAND,
    PATTERN_REPEATED_TOOL_ERROR,
    FrictionEvent,
)
from engram_compiler.server import (
    EvolutionService,
    create_uds_server,
    socket_path_for_repo,
)
from engram_compiler.shadow_eval import ShadowEvaluator
from engram_compiler.synthesizer import KIND_HOOK, SynthesizedArtifact, Synthesizer


def _init_git_repo_with_engram(root: Path, session_id: str = "sess_01J9W8K2") -> str:
    def git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip()

    git("init")
    git("config", "user.email", "compiler-test@engram.local")
    git("config", "user.name", "Engram Test")
    git("config", "core.autocrlf", "false")

    (root / "app.py").write_text("def ok():\n    return True\n", encoding="utf-8")
    (root / "docker-compose.test.yml").write_text("services:\n  db: {}\n", encoding="utf-8")
    git("add", "app.py", "docker-compose.test.yml")
    git("commit", "-m", "initial commit")
    base_sha = git("rev-parse", "HEAD")

    engram_dir = root / ".engram"
    for sub in ("hooks", "tools", "rules", ".runtime/worktrees", ".runtime/artifacts"):
        (engram_dir / sub).mkdir(parents=True, exist_ok=True)

    (engram_dir / ".gitignore").write_text(".runtime/\n", encoding="utf-8")
    (engram_dir / "config.toml").write_text(
        "[evolution]\nauto_approve_threshold = 1.0\nmin_shadow_pass_rate = 1.0\n",
        encoding="utf-8",
    )
    (engram_dir / "manifest.json").write_text(
        json.dumps({"version": "1.0", "hooks": [], "tools": [], "rules": []}, indent=2),
        encoding="utf-8",
    )

    db_path = engram_dir / ".runtime" / "state.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                task_prompt TEXT NOT NULL,
                base_commit_sha TEXT NOT NULL,
                worktree_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE steps (
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
            CREATE TABLE engrams (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                trigger_pattern TEXT NOT NULL,
                file_path TEXT NOT NULL,
                source_session_id TEXT REFERENCES sessions(id),
                failure_signature TEXT NOT NULL,
                status TEXT NOT NULL,
                shadow_pass_rate REAL DEFAULT 0.0,
                times_triggered INTEGER DEFAULT 0,
                times_prevented_error INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            "INSERT INTO sessions (id, task_prompt, base_commit_sha, worktree_path, status) VALUES (?, ?, ?, ?, ?)",
            (session_id, "Run pytest tests/api", base_sha, str(engram_dir / ".runtime/worktrees" / session_id), "failed"),
        )
        for idx in (4, 5, 6):
            conn.execute(
                """
                INSERT INTO steps (
                    id, session_id, step_index, git_commit_sha,
                    tool_name, tool_input_json, tool_output_summary, exit_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"step_{idx}",
                    session_id,
                    idx,
                    base_sha,
                    "bash",
                    '{"command":"pytest tests/api"}',
                    "ConnectionRefusedError on port 5432",
                    1,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    return base_sha


class ShadowEvalAndServerTests(unittest.TestCase):
    def test_shadow_evaluator_verifies_hook_and_cleans_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo_with_engram(repo)

            # Pick an unused local TCP port so the synthesized port-check hook blocks deterministically.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                unused_port = probe.getsockname()[1]

            ev = FrictionEvent(
                step_range=[4, 6],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary=f"Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port {unused_port}.",
                failure_signature=f"repeated_tool_error:bash:port_{unused_port}",
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
                session_id="sess_01J9W8K2",
            )
            self.assertTrue(eval_res.verified, msg=eval_res.details)
            self.assertEqual(eval_res.pass_rate, 1.0)

            # Host repo must NOT have the unpromoted artifact written yet during pure shadow eval.
            self.assertFalse((repo / artifact.file_path).exists())
            # Shadow worktrees directory must be empty after cleanup.
            remaining = list((repo / ".engram" / ".runtime" / "worktrees").iterdir())
            self.assertEqual(remaining, [])

    def test_shadow_evaluator_rejects_broken_hook_invariant_4(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo_with_engram(repo)

            bad_hook = SynthesizedArtifact(
                engram_id="eng_BADHOOK",
                kind=KIND_HOOK,
                target_tool="bash",
                trigger_pattern=r"^pytest\b",
                file_path=".engram/hooks/eng_BADHOOK_noop.py",
                failure_signature="sig_bad",
                explanation="Always allows even when failing.",
                content="import json, sys\n_ = json.load(sys.stdin)\nsys.exit(0)\n",
            )
            ev = FrictionEvent(
                step_range=[4, 6],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="pytest failed",
                failure_signature="sig_bad",
                command_sample="pytest tests/api",
            )

            eval_res = ShadowEvaluator().evaluate(
                repo_root=repo,
                base_commit_sha=base_sha,
                artifact=bad_hook,
                event=ev,
            )
            self.assertFalse(eval_res.verified)
            self.assertLess(eval_res.pass_rate, 1.0)

    def test_shadow_evaluator_verifies_mcp_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo_with_engram(repo)

            ev = FrictionEvent(
                step_range=[1, 4],
                pattern=PATTERN_MULTI_STEP_COMMAND,
                tool_name="bash",
                summary="Repeated 2-step sequence",
                failure_signature="sig_mcp_shadow",
                command_sequence=["echo shadow_a", "echo shadow_b"],
            )
            artifact = Synthesizer().synthesize(repo_root=repo, event=ev, engram_id="eng_TOOLSHDW")
            eval_res = ShadowEvaluator().evaluate(
                repo_root=repo,
                base_commit_sha=base_sha,
                artifact=artifact,
                event=ev,
            )
            self.assertTrue(eval_res.verified, msg=eval_res.details)
            self.assertEqual(eval_res.pass_rate, 1.0)

    def test_uds_jsonrpc_server_synthesizes_verifies_and_persists(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("AF_UNIX not supported on this platform")

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base_sha = _init_git_repo_with_engram(repo)

            sock_path = Path(tmp) / "engram-test.sock"
            srv = create_uds_server(sock_path, service=EvolutionService())
            thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()

            try:
                req = {
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
                                "pattern": "REPEATED_TOOL_ERROR",
                                "tool_name": "bash",
                                "summary": "Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port 5432.",
                            }
                        ],
                    },
                }

                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(15.0)
                    client.connect(str(sock_path))
                    client.sendall((json.dumps(req) + "\n").encode("utf-8"))

                    buf = b""
                    while not buf.endswith(b"\n"):
                        chunk = client.recv(65536)
                        if not chunk:
                            break
                        buf += chunk

                resp = json.loads(buf.decode("utf-8").strip())
                self.assertEqual(resp["jsonrpc"], "2.0")
                self.assertEqual(resp["id"], "req_8912")
                res = resp["result"]
                self.assertEqual(res["kind"], "hook")
                self.assertEqual(res["target_tool"], "bash")
                self.assertEqual(res["command_regex"], r"^pytest\b")
                self.assertTrue(res["shadow_verified"])
                self.assertEqual(res["status"], "active")
                self.assertTrue((repo / res["file_path"]).is_file())

                # Verify manifest.json and SQLite engrams table were updated atomically.
                manifest = json.loads((repo / ".engram" / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(len(manifest["hooks"]), 1)
                self.assertEqual(manifest["hooks"][0]["id"], res["engram_id"])

                conn = sqlite3.connect(repo / ".engram" / ".runtime" / "state.db")
                row = conn.execute("SELECT status, shadow_pass_rate FROM engrams WHERE id = ?", (res["engram_id"],)).fetchone()
                conn.close()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "active")
                self.assertEqual(row[1], 1.0)
            finally:
                srv.shutdown()
                srv.server_close()
                thread.join(timeout=2.0)

    def test_socket_path_for_repo_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p1 = socket_path_for_repo(tmp)
            p2 = socket_path_for_repo(tmp)
            self.assertEqual(p1, p2)
            self.assertTrue(p1.endswith(".sock"))


if __name__ == "__main__":
    unittest.main()