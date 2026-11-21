from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from engram_compiler.detector import (
    PATTERN_CIRCULAR_FILE_EDIT,
    PATTERN_MULTI_STEP_COMMAND,
    PATTERN_REPEATED_TOOL_ERROR,
    FrictionEvent,
    StepRecord,
    analyze_session,
    detect_friction,
    merge_friction_events,
    normalize_failure_signature,
)


def _create_test_db(db_path: Path, session_id: str, steps: list[StepRecord]) -> None:
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
                status TEXT NOT NULL
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
                tokens_out INTEGER
            );
            """
        )
        conn.execute(
            "INSERT INTO sessions (id, task_prompt, base_commit_sha, worktree_path, status) VALUES (?, ?, ?, ?, ?)",
            (session_id, "Run API tests", "a1b2c3d4", "/tmp/wt", "failed"),
        )
        for s in steps:
            conn.execute(
                """
                INSERT INTO steps (
                    id, session_id, step_index, git_commit_sha, thought,
                    tool_name, tool_input_json, tool_output_summary,
                    raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    s.id,
                    s.session_id,
                    s.step_index,
                    s.git_commit_sha,
                    s.thought,
                    s.tool_name,
                    s.tool_input_json,
                    s.tool_output_summary,
                    s.raw_artifact_path,
                    s.exit_code,
                    s.duration_ms,
                    s.tokens_in,
                    s.tokens_out,
                ),
            )
        conn.commit()
    finally:
        conn.close()


class DetectorTests(unittest.TestCase):
    def test_analyze_session_detects_repeated_tool_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "state.db"
            steps = [
                StepRecord("s1", "sess_1", 1, "sha1", tool_name="read_file", tool_input_json='{"path":"README.md"}', exit_code=0),
                StepRecord(
                    "s2", "sess_1", 2, "sha1",
                    tool_name="bash",
                    tool_input_json='{"command":"pytest tests/api"}',
                    tool_output_summary="psycopg.OperationalError: ConnectionRefusedError on port 5432",
                    exit_code=1,
                ),
                StepRecord(
                    "s3", "sess_1", 3, "sha1",
                    tool_name="bash",
                    tool_input_json='{"command":"pytest tests/api -k health"}',
                    tool_output_summary="psycopg.OperationalError: ConnectionRefusedError on port 5432",
                    exit_code=1,
                ),
                StepRecord(
                    "s4", "sess_1", 4, "sha1",
                    tool_name="bash",
                    tool_input_json='{"command":"pytest tests/api"}',
                    tool_output_summary="psycopg.OperationalError: ConnectionRefusedError on port 5432",
                    exit_code=1,
                ),
            ]
            _create_test_db(db_path, "sess_1", steps)

            events = analyze_session(db_path, "sess_1")
            self.assertEqual(len(events), 1)
            ev = events[0]
            self.assertEqual(ev.pattern, PATTERN_REPEATED_TOOL_ERROR)
            self.assertEqual(ev.step_range, [2, 4])
            self.assertEqual(ev.tool_name, "bash")
            self.assertIn("ConnectionRefusedError", ev.error_sample)
            self.assertEqual(ev.exit_codes, [1, 1, 1])

            rpc = ev.to_rpc_dict()
            self.assertEqual(set(rpc.keys()), {"step_range", "pattern", "tool_name", "summary"})

    def test_detect_circular_file_edit_and_multi_step_command_patterns(self) -> None:
        steps = [
            StepRecord("1", "sess_2", 1, "sha", tool_name="write_file", tool_input_json='{"path":"src/api/routes.py","content":"a"}', exit_code=0),
            StepRecord("2", "sess_2", 2, "sha", tool_name="bash", tool_input_json='{"command":"docker compose -f docker-compose.test.yml up -d db"}', exit_code=0),
            StepRecord("3", "sess_2", 3, "sha", tool_name="bash", tool_input_json='{"command":"alembic upgrade head"}', exit_code=0),
            StepRecord("4", "sess_2", 4, "sha", tool_name="write_file", tool_input_json='{"path":"src/api/routes.py","content":"b"}', exit_code=0),
            StepRecord("5", "sess_2", 5, "sha", tool_name="bash", tool_input_json='{"command":"docker compose -f docker-compose.test.yml up -d db"}', exit_code=0),
            StepRecord("6", "sess_2", 6, "sha", tool_name="bash", tool_input_json='{"command":"alembic upgrade head"}', exit_code=0),
            StepRecord("7", "sess_2", 7, "sha", tool_name="write_file", tool_input_json='{"path":"src/api/routes.py","content":"c"}', exit_code=0),
        ]

        events = detect_friction(steps)
        patterns = {e.pattern for e in events}
        self.assertIn(PATTERN_CIRCULAR_FILE_EDIT, patterns)
        self.assertIn(PATTERN_MULTI_STEP_COMMAND, patterns)

        circular = next(e for e in events if e.pattern == PATTERN_CIRCULAR_FILE_EDIT)
        self.assertEqual(circular.target_paths, ["src/api/routes.py"])
        self.assertEqual(circular.step_range, [1, 7])

        chain = next(e for e in events if e.pattern == PATTERN_MULTI_STEP_COMMAND)
        self.assertEqual(
            chain.command_sequence,
            ["docker compose -f docker-compose.test.yml up -d db", "alembic upgrade head"],
        )

    def test_failure_signature_is_stable_across_volatile_tokens(self) -> None:
        sig_tuesday = normalize_failure_signature(
            PATTERN_REPEATED_TOOL_ERROR,
            "bash",
            "2026-11-17T10:15:00Z /repo/.engram/.runtime/worktrees/sess_abc/test.py:42 ConnectionRefusedError commit deadbeef12345678",
        )
        sig_wednesday = normalize_failure_signature(
            PATTERN_REPEATED_TOOL_ERROR,
            "bash",
            "2026-11-18T09:02:11Z /repo/.engram/.runtime/worktrees/sess_xyz/test.py:99 ConnectionRefusedError commit cafe9876543210ab",
        )
        self.assertEqual(sig_tuesday, sig_wednesday)

    def test_merge_friction_events_enriches_go_payload(self) -> None:
        reported = [
            {
                "step_range": [4, 7],
                "pattern": PATTERN_REPEATED_TOOL_ERROR,
                "tool_name": "bash",
                "summary": "Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port 5432.",
            }
        ]
        detected = [
            FrictionEvent(
                step_range=[4, 6],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="Detected 3 errors",
                failure_signature="repeated_tool_error:bash:1234567890abcdef",
                command_sample="pytest tests/api",
                error_sample="ConnectionRefusedError on port 5432",
                exit_codes=[1, 1, 1],
            )
        ]

        merged = merge_friction_events(reported, detected)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].command_sample, "pytest tests/api")
        self.assertEqual(merged[0].failure_signature, "repeated_tool_error:bash:1234567890abcdef")
        # Ensure JSON serialization stays clean.
        self.assertTrue(json.dumps(merged[0].to_rpc_dict()))


if __name__ == "__main__":
    unittest.main()