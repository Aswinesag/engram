from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from engram_compiler.detector import (
    FrictionDetector,
    PatternType,
    StepRecord,
    normalize_failure_text,
)

REPO_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "internal" / "store" / "schema.sql"


class FrictionDetectorTests(unittest.TestCase):
    def test_detects_repeated_tool_error_and_normalizes_signature(self) -> None:
        detector = FrictionDetector(repeated_error_threshold=3)

        steps = [
            StepRecord(
                id="s1",
                session_id="sess_01",
                step_index=1,
                git_commit_sha="aaa111",
                tool_name="read_file",
                tool_input_json='{"path":"tests/api/test_users.py"}',
                exit_code=0,
            ),
            StepRecord(
                id="s4",
                session_id="sess_01",
                step_index=4,
                git_commit_sha="aaa111",
                tool_name="bash",
                tool_input_json='{"command":"pytest tests/api"}',
                tool_output_summary="exit_code=1\nConnectionRefusedError: [Errno 111] Connection refused on port 5432 at 2026-11-21T10:00:01Z",
                exit_code=1,
            ),
            StepRecord(
                id="s5",
                session_id="sess_01",
                step_index=5,
                git_commit_sha="aaa111",
                tool_name="bash",
                tool_input_json='{"command":"pytest tests/api"}',
                tool_output_summary="exit_code=1\nConnectionRefusedError: [Errno 111] Connection refused on port 5432 at 2026-11-21T10:00:04Z",
                exit_code=1,
            ),
            StepRecord(
                id="s6",
                session_id="sess_01",
                step_index=6,
                git_commit_sha="aaa111",
                tool_name="bash",
                tool_input_json='{"command":"pytest tests/api"}',
                tool_output_summary="exit_code=1\nConnectionRefusedError: [Errno 111] Connection refused on port 5432 at 2026-11-21T10:00:09Z",
                exit_code=1,
            ),
        ]

        events = detector.analyze_steps(steps)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.pattern, PatternType.REPEATED_TOOL_ERROR)
        self.assertEqual(ev.step_range, (4, 6))
        self.assertEqual(ev.tool_name, "bash")
        self.assertEqual(ev.command, "pytest tests/api")
        self.assertIn("ConnectionRefusedError", ev.summary)

        ipc = ev.to_ipc_dict()
        self.assertEqual(set(ipc.keys()), {"step_range", "pattern", "tool_name", "summary"})
        self.assertEqual(ipc["step_range"], [4, 6])
        self.assertEqual(ipc["pattern"], "REPEATED_TOOL_ERROR")

        # Normalization must produce identical signatures across different timestamps/paths.
        sig_a = normalize_failure_text(
            "ConnectionRefusedError: line 42 in /tmp/wt_a/test.py at 2026-11-21T10:00:01Z"
        )
        sig_b = normalize_failure_text(
            "ConnectionRefusedError: line 99 in /tmp/wt_b/test.py at 2026-11-21T11:22:33Z"
        )
        self.assertEqual(sig_a, sig_b)

    def test_detects_circular_file_edit_with_oscillation(self) -> None:
        detector = FrictionDetector(circular_edit_threshold=3)

        steps = [
            StepRecord(
                id="s1",
                session_id="sess_02",
                step_index=1,
                git_commit_sha="sha1",
                tool_name="write_file",
                tool_input_json=json.dumps({"path": "src/api/routes.py", "content": "async def f(): return 1\n"}),
                exit_code=0,
            ),
            StepRecord(
                id="s2",
                session_id="sess_02",
                step_index=2,
                git_commit_sha="sha2",
                tool_name="write_file",
                tool_input_json=json.dumps({"path": "src/api/routes.py", "content": "def f(): return 2\n"}),
                exit_code=0,
            ),
            StepRecord(
                id="s3",
                session_id="sess_02",
                step_index=3,
                git_commit_sha="sha3",
                tool_name="write_file",
                tool_input_json=json.dumps({"path": "src/api/routes.py", "content": "async def f(): return 1\n"}),
                exit_code=0,
            ),
        ]

        events = detector.analyze_steps(steps)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.pattern, PatternType.CIRCULAR_FILE_EDIT)
        self.assertEqual(ev.target_path, "src/api/routes.py")
        self.assertEqual(ev.step_range, (1, 3))
        self.assertTrue(ev.metadata["oscillated"])

    def test_detects_multi_step_retry_loop(self) -> None:
        detector = FrictionDetector(repeated_error_threshold=3, circular_edit_threshold=3, retry_cycle_threshold=2)

        steps = [
            StepRecord(
                id="s1",
                session_id="sess_03",
                step_index=1,
                git_commit_sha="sha1",
                tool_name="write_file",
                tool_input_json='{"path":"app/db.py","content":"v1"}',
                exit_code=0,
            ),
            StepRecord(
                id="s2",
                session_id="sess_03",
                step_index=2,
                git_commit_sha="sha1",
                tool_name="bash",
                tool_input_json='{"command":"pytest tests/test_db.py"}',
                tool_output_summary="AssertionError: expected 200 got 500",
                exit_code=1,
            ),
            StepRecord(
                id="s3",
                session_id="sess_03",
                step_index=3,
                git_commit_sha="sha2",
                tool_name="write_file",
                tool_input_json='{"path":"app/db.py","content":"v2"}',
                exit_code=0,
            ),
            StepRecord(
                id="s4",
                session_id="sess_03",
                step_index=4,
                git_commit_sha="sha2",
                tool_name="bash",
                tool_input_json='{"command":"pytest tests/test_db.py"}',
                tool_output_summary="AssertionError: expected 200 got 500",
                exit_code=1,
            ),
        ]

        events = detector.analyze_steps(steps)
        patterns = {e.pattern for e in events}
        self.assertIn(PatternType.MULTI_STEP_RETRY_LOOP, patterns)

    def test_no_false_positives_on_transient_single_error(self) -> None:
        detector = FrictionDetector()
        steps = [
            StepRecord(
                id="s1",
                session_id="sess_04",
                step_index=1,
                git_commit_sha="sha1",
                tool_name="bash",
                tool_input_json='{"command":"pytest"}',
                tool_output_summary="ModuleNotFoundError: foo",
                exit_code=1,
            ),
            StepRecord(
                id="s2",
                session_id="sess_04",
                step_index=2,
                git_commit_sha="sha2",
                tool_name="write_file",
                tool_input_json='{"path":"foo.py","content":"x = 1"}',
                exit_code=0,
            ),
            StepRecord(
                id="s3",
                session_id="sess_04",
                step_index=3,
                git_commit_sha="sha2",
                tool_name="bash",
                tool_input_json='{"command":"pytest"}',
                tool_output_summary="5 passed",
                exit_code=0,
            ),
        ]
        self.assertEqual(detector.analyze_steps(steps), [])

    def test_analyze_session_reads_sqlite_wal_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "state.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(REPO_SCHEMA_PATH.read_text(encoding="utf-8"))
            conn.execute(
                """
                INSERT INTO sessions (id, task_prompt, base_commit_sha, worktree_path, status)
                VALUES ('sess_wal', 'Fix API tests', 'a1b2c3d4', '/tmp/wt', 'failed')
                """
            )
            for idx in range(1, 4):
                conn.execute(
                    """
                    INSERT INTO steps (id, session_id, step_index, git_commit_sha, tool_name, tool_input_json, tool_output_summary, exit_code)
                    VALUES (?, 'sess_wal', ?, 'a1b2c3d4', 'bash', '{"command":"pytest tests/api"}', 'ConnectionRefusedError: port 5432', 1)
                    """,
                    (f"st_{idx}", idx),
                )
            conn.commit()
            conn.close()

            detector = FrictionDetector()
            events = detector.analyze_session(db_path, "sess_wal")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].pattern, PatternType.REPEATED_TOOL_ERROR)
            self.assertEqual(events[0].step_range, (1, 3))


if __name__ == "__main__":
    unittest.main()