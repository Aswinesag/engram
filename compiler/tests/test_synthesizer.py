from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from engram_compiler.detector import FrictionEvent, PatternType
from engram_compiler.synthesizer import (
    ASTValidationError,
    Synthesizer,
    validate_python_ast,
)


class FakeLLMClient:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls = 0

    def generate_json(self, system_prompt: str, user_prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return self.payload


class SynthesizerTests(unittest.TestCase):
    def test_ast_validator_rejects_syntax_non_stdlib_and_eval(self) -> None:
        with self.assertRaises(ASTValidationError):
            validate_python_ast("def broken(:\n  pass", kind="hook")

        with self.assertRaises(ASTValidationError):
            validate_python_ast("import requests\nimport sys\nsys.exit(2)\n", kind="hook")

        with self.assertRaises(ASTValidationError):
            validate_python_ast("import sys\neval('1+1')\nsys.exit(2)\n", kind="hook")

        with self.assertRaises(ASTValidationError):
            validate_python_ast("import sys\nsys.exit(0)\n", kind="hook")

    def test_deterministic_hook_synthesis_for_postgres_port_5432(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docker-compose.test.yml").write_text("services: {}\n", encoding="utf-8")

            event = FrictionEvent(
                step_range=(4, 7),
                pattern=PatternType.REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port 5432.",
                failure_signature="repeated_tool_error:bash:a1b2c3d4e5f6",
                command="pytest tests/api",
                error_excerpt="ConnectionRefusedError: port 5432",
                occurrences=3,
            )

            synth = Synthesizer()
            eng = synth.synthesize(repo_root=repo, friction_events=[event], engram_id="eng_01J9X4M9")

            self.assertEqual(eng.kind, "hook")
            self.assertEqual(eng.target_tool, "bash")
            self.assertEqual(eng.trigger_pattern, r"^pytest\b")
            self.assertEqual(eng.file_path, ".engram/hooks/eng_01J9X4M9_verify_service_port.py")
            self.assertTrue(eng.ast_validated)
            self.assertIn("docker-compose.test.yml", eng.content)

            written = eng.write_to_repo(repo)
            self.assertTrue(written.exists())

            # Executing the generated hook against closed port 5432 (or unreachable port) must exit 2.
            # Patch TARGET_PORT in memory check or run against unused ephemeral port in subprocess:
            proc = subprocess.run(
                [sys.executable, str(written)],
                input=json.dumps({"phase": "pre", "tool_name": "bash"}).encode("utf-8"),
                capture_output=True,
                timeout=10,
            )
            # Port 5432 is normally closed in test sandboxes -> exit 2 with docker compose guidance.
            if proc.returncode == 2:
                self.assertIn(b"docker-compose.test.yml", proc.stdout)
            else:
                # If a developer machine happens to run Postgres on 5432, hook cleanly allows with exit 0.
                self.assertEqual(proc.returncode, 0)

    def test_llm_structured_synthesis_validates_mcp_tool_via_ast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            mcp_code = (
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    msg = json.loads(line)\n"
                "    m = msg.get('method')\n"
                "    if m == 'initialize':\n"
                "        resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'safe_migrate', 'version': '1.0'}}}\n"
                "    elif m == 'tools/list':\n"
                "        resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': []}}\n"
                "    elif m == 'tools/call':\n"
                "        resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {'content': [{'type': 'text', 'text': 'ok'}]}}\n"
                "    else:\n"
                "        continue\n"
                "    sys.stdout.write(json.dumps(resp) + '\\n')\n"
                "    sys.stdout.flush()\n"
            )
            client = FakeLLMClient(
                {
                    "kind": "tool",
                    "target_tool": "bash",
                    "trigger_pattern": "safe_migrate",
                    "file_slug": "safe_migrate",
                    "code": mcp_code,
                    "explanation": "Replaces fragile migration command chain with typed MCP tool.",
                }
            )
            event = FrictionEvent(
                step_range=(2, 5),
                pattern=PatternType.MULTI_STEP_RETRY_LOOP,
                tool_name="bash",
                summary="Repeated migration retry loop.",
                failure_signature="multi_step_retry_loop:bash:112233445566",
                command="alembic upgrade head",
            )

            eng = Synthesizer(llm_client=client).synthesize(repo_root=repo, friction_events=[event], engram_id="eng_01J9Y001")
            self.assertEqual(client.calls, 1)
            self.assertEqual(eng.kind, "tool")
            self.assertEqual(eng.file_path, ".engram/tools/eng_01J9Y001_safe_migrate.py")
            self.assertTrue(eng.ast_validated)

    def test_invalid_llm_ast_falls_back_to_deterministic_safe_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            # LLM returns unsafe code using eval() + third-party import -> must be rejected and fall back safely.
            bad_client = FakeLLMClient(
                {
                    "kind": "hook",
                    "target_tool": "bash",
                    "trigger_pattern": "^pytest\\b",
                    "file_slug": "bad_hook",
                    "code": "import requests\neval('1')\n",
                    "explanation": "unsafe",
                }
            )
            event = FrictionEvent(
                step_range=(1, 3),
                pattern=PatternType.REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="ConnectionRefusedError on port 5432",
                failure_signature="repeated_tool_error:bash:deadbeef",
                command="pytest",
                error_excerpt="ConnectionRefusedError: port 5432",
            )

            eng = Synthesizer(llm_client=bad_client).synthesize(repo_root=repo, friction_events=[event], engram_id="eng_SAFE1")
            self.assertEqual(eng.kind, "hook")
            self.assertTrue(eng.ast_validated)
            self.assertNotIn("requests", eng.content)
            self.assertNotIn("eval", eng.content)

    def test_circular_edit_synthesizes_glob_scoped_markdown_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            event = FrictionEvent(
                step_range=(2, 6),
                pattern=PatternType.CIRCULAR_FILE_EDIT,
                tool_name="write_file",
                summary="Agent repeatedly edited src/api/routes.py 4 times.",
                failure_signature="circular_file_edit:write_file:998877665544",
                target_path="src/api/routes.py",
                occurrences=4,
            )

            eng = Synthesizer().synthesize(repo_root=repo, friction_events=[event], engram_id="eng_RULE1")
            self.assertEqual(eng.kind, "rule")
            self.assertEqual(eng.file_path, ".engram/rules/eng_RULE1_guard_routes.md")
            self.assertIn('globs: ["src/api/routes.py"]', eng.content)


if __name__ == "__main__":
    unittest.main()