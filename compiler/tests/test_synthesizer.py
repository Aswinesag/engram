from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from engram_compiler.detector import (
    PATTERN_CIRCULAR_FILE_EDIT,
    PATTERN_MULTI_STEP_COMMAND,
    PATTERN_REPEATED_TOOL_ERROR,
    FrictionEvent,
)
from engram_compiler.synthesizer import (
    KIND_HOOK,
    KIND_RULE,
    KIND_TOOL,
    ModelSettings,
    SynthesisError,
    Synthesizer,
    materialize_artifact,
    validate_python_artifact,
    validate_rule_markdown,
)


class SynthesizerTests(unittest.TestCase):
    def test_validate_python_artifact_rejects_unsafe_code_and_non_stdlib_imports(self) -> None:
        bad_syntax = "def broken(:\n    pass\n"
        self.assertTrue(validate_python_artifact(bad_syntax, KIND_HOOK))

        non_stdlib = "import langchain\nimport sys\nsys.exit(0)\n"
        errs = validate_python_artifact(non_stdlib, KIND_HOOK)
        self.assertTrue(any("non-stdlib" in e for e in errs))

        uses_eval = "import sys\neval('1+1')\nsys.exit(0)\n"
        errs = validate_python_artifact(uses_eval, KIND_HOOK)
        self.assertTrue(any("eval" in e for e in errs))

        missing_exit = "import sys\nprint('no exit')\n"
        errs = validate_python_artifact(missing_exit, KIND_HOOK)
        self.assertTrue(any("sys.exit" in e for e in errs))

    def test_deterministic_hook_synthesis_for_connection_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docker-compose.test.yml").write_text("services:\n  db: {}\n", encoding="utf-8")

            ev = FrictionEvent(
                step_range=[4, 7],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port 5432.",
                failure_signature="repeated_tool_error:bash:aabbccdd",
                command_sample="pytest tests/api",
                error_sample="ConnectionRefusedError on port 5432",
                exit_codes=[1, 1, 1],
            )

            synth = Synthesizer()
            art = synth.synthesize(repo_root=repo, event=ev, engram_id="eng_01J9X4M9")

            self.assertEqual(art.kind, KIND_HOOK)
            self.assertEqual(art.trigger_pattern, r"^pytest\b")
            self.assertEqual(art.file_path, ".engram/hooks/eng_01J9X4M9_verify_port_5432.py")
            self.assertTrue(art.ast_validated)
            self.assertEqual(validate_python_artifact(art.content, KIND_HOOK), [])

            written = materialize_artifact(repo, art)
            self.assertTrue(written.is_file())

            # Run the generated hook directly with unused port check -> should exit 2 with docker-compose hint.
            proc = subprocess.run(
                [sys.executable, str(written)],
                input=json.dumps({"tool_name": "bash", "tool_input": {"command": "pytest tests/api"}}),
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("docker-compose.test.yml", proc.stdout)

    def test_deterministic_composite_mcp_tool_synthesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            ev = FrictionEvent(
                step_range=[2, 6],
                pattern=PATTERN_MULTI_STEP_COMMAND,
                tool_name="bash",
                summary="Repeated 2-step sequence",
                failure_signature="multi_step_command_pattern:bash:11223344",
                command_sequence=["echo step_one", "echo step_two"],
            )

            synth = Synthesizer()
            art = synth.synthesize(repo_root=repo, event=ev, engram_id="eng_01J9Y001")

            self.assertEqual(art.kind, KIND_TOOL)
            self.assertEqual(validate_python_artifact(art.content, KIND_TOOL), [])

            written = materialize_artifact(repo, art)
            # Exercise MCP initialize + tools/list + tools/call over stdio.
            rpc_stream = "\n".join([
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": art.target_tool, "arguments": {}}}),
            ]) + "\n"
            proc = subprocess.run(
                [sys.executable, str(written)],
                input=rpc_stream,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            responses = [json.loads(ln) for ln in proc.stdout.strip().splitlines()]
            self.assertEqual(len(responses), 3)
            self.assertEqual(responses[1]["result"]["tools"][0]["name"], art.target_tool)
            self.assertIn("step_one", responses[2]["result"]["content"][0]["text"])
            self.assertIn("step_two", responses[2]["result"]["content"][0]["text"])

    def test_circular_edit_synthesizes_glob_scoped_markdown_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            ev = FrictionEvent(
                step_range=[1, 7],
                pattern=PATTERN_CIRCULAR_FILE_EDIT,
                tool_name="write_file",
                summary="Circular edit on src/api/routes.py",
                failure_signature="circular_file_edit:write_file:99887766",
                target_paths=["src/api/routes.py"],
            )

            art = Synthesizer().synthesize(repo_root=repo, event=ev, engram_id="eng_RULE01")
            self.assertEqual(art.kind, KIND_RULE)
            self.assertTrue(art.file_path.endswith(".md"))
            self.assertEqual(validate_rule_markdown(art.content), [])

    def test_llm_transport_retries_after_ast_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            calls = 0

            def fake_llm(_settings: ModelSettings, _sys: str, user_prompt: str) -> str:
                nonlocal calls
                calls += 1
                if calls == 1:
                    # Invalid: imports forbidden third-party package.
                    return json.dumps({
                        "kind": KIND_HOOK,
                        "slug": "bad_hook",
                        "target_tool": "bash",
                        "trigger_pattern": "^pytest\\b",
                        "explanation": "Invalid attempt using requests.",
                        "content": "import requests\nimport sys\nsys.exit(0)\n",
                    })
                self.assertIn("non-stdlib import not allowed", user_prompt)
                return json.dumps({
                    "kind": KIND_HOOK,
                    "slug": "clean_hook",
                    "target_tool": "bash",
                    "trigger_pattern": "^pytest\\b",
                    "explanation": "Valid stdlib-only hook after AST feedback.",
                    "content": "import json, sys\n_ = json.load(sys.stdin)\nsys.exit(0)\n",
                })

            ev = FrictionEvent(
                step_range=[1, 3],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name="bash",
                summary="pytest failed 3 times",
                failure_signature="sig_retry_test",
                command_sample="pytest",
            )
            art = Synthesizer(llm_transport=fake_llm, allow_deterministic_fallback=False).synthesize(
                repo_root=repo,
                event=ev,
                engram_id="eng_LLM01",
            )
            self.assertEqual(calls, 2)
            self.assertEqual(art.file_path, ".engram/hooks/eng_LLM01_clean_hook.py")

    def test_materialize_artifact_blocks_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            bad = Synthesizer().synthesize(
                repo_root=repo,
                event=FrictionEvent(
                    step_range=[1, 3],
                    pattern=PATTERN_REPEATED_TOOL_ERROR,
                    tool_name="bash",
                    summary="ConnectionRefusedError on port 5432",
                    failure_signature="sig_path",
                    command_sample="pytest",
                    error_sample="ConnectionRefusedError on port 5432",
                ),
                engram_id="eng_PATH1",
            )
            tampered = type(bad)(
                engram_id=bad.engram_id,
                kind=bad.kind,
                target_tool=bad.target_tool,
                trigger_pattern=bad.trigger_pattern,
                file_path=".engram/hooks/../../evil.py",
                failure_signature=bad.failure_signature,
                explanation=bad.explanation,
                content=bad.content,
            )
            with self.assertRaises(SynthesisError):
                materialize_artifact(repo, tampered)


if __name__ == "__main__":
    unittest.main()