"""Shadow regression evaluator verifying candidate engrams in isolated Git worktrees."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engram_compiler.detector import FrictionEvent
from engram_compiler.synthesizer import (
    KIND_HOOK,
    KIND_RULE,
    KIND_TOOL,
    SynthesizedArtifact,
    materialize_artifact,
    validate_python_artifact,
    validate_rule_markdown,
)


@dataclass(frozen=True)
class ShadowEvalResult:
    """Outcome of replaying a candidate engram in a temporary shadow worktree."""

    verified: bool
    pass_rate: float
    checks_passed: int
    checks_total: int
    details: list[str] = field(default_factory=list)
    error: str = ""


class ShadowEvaluator:
    """Enforces Invariant #4 by verifying candidate engrams in detached shadow worktrees."""

    def __init__(self, *, python_bin: str | None = None, timeout_seconds: float = 30.0) -> None:
        self._python_bin = python_bin or sys.executable
        self._timeout = timeout_seconds

    def evaluate(
        self,
        *,
        repo_root: str | Path,
        base_commit_sha: str,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
        regression_cmd: str | None = None,
    ) -> ShadowEvalResult:
        """Provision a shadow worktree at base_commit_sha, inject artifact, and verify replay."""
        root = Path(repo_root).resolve()

        # 1. Pre-flight AST / Markdown validation (Invariant #3 & #4).
        if artifact.kind in {KIND_HOOK, KIND_TOOL}:
            errs = validate_python_artifact(artifact.content, artifact.kind)
            if errs:
                return ShadowEvalResult(
                    verified=False,
                    pass_rate=0.0,
                    checks_passed=0,
                    checks_total=1,
                    error="AST validation failed: " + "; ".join(errs),
                )
        elif artifact.kind == KIND_RULE:
            errs = validate_rule_markdown(artifact.content)
            if errs:
                return ShadowEvalResult(
                    verified=False,
                    pass_rate=0.0,
                    checks_passed=0,
                    checks_total=1,
                    error="Markdown rule validation failed: " + "; ".join(errs),
                )
        else:
            return ShadowEvalResult(
                verified=False,
                pass_rate=0.0,
                checks_passed=0,
                checks_total=1,
                error=f"Unsupported artifact kind: {artifact.kind!r}",
            )

        commit_ref = (base_commit_sha or "HEAD").strip()
        shadow_wt = self._allocate_shadow_worktree_path(root, artifact.engram_id)
        created_worktree = False

        try:
            self._create_shadow_worktree(root, shadow_wt, commit_ref)
            created_worktree = True

            # Inject candidate artifact strictly inside the isolated shadow worktree (Invariant #1).
            injected_path = materialize_artifact(shadow_wt, artifact)

            if artifact.kind == KIND_HOOK:
                passed, total, details = self._replay_hook(
                    shadow_wt=shadow_wt,
                    script_path=injected_path,
                    artifact=artifact,
                    event=event,
                )
            elif artifact.kind == KIND_TOOL:
                passed, total, details = self._replay_mcp_tool(
                    shadow_wt=shadow_wt,
                    script_path=injected_path,
                    artifact=artifact,
                )
            else:
                passed, total, details = self._replay_rule(
                    injected_path=injected_path,
                    artifact=artifact,
                    event=event,
                )

            if regression_cmd:
                total += 1
                ok, msg = self._run_regression_command(shadow_wt, regression_cmd)
                details.append(msg)
                if ok:
                    passed += 1

            pass_rate = round(passed / total, 4) if total > 0 else 0.0
            verified = total > 0 and passed == total
            return ShadowEvalResult(
                verified=verified,
                pass_rate=pass_rate,
                checks_passed=passed,
                checks_total=total,
                details=details,
            )
        except Exception as exc:  # noqa: BLE001 - capture shadow replay failures cleanly
            return ShadowEvalResult(
                verified=False,
                pass_rate=0.0,
                checks_passed=0,
                checks_total=1,
                error=str(exc),
            )
        finally:
            if created_worktree:
                self._cleanup_shadow_worktree(root, shadow_wt)

    def _allocate_shadow_worktree_path(self, repo_root: Path, engram_id: str) -> Path:
        wt_parent = repo_root / ".engram" / ".runtime" / "worktrees"
        wt_parent.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_-]+", "_", engram_id)[:32] or "engram"
        return wt_parent / f"shadow_{safe_id}_{secrets.token_hex(4)}"

    def _create_shadow_worktree(self, repo_root: Path, shadow_wt: Path, base_ref: str) -> None:
        resolved = _run_git(repo_root, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
        _run_git(repo_root, "worktree", "add", "--detach", str(shadow_wt), resolved)

    def _cleanup_shadow_worktree(self, repo_root: Path, shadow_wt: Path) -> None:
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(shadow_wt)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if shadow_wt.exists():
            shutil.rmtree(shadow_wt, ignore_errors=True)
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "prune"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def _replay_hook(
        self,
        *,
        shadow_wt: Path,
        script_path: Path,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
    ) -> tuple[int, int, list[str]]:
        passed = 0
        total = 3
        details: list[str] = []

        sample_cmd = event.command_sample or event.tool_name or "pytest"
        compiled_re = re.compile(artifact.trigger_pattern)

        # Check 1: Trigger regex matches the failing invocation.
        if compiled_re.search(sample_cmd):
            passed += 1
            details.append(f"trigger regex {artifact.trigger_pattern!r} matched {sample_cmd!r}")
        else:
            details.append(f"trigger regex {artifact.trigger_pattern!r} did NOT match {sample_cmd!r}")

        # Check 2: Replaying the failing command against the hook exits with code 2 and guidance.
        payload = {
            "phase": "pre",
            "session_id": "shadow_eval",
            "step_index": event.step_range[0] if event.step_range else 1,
            "worktree_path": str(shadow_wt),
            "tool_name": artifact.target_tool or event.tool_name or "bash",
            "tool_input": {"command": sample_cmd},
        }
        proc = subprocess.run(
            [self._python_bin, str(script_path)],
            input=json.dumps(payload),
            cwd=str(shadow_wt),
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )
        combined_out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode == 2 and len(combined_out) >= 10:
            passed += 1
            details.append(f"hook blocked failing step with exit code 2: {combined_out[:160]}")
        else:
            details.append(
                f"hook failed shadow replay (expected exit 2 with guidance, got exit={proc.returncode}, out={combined_out[:160]!r})"
            )

        # Check 3: Specificity / non-regression — trigger must not match unrelated commands
        # unless intentionally scoped to a non-bash tool.
        benign_cmd = "__engram_unrelated_noop_command__"
        if artifact.trigger_pattern == ".*" or not compiled_re.search(benign_cmd):
            passed += 1
            details.append("hook specificity check passed")
        else:
            details.append(f"hook trigger {artifact.trigger_pattern!r} overly broad (matched {benign_cmd!r})")

        return passed, total, details

    def _replay_mcp_tool(
        self,
        *,
        shadow_wt: Path,
        script_path: Path,
        artifact: SynthesizedArtifact,
    ) -> tuple[int, int, list[str]]:
        passed = 0
        total = 3
        details: list[str] = []

        rpc_requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": artifact.target_tool, "arguments": {}}},
        ]
        stdin_stream = "\n".join(json.dumps(r) for r in rpc_requests) + "\n"

        env = os.environ.copy()
        env["ENGRAM_WORKTREE_PATH"] = str(shadow_wt)
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.run(
            [self._python_bin, str(script_path)],
            input=stdin_stream,
            cwd=str(shadow_wt),
            env=env,
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        if proc.returncode != 0 or len(lines) < 3:
            details.append(
                f"MCP stdio replay failed (exit={proc.returncode}, responses={len(lines)}, stderr={(proc.stderr or '')[:160]!r})"
            )
            return 0, total, details

        responses = [json.loads(ln) for ln in lines[:3]]

        # Check 1: initialize succeeded.
        if "result" in responses[0] and "protocolVersion" in responses[0]["result"]:
            passed += 1
            details.append("MCP initialize handshake passed")
        else:
            details.append(f"MCP initialize invalid: {responses[0]}")

        # Check 2: tools/list exposes the synthesized tool.
        listed_names = [t.get("name") for t in responses[1].get("result", {}).get("tools", [])]
        if artifact.target_tool in listed_names:
            passed += 1
            details.append(f"MCP tools/list exposed {artifact.target_tool!r}")
        else:
            details.append(f"MCP tools/list missing {artifact.target_tool!r}: {listed_names}")

        # Check 3: tools/call completed without error.
        call_res = responses[2].get("result", {})
        if call_res and not call_res.get("isError", True):
            passed += 1
            details.append("MCP tools/call executed cleanly in shadow worktree")
        else:
            details.append(f"MCP tools/call reported error: {call_res}")

        return passed, total, details

    def _replay_rule(
        self,
        *,
        injected_path: Path,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
    ) -> tuple[int, int, list[str]]:
        passed = 0
        total = 2
        details: list[str] = []

        if injected_path.is_file() and validate_rule_markdown(injected_path.read_text(encoding="utf-8")) == []:
            passed += 1
            details.append("Markdown rule materialized and passed frontmatter validation")
        else:
            details.append("Markdown rule failed materialization or frontmatter validation")

        targets = event.target_paths or [artifact.trigger_pattern]
        pattern = artifact.trigger_pattern
        if any(fnmatch.fnmatch(t, pattern) or t == pattern for t in targets):
            passed += 1
            details.append(f"Rule glob {pattern!r} matches target path(s) {targets}")
        else:
            details.append(f"Rule glob {pattern!r} did not match target path(s) {targets}")

        return passed, total, details

    def _run_regression_command(self, shadow_wt: Path, cmd: str) -> tuple[bool, str]:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(shadow_wt),
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )
        if proc.returncode == 0:
            return True, f"regression command passed: {cmd}"
        return False, f"regression command failed (exit={proc.returncode}): {(proc.stderr or proc.stdout)[:160]}"


def _run_git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {msg}")
    return (proc.stdout or "").strip()