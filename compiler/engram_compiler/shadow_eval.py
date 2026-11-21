"""Shadow worktree replay evaluator verifying synthesized engrams before activation (Invariant #4)."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from engram_compiler.detector import FrictionEvent, StepRecord, load_session_steps
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
    """Outcome of replaying a synthesized engram inside an isolated shadow worktree."""

    verified: bool
    pass_rate: float
    checks_passed: int
    checks_total: int
    details: str


class ShadowEvaluator:
    """Spins up a temporary detached Git worktree at base_commit_sha, injects the
    candidate engram, and verifies error prevention without host mutation."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def evaluate(
        self,
        *,
        repo_root: str | Path,
        base_commit_sha: str,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
        session_id: str = "",
        regression_command: str = "",
    ) -> ShadowEvalResult:
        root = Path(repo_root).resolve()

        # 1. Pre-flight AST / Markdown validation before spinning up any worktree.
        if artifact.kind in {KIND_HOOK, KIND_TOOL}:
            errs = validate_python_artifact(artifact.content, artifact.kind)
            if errs:
                return ShadowEvalResult(
                    verified=False,
                    pass_rate=0.0,
                    checks_passed=0,
                    checks_total=1,
                    details=f"AST validation failed: {'; '.join(errs)}",
                )
        elif artifact.kind == KIND_RULE:
            errs = validate_rule_markdown(artifact.content)
            if errs:
                return ShadowEvalResult(
                    verified=False,
                    pass_rate=0.0,
                    checks_passed=0,
                    checks_total=1,
                    details=f"Markdown rule validation failed: {'; '.join(errs)}",
                )
        else:
            return ShadowEvalResult(
                verified=False,
                pass_rate=0.0,
                checks_passed=0,
                checks_total=1,
                details=f"Unsupported artifact kind: {artifact.kind!r}",
            )

        target_ref = (base_commit_sha or "").strip() or "HEAD"
        if not self._verify_commit(root, target_ref):
            return ShadowEvalResult(
                verified=False,
                pass_rate=0.0,
                checks_passed=0,
                checks_total=1,
                details=f"Invalid base_commit_sha {target_ref!r} in {root}",
            )

        worktrees_parent = root / ".engram" / ".runtime" / "worktrees"
        worktrees_parent.mkdir(parents=True, exist_ok=True)
        shadow_name = f"shadow_{artifact.engram_id}_{secrets.token_hex(3)}"
        shadow_wt = worktrees_parent / shadow_name

        try:
            self._create_shadow_worktree(root, shadow_wt, target_ref)
            injected_path = materialize_artifact(shadow_wt, artifact)

            if artifact.kind == KIND_HOOK:
                return self._evaluate_hook(
                    root=root,
                    shadow_wt=shadow_wt,
                    hook_path=injected_path,
                    artifact=artifact,
                    event=event,
                    session_id=session_id,
                    regression_command=regression_command,
                )
            if artifact.kind == KIND_TOOL:
                return self._evaluate_tool(
                    shadow_wt=shadow_wt,
                    tool_path=injected_path,
                    artifact=artifact,
                    regression_command=regression_command,
                )
            return self._evaluate_rule(
                artifact=artifact,
                event=event,
            )
        finally:
            self._cleanup_shadow_worktree(root, shadow_wt)

    def _evaluate_hook(
        self,
        *,
        root: Path,
        shadow_wt: Path,
        hook_path: Path,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
        session_id: str,
        regression_command: str,
    ) -> ShadowEvalResult:
        checks_total = 0
        checks_passed = 0
        notes: list[str] = []

        failing_input = self._resolve_failing_tool_input(root, session_id, event)
        match_target = _extract_match_target(artifact.target_tool or event.tool_name, failing_input)

        # Check 1: trigger_pattern must match the failing tool invocation.
        checks_total += 1
        try:
            pattern = re.compile(artifact.trigger_pattern)
        except re.error as exc:
            return ShadowEvalResult(
                verified=False,
                pass_rate=0.0,
                checks_passed=0,
                checks_total=checks_total,
                details=f"Invalid trigger regex {artifact.trigger_pattern!r}: {exc}",
            )

        if pattern.search(match_target):
            checks_passed += 1
            notes.append(f"trigger_pattern matched {match_target!r}")
        else:
            notes.append(f"trigger_pattern {artifact.trigger_pattern!r} did not match {match_target!r}")

        # Check 2: replay the failing step through the synthesized Python hook -> must block with exit 2 and guidance.
        checks_total += 1
        payload = {
            "phase": "pre",
            "session_id": session_id or "shadow_eval",
            "step_index": event.step_range[0] if event.step_range else 1,
            "worktree_path": str(shadow_wt),
            "tool_name": artifact.target_tool or event.tool_name or "bash",
            "tool_input": failing_input,
        }
        proc = subprocess.run(
            [sys.executable, str(hook_path)],
            input=json.dumps(payload),
            cwd=str(shadow_wt),
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )
        guidance = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode == 2 and guidance:
            checks_passed += 1
            notes.append("hook blocked failing replay with exit 2 and actionable guidance")
        else:
            notes.append(
                f"hook replay returned exit_code={proc.returncode} (want 2) output={guidance[:200]!r}"
            )

        # Check 3 (optional): verify non-regression command inside shadow worktree if provided.
        if regression_command.strip():
            checks_total += 1
            reg = subprocess.run(
                regression_command,
                shell=True,
                cwd=str(shadow_wt),
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if reg.returncode == 0:
                checks_passed += 1
                notes.append("regression command passed")
            else:
                notes.append(f"regression command failed (exit={reg.returncode})")

        pass_rate = checks_passed / checks_total if checks_total else 0.0
        return ShadowEvalResult(
            verified=(checks_passed == checks_total),
            pass_rate=pass_rate,
            checks_passed=checks_passed,
            checks_total=checks_total,
            details="; ".join(notes),
        )

    def _evaluate_tool(
        self,
        *,
        shadow_wt: Path,
        tool_path: Path,
        artifact: SynthesizedArtifact,
        regression_command: str,
    ) -> ShadowEvalResult:
        checks_total = 2
        checks_passed = 0
        notes: list[str] = []

        rpc_requests = "\n".join([
            json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": artifact.target_tool, "arguments": {}},
            }),
        ]) + "\n"

        env = os.environ.copy()
        env["ENGRAM_WORKTREE_PATH"] = str(shadow_wt)
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.run(
            [sys.executable, str(tool_path)],
            input=rpc_requests,
            cwd=str(shadow_wt),
            env=env,
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        if proc.returncode == 0 and len(lines) == 3:
            try:
                resps = [json.loads(ln) for ln in lines]
                listed = resps[1].get("result", {}).get("tools", [])
                if any(t.get("name") == artifact.target_tool for t in listed):
                    checks_passed += 1
                    notes.append("MCP initialize and tools/list verified")
                else:
                    notes.append("tools/list missing synthesized tool name")

                call_res = resps[2].get("result", {})
                if not call_res.get("isError", True):
                    checks_passed += 1
                    notes.append("MCP tools/call succeeded cleanly in shadow worktree")
                else:
                    notes.append(f"MCP tools/call returned error: {call_res}")
            except json.JSONDecodeError as exc:
                notes.append(f"invalid JSON-RPC response from tool: {exc}")
        else:
            notes.append(f"tool process exited {proc.returncode}: {(proc.stderr or '').strip()[:200]}")

        if regression_command.strip():
            checks_total += 1
            reg = subprocess.run(
                regression_command,
                shell=True,
                cwd=str(shadow_wt),
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if reg.returncode == 0:
                checks_passed += 1
                notes.append("regression command passed")
            else:
                notes.append(f"regression command failed (exit={reg.returncode})")

        pass_rate = checks_passed / checks_total if checks_total else 0.0
        return ShadowEvalResult(
            verified=(checks_passed == checks_total),
            pass_rate=pass_rate,
            checks_passed=checks_passed,
            checks_total=checks_total,
            details="; ".join(notes),
        )

    def _evaluate_rule(
        self,
        *,
        artifact: SynthesizedArtifact,
        event: FrictionEvent,
    ) -> ShadowEvalResult:
        globs = _extract_rule_globs(artifact.content)
        targets = event.target_paths or [artifact.trigger_pattern]
        matched = False
        for t in targets:
            norm_t = PurePosixPath(t.replace("\\", "/"))
            for g in globs:
                if fnmatch.fnmatch(str(norm_t), g) or norm_t.match(g):
                    matched = True
                    break
            if matched:
                break

        if matched:
            return ShadowEvalResult(
                verified=True,
                pass_rate=1.0,
                checks_passed=1,
                checks_total=1,
                details=f"Markdown rule globs {globs} matched target path(s) {targets}",
            )
        return ShadowEvalResult(
            verified=False,
            pass_rate=0.0,
            checks_passed=0,
            checks_total=1,
            details=f"Markdown rule globs {globs} did not match target path(s) {targets}",
        )

    def _resolve_failing_tool_input(
        self,
        root: Path,
        session_id: str,
        event: FrictionEvent,
    ) -> dict[str, Any]:
        db_path = root / ".engram" / ".runtime" / "state.db"
        if session_id and db_path.is_file():
            try:
                steps: list[StepRecord] = load_session_steps(db_path, session_id)
                start_s, end_s = (event.step_range + [0, 0])[:2]
                for st in steps:
                    if start_s <= st.step_index <= end_s and st.exit_code not in (None, 0):
                        parsed = st.parsed_input()
                        if parsed:
                            return parsed
            except Exception:
                pass

        if event.command_sample:
            return {"command": event.command_sample}
        if event.target_paths:
            return {"path": event.target_paths[0]}
        return {"command": event.tool_name or "pytest"}

    def _verify_commit(self, root: Path, ref: str) -> bool:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0

    def _create_shadow_worktree(self, root: Path, shadow_wt: Path, ref: str) -> None:
        proc = subprocess.run(
            ["git", "-C", str(root), "worktree", "add", "--detach", str(shadow_wt), ref],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"git worktree add failed: {(proc.stderr or proc.stdout).strip()}"
            )

    def _cleanup_shadow_worktree(self, root: Path, shadow_wt: Path) -> None:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "remove", "--force", str(shadow_wt)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        subprocess.run(
            ["git", "-C", str(root), "worktree", "prune"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if shadow_wt.exists():
            shutil.rmtree(shadow_wt, ignore_errors=True)


def _extract_match_target(tool_name: str, tool_input: dict[str, Any]) -> str:
    for key in ("command", "cmd", "path", "file_path"):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return json.dumps(tool_input) if tool_input else tool_name


def _extract_rule_globs(markdown: str) -> list[str]:
    match = re.match(r"^---\s*\n(.*?)\n---", markdown.lstrip(), re.DOTALL)
    if not match:
        return []
    fm = match.group(1)
    inline = re.search(r"globs:\s*(\[[^\]]*\])", fm, re.DOTALL)
    if inline:
        try:
            vals = json.loads(inline.group(1))
            if isinstance(vals, list):
                return [str(v).strip() for v in vals if str(v).strip()]
        except json.JSONDecodeError:
            pass
    bullets = re.findall(r"^\s*-\s+[\"']?([^\"'\n]+)[\"']?", fm, re.MULTILINE)
    return [b.strip() for b in bullets if b.strip()]