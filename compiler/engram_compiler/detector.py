"""Friction, loop, and normalized failure-signature detector for Engram traces."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Sequence


class PatternType(StrEnum):
    REPEATED_TOOL_ERROR = "REPEATED_TOOL_ERROR"
    CIRCULAR_FILE_EDIT = "CIRCULAR_FILE_EDIT"
    MULTI_STEP_RETRY_LOOP = "MULTI_STEP_RETRY_LOOP"


@dataclass(frozen=True, slots=True)
class StepRecord:
    """Typed mirror of a row in the SQLite `steps` table."""

    id: str
    session_id: str
    step_index: int
    git_commit_sha: str
    thought: str = ""
    tool_name: str = ""
    tool_input_json: str = ""
    tool_output_summary: str = ""
    raw_artifact_path: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0

    @property
    def parsed_input(self) -> dict[str, Any]:
        if not self.tool_input_json:
            return {}
        try:
            loaded = json.loads(self.tool_input_json)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            return {}


@dataclass(frozen=True, slots=True)
class FrictionEvent:
    """Detected execution friction event aligned with the Go <-> Python JSON-RPC contract."""

    step_range: tuple[int, int]
    pattern: PatternType
    tool_name: str
    summary: str
    failure_signature: str
    command: str = ""
    target_path: str = ""
    error_excerpt: str = ""
    occurrences: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_ipc_dict(self) -> dict[str, Any]:
        """Serialize strictly to the Section 5 JSON-RPC friction_events schema."""
        return {
            "step_range": [self.step_range[0], self.step_range[1]],
            "pattern": str(self.pattern),
            "tool_name": self.tool_name,
            "summary": self.summary,
        }


_NORMALIZE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Windows/POSIX temp worktree paths
    (re.compile(r"[A-Za-z]:\\[^\s\"']+"), "<PATH>"),
    (re.compile(r"/(?:tmp|var|private|Users|home)/[^\s\"']+"), "<PATH>"),
    # Hex SHAs, UUIDs, memory pointers
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<PTR>"),
    (re.compile(r"\b[0-9a-fA-F]{12,64}\b"), "<HEX>"),
    # Timestamps and durations
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"), "<TIME>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds)\b"), "<DUR>"),
    # Line numbers and PIDs
    (re.compile(r"\bline \d+\b", re.IGNORECASE), "line <N>"),
    (re.compile(r"\bpid[=: ]+\d+\b", re.IGNORECASE), "pid=<N>"),
    # Collapse whitespace
    (re.compile(r"\s+"), " "),
)

_FILE_MUTATING_TOOLS = frozenset({"write_file", "edit_file", "apply_patch", "patch_file"})


class FrictionDetector:
    """Analyzes session step telemetry to detect failure loops and circular edits."""

    def __init__(
        self,
        *,
        repeated_error_threshold: int = 3,
        circular_edit_threshold: int = 3,
        retry_cycle_threshold: int = 2,
    ) -> None:
        if repeated_error_threshold < 2:
            raise ValueError("repeated_error_threshold must be >= 2")
        if circular_edit_threshold < 2:
            raise ValueError("circular_edit_threshold must be >= 2")
        if retry_cycle_threshold < 2:
            raise ValueError("retry_cycle_threshold must be >= 2")
        self.repeated_error_threshold = repeated_error_threshold
        self.circular_edit_threshold = circular_edit_threshold
        self.retry_cycle_threshold = retry_cycle_threshold

    def load_session_steps(self, db_path: str | Path, session_id: str) -> list[StepRecord]:
        """Load ordered step records for session_id from SQLite WAL state.db."""
        path = Path(db_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"SQLite state store not found: {path}")

        uri = f"{path.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT id, session_id, step_index, git_commit_sha,
                       COALESCE(thought, '') AS thought,
                       COALESCE(tool_name, '') AS tool_name,
                       COALESCE(tool_input_json, '') AS tool_input_json,
                       COALESCE(tool_output_summary, '') AS tool_output_summary,
                       COALESCE(raw_artifact_path, '') AS raw_artifact_path,
                       exit_code,
                       COALESCE(duration_ms, 0) AS duration_ms,
                       COALESCE(tokens_in, 0) AS tokens_in,
                       COALESCE(tokens_out, 0) AS tokens_out
                FROM steps
                WHERE session_id = ?
                ORDER BY step_index ASC
                """,
                (session_id,),
            ).fetchall()
        finally:
            conn.close()

        return [
            StepRecord(
                id=str(r["id"]),
                session_id=str(r["session_id"]),
                step_index=int(r["step_index"]),
                git_commit_sha=str(r["git_commit_sha"]),
                thought=str(r["thought"]),
                tool_name=str(r["tool_name"]),
                tool_input_json=str(r["tool_input_json"]),
                tool_output_summary=str(r["tool_output_summary"]),
                raw_artifact_path=str(r["raw_artifact_path"]),
                exit_code=int(r["exit_code"]) if r["exit_code"] is not None else None,
                duration_ms=int(r["duration_ms"]),
                tokens_in=int(r["tokens_in"]),
                tokens_out=int(r["tokens_out"]),
            )
            for r in rows
        ]

    def analyze_session(self, db_path: str | Path, session_id: str) -> list[FrictionEvent]:
        """Load steps from state.db and detect all friction events for session_id."""
        steps = self.load_session_steps(db_path, session_id)
        return self.analyze_steps(steps)

    def analyze_steps(self, steps: Sequence[StepRecord]) -> list[FrictionEvent]:
        """Analyze an ordered sequence of StepRecords for repeatable friction patterns."""
        ordered = sorted((s for s in steps if s.tool_name), key=lambda s: s.step_index)
        if not ordered:
            return []

        events: list[FrictionEvent] = []
        events.extend(self._detect_repeated_tool_errors(ordered))
        events.extend(self._detect_circular_file_edits(ordered))
        events.extend(self._detect_multi_step_retry_loops(ordered))

        # Deduplicate by (pattern, failure_signature), keeping the earliest/most specific span.
        deduped: list[FrictionEvent] = []
        seen_keys: set[tuple[PatternType, str]] = set()
        for ev in sorted(events, key=lambda e: (e.step_range[0], e.step_range[1], str(e.pattern))):
            key = (ev.pattern, ev.failure_signature)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped.append(ev)
        return deduped

    def _detect_repeated_tool_errors(self, steps: Sequence[StepRecord]) -> list[FrictionEvent]:
        groups: dict[tuple[str, str], list[StepRecord]] = {}
        for st in steps:
            if st.exit_code is None or st.exit_code == 0:
                continue
            norm_err = normalize_failure_text(st.tool_output_summary)
            norm_in = normalize_input_key(st.tool_name, st.parsed_input)
            key = (st.tool_name, f"{norm_in}|{norm_err}")
            groups.setdefault(key, []).append(st)

        events: list[FrictionEvent] = []
        for (tool_name, sig_seed), group in groups.items():
            if len(group) < self.repeated_error_threshold:
                continue

            first = group[0]
            last = group[-1]
            cmd = extract_command(first.parsed_input)
            excerpt = extract_error_headline(last.tool_output_summary)
            sig = build_failure_signature(PatternType.REPEATED_TOOL_ERROR, tool_name, sig_seed)

            if cmd:
                summary = (
                    f"Agent ran '{cmd}' {len(group)} times via {tool_name} "
                    f"failing with exit code {last.exit_code}: {excerpt}"
                )
            else:
                summary = (
                    f"Tool '{tool_name}' failed {len(group)} times "
                    f"(exit code {last.exit_code}): {excerpt}"
                )

            events.append(
                FrictionEvent(
                    step_range=(first.step_index, last.step_index),
                    pattern=PatternType.REPEATED_TOOL_ERROR,
                    tool_name=tool_name,
                    summary=summary.strip(),
                    failure_signature=sig,
                    command=cmd,
                    target_path=extract_target_path(first.parsed_input),
                    error_excerpt=excerpt,
                    occurrences=len(group),
                    metadata={
                        "exit_codes": [s.exit_code for s in group],
                        "step_indices": [s.step_index for s in group],
                    },
                )
            )
        return events

    def _detect_circular_file_edits(self, steps: Sequence[StepRecord]) -> list[FrictionEvent]:
        by_path: dict[str, list[StepRecord]] = {}
        for st in steps:
            if st.tool_name not in _FILE_MUTATING_TOOLS:
                continue
            target = extract_target_path(st.parsed_input)
            if not target:
                continue
            by_path.setdefault(target, []).append(st)

        events: list[FrictionEvent] = []
        for target_path, group in by_path.items():
            if len(group) < self.circular_edit_threshold:
                continue

            first = group[0]
            last = group[-1]
            sig = build_failure_signature(PatternType.CIRCULAR_FILE_EDIT, first.tool_name, target_path)

            # Check whether edits oscillate back to an earlier content hash.
            content_hashes = [
                hashlib.sha256(str(s.parsed_input.get("content", "")).encode("utf-8")).hexdigest()[:8]
                for s in group
            ]
            oscillated = len(set(content_hashes)) < len(content_hashes)
            detail = " (oscillating content detected)" if oscillated else ""

            summary = (
                f"Agent repeatedly edited '{target_path}' {len(group)} times "
                f"between steps {first.step_index} and {last.step_index}{detail}."
            )
            events.append(
                FrictionEvent(
                    step_range=(first.step_index, last.step_index),
                    pattern=PatternType.CIRCULAR_FILE_EDIT,
                    tool_name=first.tool_name,
                    summary=summary,
                    failure_signature=sig,
                    target_path=target_path,
                    occurrences=len(group),
                    metadata={
                        "oscillated": oscillated,
                        "step_indices": [s.step_index for s in group],
                    },
                )
            )
        return events

    def _detect_multi_step_retry_loops(self, steps: Sequence[StepRecord]) -> list[FrictionEvent]:
        # Detect repeating 2-step (mutate -> verify/fail) or identical 2-step tool pairs.
        if len(steps) < 4:
            return []

        tokens: list[tuple[str, str, int | None]] = [
            (
                st.tool_name,
                normalize_input_key(st.tool_name, st.parsed_input),
                0 if (st.exit_code is None or st.exit_code == 0) else 1,
            )
            for st in steps
        ]

        pair_occurrences: dict[tuple[tuple[str, str, int | None], tuple[str, str, int | None]], list[int]] = {}
        for i in range(len(tokens) - 1):
            a, b = tokens[i], tokens[i + 1]
            # Focus on cycles where the second step is a failing command/check.
            if b[2] != 1:
                continue
            if a[0] not in _FILE_MUTATING_TOOLS and a[0] != "bash":
                continue
            pair = (a, b)
            indices = pair_occurrences.setdefault(pair, [])
            # Avoid counting overlapping indices.
            if not indices or i >= indices[-1] + 2:
                indices.append(i)

        events: list[FrictionEvent] = []
        for (first_tok, second_tok), start_positions in pair_occurrences.items():
            if len(start_positions) < self.retry_cycle_threshold:
                continue

            start_step = steps[start_positions[0]]
            end_step = steps[start_positions[-1] + 1]
            cmd = extract_command(steps[start_positions[-1] + 1].parsed_input)
            target = extract_target_path(start_step.parsed_input)
            seed = f"{first_tok[0]}:{first_tok[1]}->{second_tok[0]}:{second_tok[1]}"
            sig = build_failure_signature(PatternType.MULTI_STEP_RETRY_LOOP, second_tok[0], seed)

            excerpt = extract_error_headline(end_step.tool_output_summary)
            summary = (
                f"Detected {len(start_positions)}x multi-step retry loop "
                f"({first_tok[0]} -> {second_tok[0]})"
                + (f" targeting '{target}'" if target else "")
                + (f" running '{cmd}'" if cmd else "")
                + (f" failing with: {excerpt}" if excerpt else ".")
            )

            events.append(
                FrictionEvent(
                    step_range=(start_step.step_index, end_step.step_index),
                    pattern=PatternType.MULTI_STEP_RETRY_LOOP,
                    tool_name=second_tok[0],
                    summary=summary,
                    failure_signature=sig,
                    command=cmd,
                    target_path=target,
                    error_excerpt=excerpt,
                    occurrences=len(start_positions),
                    metadata={
                        "cycle": [first_tok[0], second_tok[0]],
                        "start_steps": [steps[pos].step_index for pos in start_positions],
                    },
                )
            )
        return events


def normalize_failure_text(text: str) -> str:
    """Strip ephemeral paths, timestamps, SHAs, and line numbers to form a stable error key."""
    if not text:
        return "empty"
    headline = extract_error_headline(text)
    cleaned = headline
    for pattern, repl in _NORMALIZE_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned.strip().lower()[:200]


def normalize_input_key(tool_name: str, parsed_input: dict[str, Any]) -> str:
    """Create a normalized input signature for grouping repeated tool invocations."""
    if tool_name == "bash":
        cmd = extract_command(parsed_input)
        return re.sub(r"\s+", " ", cmd).strip()
    target = extract_target_path(parsed_input)
    if target:
        return target
    if not parsed_input:
        return ""
    return json.dumps(parsed_input, sort_keys=True, separators=(",", ":"))[:120]


def extract_command(parsed_input: dict[str, Any]) -> str:
    for key in ("command", "cmd"):
        val = parsed_input.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def extract_target_path(parsed_input: dict[str, Any]) -> str:
    for key in ("path", "file_path", "target"):
        val = parsed_input.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().replace("\\", "/")
    return ""


def extract_error_headline(output: str) -> str:
    """Extract the most informative error line (e.g., Exception/Error line) from tool output."""
    if not output:
        return "non-zero exit"
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    if not lines:
        return "non-zero exit"

    # Prefer explicit exception/error lines from tracebacks (searching bottom-up).
    for ln in reversed(lines):
        if ln.startswith(("exit_code=", "[output truncated:", "[full raw artifact", "--- ")):
            continue
        if re.search(r"(?:Error|Exception|FAILED|Refused|Denied|Traceback|fatal):", ln, re.IGNORECASE):
            return ln[:200]

    for ln in reversed(lines):
        if not ln.startswith(("exit_code=", "--- ")):
            return ln[:200]
    return lines[0][:200]


def build_failure_signature(pattern: PatternType, tool_name: str, seed: str) -> str:
    """Generate a deterministic failure signature matching engrams.failure_signature."""
    digest = hashlib.sha256(f"{pattern}:{tool_name}:{seed}".encode("utf-8")).hexdigest()[:12]
    return f"{pattern.lower()}:{tool_name}:{digest}"