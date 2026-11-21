"""Friction, loop, and normalized failure-signature analyzer for Engram traces."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PATTERN_REPEATED_TOOL_ERROR = "REPEATED_TOOL_ERROR"
PATTERN_CIRCULAR_FILE_EDIT = "CIRCULAR_FILE_EDIT"
PATTERN_MULTI_STEP_COMMAND = "MULTI_STEP_COMMAND_PATTERN"

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_SHA_RE = re.compile(r"\b[0-9a-fA-F]{12,64}\b")
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_WORKTREE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:)?[^\s\"']*?\.engram[/\\]\.runtime[/\\]worktrees[/\\][^\s\"'/\\]+",
)
_LINE_COL_RE = re.compile(r":\d+(?::\d+)?\b")
_ERROR_LINE_RE = re.compile(
    r"(?im)^.*(?:error|exception|failed|refused|denied|timeout|traceback|enoent|econnrefused|not found).*$"
)
_SUMMARY_CMD_RE = re.compile(
    r"(?:ran|running|command)\s+['\"`]([^'\"`]+)['\"`]", re.IGNORECASE
)


@dataclass(frozen=True)
class StepRecord:
    """Normalized execution step loaded from SQLite telemetry."""

    id: str
    session_id: str
    step_index: int
    git_commit_sha: str
    thought: str = ""
    tool_name: str = ""
    tool_input_json: str = "{}"
    tool_output_summary: str = ""
    raw_artifact_path: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0

    def parsed_input(self) -> dict[str, Any]:
        raw = (self.tool_input_json or "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def command_text(self) -> str:
        inp = self.parsed_input()
        for key in ("command", "cmd"):
            val = inp.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    def target_path(self) -> str:
        inp = self.parsed_input()
        for key in ("path", "file_path", "target"):
            val = inp.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().replace("\\", "/")
        return ""


@dataclass
class FrictionEvent:
    """Structured friction event matching the Go <-> Python JSON-RPC 2.0 contract."""

    step_range: list[int]
    pattern: str
    tool_name: str
    summary: str
    failure_signature: str = ""
    command_sample: str = ""
    error_sample: str = ""
    target_paths: list[str] = field(default_factory=list)
    exit_codes: list[int] = field(default_factory=list)
    command_sequence: list[str] = field(default_factory=list)

    def to_rpc_dict(self) -> dict[str, Any]:
        return {
            "step_range": list(self.step_range),
            "pattern": self.pattern,
            "tool_name": self.tool_name,
            "summary": self.summary,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrictionEvent:
        step_range = data.get("step_range") or [0, 0]
        if len(step_range) != 2:
            step_range = [0, 0]
        pattern = str(data.get("pattern", PATTERN_REPEATED_TOOL_ERROR))
        tool_name = str(data.get("tool_name", ""))
        summary = str(data.get("summary", ""))
        sig = str(data.get("failure_signature", "")) or normalize_failure_signature(
            pattern=pattern,
            tool_name=tool_name,
            detail=summary,
        )
        command_sample = str(data.get("command_sample", "")).strip()
        if not command_sample and summary:
            cmd_match = _SUMMARY_CMD_RE.search(summary)
            if cmd_match:
                command_sample = cmd_match.group(1).strip()
        return cls(
            step_range=[int(step_range[0]), int(step_range[1])],
            pattern=pattern,
            tool_name=tool_name,
            summary=summary,
            failure_signature=sig,
            command_sample=command_sample,
            error_sample=str(data.get("error_sample", "")),
            target_paths=[str(p) for p in data.get("target_paths", [])],
            exit_codes=[int(c) for c in data.get("exit_codes", [])],
            command_sequence=[str(c) for c in data.get("command_sequence", [])],
        )


def normalize_text_for_signature(text: str) -> str:
    """Strip volatile IDs, timestamps, SHAs, and worktree paths for stable signatures."""
    s = (text or "").strip()
    if not s:
        return ""
    s = _WORKTREE_PATH_RE.sub("<WORKTREE>", s)
    s = _TIMESTAMP_RE.sub("<TS>", s)
    s = _UUID_RE.sub("<UUID>", s)
    s = _HEX_SHA_RE.sub("<SHA>", s)
    s = _LINE_COL_RE.sub(":<N>", s)
    s = re.sub(r"\s+", " ", s)
    return s.lower()[:300]


def normalize_failure_signature(pattern: str, tool_name: str, detail: str) -> str:
    """Compute a deterministic failure signature matching engrams.failure_signature."""
    norm_detail = normalize_text_for_signature(detail)
    canonical = f"{pattern}|{tool_name.strip().lower()}|{norm_detail}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{pattern.lower()}:{tool_name.strip().lower() or 'unknown'}:{digest}"


def load_session_steps(db_path: str | Path, session_id: str) -> list[StepRecord]:
    """Load ordered steps for session_id from Engram's WAL-mode SQLite state store."""
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"SQLite state DB not found: {path}")

    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, session_id, step_index, git_commit_sha,
                   COALESCE(thought, '') AS thought,
                   COALESCE(tool_name, '') AS tool_name,
                   COALESCE(tool_input_json, '{}') AS tool_input_json,
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
            id=row["id"],
            session_id=row["session_id"],
            step_index=int(row["step_index"]),
            git_commit_sha=row["git_commit_sha"],
            thought=row["thought"],
            tool_name=row["tool_name"],
            tool_input_json=row["tool_input_json"],
            tool_output_summary=row["tool_output_summary"],
            raw_artifact_path=row["raw_artifact_path"],
            exit_code=int(row["exit_code"]) if row["exit_code"] is not None else None,
            duration_ms=int(row["duration_ms"]),
            tokens_in=int(row["tokens_in"]),
            tokens_out=int(row["tokens_out"]),
        )
        for row in rows
    ]


def analyze_session(
    db_path: str | Path,
    session_id: str,
    *,
    min_error_streak: int = 3,
    min_circular_edits: int = 3,
) -> list[FrictionEvent]:
    """Load steps for session_id from SQLite and detect all friction patterns."""
    steps = load_session_steps(db_path, session_id)
    return detect_friction(
        steps,
        min_error_streak=min_error_streak,
        min_circular_edits=min_circular_edits,
    )


def detect_friction(
    steps: list[StepRecord],
    *,
    min_error_streak: int = 3,
    min_circular_edits: int = 3,
) -> list[FrictionEvent]:
    """Analyze ordered execution steps for repeated errors, circular edits, and retry loops."""
    if not steps:
        return []

    events: list[FrictionEvent] = []
    events.extend(_detect_repeated_tool_errors(steps, min_error_streak))
    events.extend(_detect_circular_file_edits(steps, min_circular_edits))
    events.extend(_detect_multi_step_command_patterns(steps))

    # Deduplicate by normalized failure_signature while preserving step order.
    deduped: list[FrictionEvent] = []
    seen_sigs: set[str] = set()
    for ev in sorted(events, key=lambda e: (e.step_range[0], e.step_range[1], e.pattern)):
        if ev.failure_signature in seen_sigs:
            continue
        seen_sigs.add(ev.failure_signature)
        deduped.append(ev)
    return deduped


def merge_friction_events(
    reported: list[dict[str, Any]] | None,
    detected: list[FrictionEvent],
) -> list[FrictionEvent]:
    """Enrich Go-reported friction events with step telemetry and append any newly detected events."""
    merged: list[FrictionEvent] = []
    seen_sigs: set[str] = set()

    for raw in reported or []:
        ev = FrictionEvent.from_dict(raw)
        # Match against richer SQLite-detected event with overlapping step range & pattern if present.
        for det in detected:
            if det.pattern == ev.pattern and _ranges_overlap(det.step_range, ev.step_range):
                if not ev.command_sample:
                    ev.command_sample = det.command_sample
                if not ev.error_sample:
                    ev.error_sample = det.error_sample
                if not ev.target_paths:
                    ev.target_paths = det.target_paths
                if not ev.exit_codes:
                    ev.exit_codes = det.exit_codes
                if not ev.command_sequence:
                    ev.command_sequence = det.command_sequence
                ev.failure_signature = det.failure_signature
                break
        if ev.failure_signature not in seen_sigs:
            seen_sigs.add(ev.failure_signature)
            merged.append(ev)

    for det in detected:
        if det.failure_signature not in seen_sigs:
            seen_sigs.add(det.failure_signature)
            merged.append(det)

    return merged


def _detect_repeated_tool_errors(steps: list[StepRecord], min_streak: int) -> list[FrictionEvent]:
    events: list[FrictionEvent] = []
    streak: list[StepRecord] = []

    def flush_streak() -> None:
        if len(streak) < min_streak:
            return
        first, last = streak[0], streak[-1]
        tool_name = _dominant_tool(streak)
        cmd_sample = next((s.command_text() for s in streak if s.command_text()), "")
        err_sample = _extract_error_snippet(_step_output_text(last))
        exit_codes = [s.exit_code for s in streak if s.exit_code is not None]

        detail_parts = []
        if cmd_sample:
            detail_parts.append(f"command '{cmd_sample}'")
        if err_sample:
            detail_parts.append(f"error '{err_sample}'")
        detail = " | ".join(detail_parts) or f"tool {tool_name} failed {len(streak)} times"

        summary = (
            f"Agent ran '{cmd_sample or tool_name}' {len(streak)} consecutive times "
            f"(steps {first.step_index}..{last.step_index}) failing with "
            f"{err_sample or f'exit code {exit_codes[-1] if exit_codes else 1}'}."
        )
        sig = normalize_failure_signature(PATTERN_REPEATED_TOOL_ERROR, tool_name, detail)
        events.append(
            FrictionEvent(
                step_range=[first.step_index, last.step_index],
                pattern=PATTERN_REPEATED_TOOL_ERROR,
                tool_name=tool_name,
                summary=summary,
                failure_signature=sig,
                command_sample=cmd_sample,
                error_sample=err_sample,
                exit_codes=exit_codes,
            )
        )

    for st in steps:
        if st.exit_code is not None and st.exit_code != 0:
            if not streak:
                streak.append(st)
            elif _same_error_cluster(streak[-1], st):
                streak.append(st)
            else:
                flush_streak()
                streak = [st]
        else:
            flush_streak()
            streak = []
    flush_streak()
    return events


def _detect_circular_file_edits(steps: list[StepRecord], min_edits: int) -> list[FrictionEvent]:
    edits_by_path: dict[str, list[StepRecord]] = {}
    for st in steps:
        if st.tool_name not in {"write_file", "edit_file", "apply_patch"}:
            continue
        target = st.target_path()
        if not target:
            continue
        edits_by_path.setdefault(target, []).append(st)

    events: list[FrictionEvent] = []
    for path, edit_steps in edits_by_path.items():
        if len(edit_steps) < min_edits:
            continue
        first, last = edit_steps[0], edit_steps[-1]
        summary = (
            f"Agent edited '{path}' {len(edit_steps)} times across steps "
            f"{first.step_index}..{last.step_index} in a circular edit loop."
        )
        sig = normalize_failure_signature(PATTERN_CIRCULAR_FILE_EDIT, edit_steps[0].tool_name, path)
        events.append(
            FrictionEvent(
                step_range=[first.step_index, last.step_index],
                pattern=PATTERN_CIRCULAR_FILE_EDIT,
                tool_name=edit_steps[0].tool_name,
                summary=summary,
                failure_signature=sig,
                target_paths=[path],
            )
        )
    return events


def _detect_multi_step_command_patterns(steps: list[StepRecord]) -> list[FrictionEvent]:
    """Detect repeated 2-step or 3-step bash command chains suitable for composite MCP tools."""
    bash_steps = [s for s in steps if s.tool_name == "bash" and s.command_text()]
    if len(bash_steps) < 4:
        return []

    events: list[FrictionEvent] = []
    for chain_len in (3, 2):
        occurrences: dict[tuple[str, ...], list[list[StepRecord]]] = {}
        for i in range(len(bash_steps) - chain_len + 1):
            window = bash_steps[i : i + chain_len]
            key = tuple(normalize_text_for_signature(w.command_text()) for w in window)
            if len(set(key)) < 2:
                # Single repeated command is already handled by REPEATED_TOOL_ERROR.
                continue
            occurrences.setdefault(key, []).append(window)

        for _, windows in occurrences.items():
            # Require at least 2 non-overlapping occurrences of the multi-step sequence.
            non_overlapping: list[list[StepRecord]] = []
            last_end = -1
            for w in windows:
                if w[0].step_index > last_end:
                    non_overlapping.append(w)
                    last_end = w[-1].step_index
            if len(non_overlapping) < 2:
                continue

            sample_seq = [w.command_text() for w in non_overlapping[0]]
            first_step = non_overlapping[0][0].step_index
            last_step = non_overlapping[-1][-1].step_index
            seq_str = " -> ".join(sample_seq)
            summary = (
                f"Agent repeated {chain_len}-step command chain ({seq_str}) "
                f"{len(non_overlapping)} times across steps {first_step}..{last_step}."
            )
            sig = normalize_failure_signature(PATTERN_MULTI_STEP_COMMAND, "bash", seq_str)
            events.append(
                FrictionEvent(
                    step_range=[first_step, last_step],
                    pattern=PATTERN_MULTI_STEP_COMMAND,
                    tool_name="bash",
                    summary=summary,
                    failure_signature=sig,
                    command_sequence=sample_seq,
                )
            )
    return events


def _same_error_cluster(prev: StepRecord, curr: StepRecord) -> bool:
    if prev.tool_name == curr.tool_name:
        prev_cmd = normalize_text_for_signature(prev.command_text())
        curr_cmd = normalize_text_for_signature(curr.command_text())
        if prev_cmd and curr_cmd:
            prev_head = prev_cmd.split(" ", 1)[0]
            curr_head = curr_cmd.split(" ", 1)[0]
            if prev_head == curr_head:
                return True
        prev_err = normalize_text_for_signature(_extract_error_snippet(_step_output_text(prev)))
        curr_err = normalize_text_for_signature(_extract_error_snippet(_step_output_text(curr)))
        if prev_err and curr_err and prev_err == curr_err:
            return True
    return prev.tool_name == curr.tool_name


def _dominant_tool(steps: list[StepRecord]) -> str:
    counts: dict[str, int] = {}
    for s in steps:
        name = s.tool_name or "unknown"
        counts[name] = counts.get(name, 0) + 1
    return max(counts, key=lambda k: counts[k])


def _step_output_text(step: StepRecord) -> str:
    if step.raw_artifact_path:
        artifact = Path(step.raw_artifact_path)
        if artifact.is_file():
            try:
                raw = artifact.read_text(encoding="utf-8", errors="replace")
                return raw[-4000:]
            except OSError:
                pass
    return step.tool_output_summary


def _extract_error_snippet(output: str) -> str:
    text = (output or "").strip()
    if not text:
        return ""
    matches = _ERROR_LINE_RE.findall(text)
    if matches:
        return matches[-1].strip()[:200]
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


def _ranges_overlap(a: list[int], b: list[int]) -> bool:
    if len(a) != 2 or len(b) != 2:
        return False
    return max(a[0], b[0]) <= min(a[1], b[1])