"""AST-validated synthesis engine for Python hooks, MCP stdio tools, and scoped rules."""

from __future__ import annotations

import ast
import json
import os
import re
import secrets
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from engram_compiler.detector import (
    PATTERN_CIRCULAR_FILE_EDIT,
    PATTERN_MULTI_STEP_COMMAND,
    PATTERN_REPEATED_TOOL_ERROR,
    FrictionEvent,
)

KIND_HOOK = "hook"
KIND_TOOL = "tool"
KIND_RULE = "rule"

VALID_KINDS = {KIND_HOOK, KIND_TOOL, KIND_RULE}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}

_PORT_RE = re.compile(r"\bport\s+(\d{2,5})\b", re.IGNORECASE)
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

# Strict JSON Schema enforced on structured LLM synthesis responses.
SYNTHESIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "slug", "target_tool", "trigger_pattern", "explanation", "content"],
    "properties": {
        "kind": {"type": "string", "enum": [KIND_HOOK, KIND_TOOL, KIND_RULE]},
        "slug": {"type": "string", "pattern": "^[a-z0-9_]{3,40}$"},
        "target_tool": {"type": "string"},
        "trigger_pattern": {"type": "string", "minLength": 1},
        "explanation": {"type": "string", "minLength": 10},
        "content": {"type": "string", "minLength": 20},
    },
}


class SynthesisError(RuntimeError):
    """Raised when engram synthesis or AST/schema validation fails."""


@dataclass(frozen=True)
class ModelSettings:
    """Direct LLM settings parsed from .engram/config.toml."""

    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    endpoint: str = "https://api.anthropic.com/v1/messages"
    api_key_env: str = "ANTHROPIC_API_KEY"
    max_output_tokens: int = 4096

    @classmethod
    def from_repo(cls, repo_root: str | Path) -> ModelSettings:
        cfg_path = Path(repo_root) / ".engram" / "config.toml"
        if not cfg_path.is_file():
            return cls()
        with cfg_path.open("rb") as f:
            data = tomllib.load(f)
        m = data.get("model", {})
        return cls(
            provider=str(m.get("provider", "anthropic")),
            model=str(m.get("model", "claude-sonnet-4-20250514")),
            endpoint=str(m.get("endpoint", "https://api.anthropic.com/v1/messages")),
            api_key_env=str(m.get("api_key_env", "ANTHROPIC_API_KEY")),
            max_output_tokens=int(m.get("max_output_tokens", 4096)),
        )


@dataclass(frozen=True)
class SynthesizedArtifact:
    """Validated candidate harness artifact prior to shadow verification."""

    engram_id: str
    kind: str
    target_tool: str
    trigger_pattern: str
    file_path: str  # Relative to repo root, e.g. ".engram/hooks/eng_...py"
    failure_signature: str
    explanation: str
    content: str
    ast_validated: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


LLMTransport = Callable[[ModelSettings, str, str], str]


def new_engram_id() -> str:
    """Generate a unique eng_<millis_hex><rand> identifier."""
    ts = int(time.time() * 1000)
    rand_hex = secrets.token_hex(3).upper()
    return f"eng_{ts:X}{rand_hex}"


def sanitize_slug(raw: str, fallback: str = "compiled_engram") -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", (raw or "").lower()).strip("_")
    if len(cleaned) < 3:
        cleaned = fallback
    return cleaned[:40].strip("_") or fallback


def validate_python_artifact(source: str, kind: str) -> list[str]:
    """Validate Python source via ast.parse() and static zero-dependency safety rules.

    Returns a list of validation errors (empty means valid).
    """
    if kind not in {KIND_HOOK, KIND_TOOL}:
        return [f"unsupported python artifact kind: {kind!r}"]
    if not (source or "").strip():
        return ["generated Python source is empty"]

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"SyntaxError at line {exc.lineno}: {exc.msg}"]

    errors: list[str] = []
    stdlib = sys.stdlib_module_names
    imported_modules: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                imported_modules.add(root_mod)
                if root_mod not in stdlib:
                    errors.append(f"non-stdlib import not allowed: {alias.name!r}")
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                errors.append("relative imports are not allowed in self-contained artifacts")
            elif node.module:
                root_mod = node.module.split(".", 1)[0]
                imported_modules.add(root_mod)
                if root_mod not in stdlib:
                    errors.append(f"non-stdlib import not allowed: {node.module!r}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                errors.append(f"forbidden dynamic execution call: {node.func.id}()")

    if kind == KIND_HOOK:
        has_exit = _contains_sys_exit(tree)
        if not has_exit:
            errors.append("hook must explicitly invoke sys.exit(...) or raise SystemExit")
        if "sys" not in imported_modules:
            errors.append("hook must import sys")

    if kind == KIND_TOOL:
        for required_rpc in ("initialize", "tools/list", "tools/call"):
            if required_rpc not in source:
                errors.append(f"MCP tool server missing JSON-RPC handler for {required_rpc!r}")

    return errors


def validate_rule_markdown(content: str) -> list[str]:
    """Validate that a glob-scoped Markdown rule has YAML globs frontmatter and body."""
    text = (content or "").lstrip()
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return ["Markdown rule must begin with YAML frontmatter ('--- ... ---')"]
    frontmatter, body = match.group(1), match.group(2)
    if "globs:" not in frontmatter:
        return ["Markdown rule frontmatter must declare 'globs:'"]
    if not re.search(r"globs:\s*\[.+\]", frontmatter, re.DOTALL) and not re.search(
        r"globs:\s*\n\s*-\s+\S+", frontmatter
    ):
        return ["Markdown rule 'globs:' must specify at least one file glob pattern"]
    if len(body.strip()) < 10:
        return ["Markdown rule body must contain actionable guidance"]
    return []


def materialize_artifact(base_dir: str | Path, artifact: SynthesizedArtifact) -> Path:
    """Write a validated artifact into <base_dir>/.engram/{hooks,tools,rules}/ safely."""
    root = Path(base_dir).resolve()
    rel = Path(artifact.file_path)
    if rel.is_absolute():
        raise SynthesisError(f"artifact file_path must be relative: {artifact.file_path!r}")

    expected_subdir = {
        KIND_HOOK: "hooks",
        KIND_TOOL: "tools",
        KIND_RULE: "rules",
    }.get(artifact.kind)
    if expected_subdir is None:
        raise SynthesisError(f"unsupported artifact kind: {artifact.kind!r}")

    allowed_parent = (root / ".engram" / expected_subdir).resolve()
    target = (root / rel).resolve()
    try:
        target.relative_to(allowed_parent)
    except ValueError as exc:
        raise SynthesisError(
            f"unsafe artifact path {target} outside {allowed_parent}"
        ) from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(artifact.content, encoding="utf-8")
    return target


class Synthesizer:
    """Compiles FrictionEvents into AST-validated hooks, MCP tools, or glob-scoped rules."""

    def __init__(
        self,
        *,
        llm_transport: LLMTransport | None = None,
        allow_deterministic_fallback: bool = True,
    ) -> None:
        self._llm_transport = llm_transport
        self._allow_fallback = allow_deterministic_fallback

    def synthesize(
        self,
        *,
        repo_root: str | Path,
        event: FrictionEvent,
        engram_id: str | None = None,
    ) -> SynthesizedArtifact:
        """Synthesize and AST-validate an engram resolving the given FrictionEvent."""
        eid = engram_id or new_engram_id()
        settings = ModelSettings.from_repo(repo_root)

        api_key = os.environ.get(settings.api_key_env, "").strip()
        can_call_llm = self._llm_transport is not None or bool(api_key) or settings.provider == "ollama"

        if can_call_llm:
            try:
                return self._synthesize_via_llm(
                    repo_root=repo_root,
                    settings=settings,
                    event=event,
                    engram_id=eid,
                )
            except SynthesisError:
                if not self._allow_fallback:
                    raise
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                if not self._allow_fallback:
                    raise

        if not self._allow_fallback:
            raise SynthesisError("LLM synthesis unavailable and deterministic fallback disabled")

        return self._synthesize_deterministic(
            repo_root=repo_root,
            event=event,
            engram_id=eid,
        )

    def _synthesize_via_llm(
        self,
        *,
        repo_root: str | Path,
        settings: ModelSettings,
        event: FrictionEvent,
        engram_id: str,
    ) -> SynthesizedArtifact:
        transport = self._llm_transport or _default_llm_transport
        repo_context = _collect_repo_hints(repo_root)
        system_prompt = _build_system_prompt()
        user_prompt = _build_user_prompt(event, repo_context)

        last_err = ""
        for attempt in range(2):
            prompt = user_prompt
            if attempt > 0 and last_err:
                prompt += f"\n\nPrevious output failed validation with:\n{last_err}\nFix all errors and output valid JSON matching the schema."

            raw_json = transport(settings, system_prompt, prompt)
            try:
                spec = _parse_structured_spec(raw_json)
                return self._build_and_validate_artifact(
                    spec=spec,
                    engram_id=engram_id,
                    failure_signature=event.failure_signature,
                )
            except SynthesisError as exc:
                last_err = str(exc)

        raise SynthesisError(f"LLM synthesis failed AST/schema validation after retries: {last_err}")

    def _synthesize_deterministic(
        self,
        *,
        repo_root: str | Path,
        event: FrictionEvent,
        engram_id: str,
    ) -> SynthesizedArtifact:
        if event.pattern == PATTERN_CIRCULAR_FILE_EDIT:
            spec = _compile_circular_edit_rule(event)
        elif event.pattern == PATTERN_MULTI_STEP_COMMAND and len(event.command_sequence) >= 2:
            spec = _compile_composite_mcp_tool(event)
        else:
            spec = _compile_pre_tool_hook(repo_root, event)

        return self._build_and_validate_artifact(
            spec=spec,
            engram_id=engram_id,
            failure_signature=event.failure_signature,
        )

    def _build_and_validate_artifact(
        self,
        *,
        spec: dict[str, Any],
        engram_id: str,
        failure_signature: str,
    ) -> SynthesizedArtifact:
        kind = str(spec.get("kind", "")).strip()
        if kind not in VALID_KINDS:
            raise SynthesisError(f"invalid engram kind: {kind!r}")

        slug = sanitize_slug(str(spec.get("slug", "")))
        target_tool = str(spec.get("target_tool", "")).strip()
        trigger_pattern = str(spec.get("trigger_pattern", "")).strip()
        explanation = str(spec.get("explanation", "")).strip()
        content = str(spec.get("content", ""))

        if not trigger_pattern:
            raise SynthesisError("trigger_pattern must not be empty")
        if len(explanation) < 5:
            raise SynthesisError("explanation must not be empty")

        if kind in {KIND_HOOK, KIND_TOOL}:
            errs = validate_python_artifact(content, kind)
            if errs:
                raise SynthesisError("; ".join(errs))
            try:
                re.compile(trigger_pattern)
            except re.error as exc:
                raise SynthesisError(f"invalid trigger regex {trigger_pattern!r}: {exc}") from exc
            subdir = "hooks" if kind == KIND_HOOK else "tools"
            ext = ".py"
        else:
            errs = validate_rule_markdown(content)
            if errs:
                raise SynthesisError("; ".join(errs))
            subdir = "rules"
            ext = ".md"

        rel_path = f".engram/{subdir}/{engram_id}_{slug}{ext}"
        return SynthesizedArtifact(
            engram_id=engram_id,
            kind=kind,
            target_tool=target_tool,
            trigger_pattern=trigger_pattern,
            file_path=rel_path,
            failure_signature=failure_signature,
            explanation=explanation,
            content=content,
            ast_validated=True,
        )


def _contains_sys_exit(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == "SystemExit":
                return True
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "exit":
                if isinstance(fn.value, ast.Name) and fn.value.id == "sys":
                    return True
    return False


def _parse_structured_spec(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SynthesisError(f"invalid JSON structured output: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SynthesisError("structured output must be a JSON object")
    for req_key in ("kind", "slug", "trigger_pattern", "explanation", "content"):
        if req_key not in parsed:
            raise SynthesisError(f"structured output missing required key {req_key!r}")
    return parsed


def _compile_pre_tool_hook(repo_root: str | Path, event: FrictionEvent) -> dict[str, Any]:
    cmd = event.command_sample or ""
    err_text = f"{event.error_sample} {event.summary}"

    # 1. TCP port / connection refused prerequisite (e.g. Postgres 5432, Redis 6379).
    port_match = _PORT_RE.search(err_text)
    if port_match or "connectionrefused" in err_text.lower() or "econnrefused" in err_text.lower():
        port = int(port_match.group(1)) if port_match else 5432
        cmd_head = (cmd.split()[0] if cmd.split() else "pytest")
        cmd_regex = f"^{re.escape(cmd_head)}\\b"
        compose_hint = _find_compose_hint(repo_root)
        guidance = (
            f"Service on localhost:{port} is not accepting connections. "
            f"Start dependencies first (e.g. {compose_hint}) before running '{cmd_head}'."
        )
        script = f'''"""Deterministic Engram pre-tool hook: verify localhost:{port} is reachable."""

import json
import socket
import sys


def main() -> int:
    _payload = json.load(sys.stdin)
    try:
        with socket.create_connection(("127.0.0.1", {port}), timeout=1.5):
            return 0
    except OSError as exc:
        print({guidance!r} + f" (error: {{exc}})")
        return 2


if __name__ == "__main__":
    sys.exit(main())
'''
        return {
            "kind": KIND_HOOK,
            "slug": f"verify_port_{port}",
            "target_tool": event.tool_name or "bash",
            "trigger_pattern": cmd_regex,
            "explanation": f"Verifies localhost:{port} is accepting connections before running {cmd_head}; exits with code 2 and startup instructions if unreachable.",
            "content": script,
        }

    # 2. Missing file/marker/binary prerequisite.
    cmd_head = (cmd.split()[0] if cmd.split() else event.tool_name or "bash")
    cmd_regex = f"^{re.escape(cmd_head)}\\b" if cmd else ".*"
    guidance = (
        f"Blocked repeated failing command '{cmd or cmd_head}'. "
        f"Previous attempts failed with: {event.error_sample or event.summary}. "
        f"Resolve the missing prerequisite before retrying."
    )
    script = f'''"""Deterministic Engram pre-tool hook: guard repeated failing command."""

import json
import shutil
import sys


def main() -> int:
    payload = json.load(sys.stdin)
    tool_input = payload.get("tool_input") or {{}}
    cmd = str(tool_input.get("command") or tool_input.get("cmd") or "").strip()
    if not cmd:
        return 0
    head = cmd.split()[0]
    if shutil.which(head) is None:
        print(f"Required executable '{{head}}' not found in PATH. " + {guidance!r})
        return 2
    print({guidance!r})
    return 2


if __name__ == "__main__":
    sys.exit(main())
'''
    return {
        "kind": KIND_HOOK,
        "slug": sanitize_slug(f"guard_{cmd_head}", "guard_command"),
        "target_tool": event.tool_name or "bash",
        "trigger_pattern": cmd_regex,
        "explanation": f"Guards '{cmd_head}' invocations after repeated tool failures and provides deterministic remediation guidance on exit code 2.",
        "content": script,
    }


def _compile_composite_mcp_tool(event: FrictionEvent) -> dict[str, Any]:
    seq = list(event.command_sequence)
    tool_fn_name = sanitize_slug(f"workflow_{seq[0].split()[0]}", "composite_workflow")
    commands_literal = repr(seq)
    script = f'''"""Synthesized MCP-compatible stdio JSON-RPC 2.0 composite tool."""

import json
import os
import subprocess
import sys

COMMANDS = {commands_literal}
TOOL_NAME = {tool_fn_name!r}


def run_sequence(worktree_path: str) -> tuple[bool, str]:
    outputs = []
    for cmd in COMMANDS:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=worktree_path,
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        outputs.append(f"$ {{cmd}} (exit={{proc.returncode}})\\n{{combined.strip()}}")
        if proc.returncode != 0:
            return True, "\\n\\n".join(outputs)
    return False, "\\n\\n".join(outputs)


def main() -> int:
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        msg = json.loads(raw)
        msg_id = msg.get("id")
        method = msg.get("method")
        if msg_id is None:
            continue

        if method == "initialize":
            resp = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "protocolVersion": msg.get("params", {{}}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {{"tools": {{}}}},
                    "serverInfo": {{"name": TOOL_NAME, "version": "1.0.0"}},
                }},
            }}
        elif method == "tools/list":
            resp = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "tools": [
                        {{
                            "name": TOOL_NAME,
                            "description": "Execute verified multi-step workflow atomically inside the isolated worktree.",
                            "inputSchema": {{"type": "object", "properties": {{}}}},
                        }}
                    ]
                }},
            }}
        elif method == "tools/call":
            wt = os.environ.get("ENGRAM_WORKTREE_PATH") or os.getcwd()
            is_err, text = run_sequence(wt)
            resp = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "content": [{{"type": "text", "text": text}}],
                    "isError": is_err,
                }},
            }}
        else:
            resp = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {{"code": -32601, "message": f"unknown method {{method}}"}},
            }}

        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
    return {
        "kind": KIND_TOOL,
        "slug": tool_fn_name,
        "target_tool": tool_fn_name,
        "trigger_pattern": f"^{re.escape(tool_fn_name)}$",
        "explanation": f"Replaces fragile {len(seq)}-step bash sequence with a single deterministic MCP stdio tool.",
        "content": script,
    }


def _compile_circular_edit_rule(event: FrictionEvent) -> dict[str, Any]:
    paths = event.target_paths or ["**/*"]
    globs_json = json.dumps(paths)
    primary = paths[0]
    slug = sanitize_slug(Path(primary).stem, "scoped_edit_rule")
    content = (
        f"---\n"
        f"globs: {globs_json}\n"
        f"---\n\n"
        f"# Scoped Guidance for `{primary}`\n\n"
        f"Previous agent steps entered a circular edit loop on `{primary}` "
        f"(steps {event.step_range[0]}..{event.step_range[1]}).\n\n"
        f"- Read the full target file and related tests before applying another edit.\n"
        f"- Run targeted verification immediately after each edit instead of rewriting repeatedly.\n"
    )
    return {
        "kind": KIND_RULE,
        "slug": slug,
        "target_tool": event.tool_name or "write_file",
        "trigger_pattern": paths[0],
        "explanation": f"Glob-scoped rule injected when editing {primary} to prevent circular edits.",
        "content": content,
    }


def _find_compose_hint(repo_root: str | Path) -> str:
    root = Path(repo_root)
    for name in ("docker-compose.test.yml", "docker-compose.yml", "compose.yml"):
        if (root / name).is_file():
            return f"docker compose -f {name} up -d"
    return "docker compose up -d"


def _collect_repo_hints(repo_root: str | Path) -> str:
    root = Path(repo_root)
    if not root.is_dir():
        return ""
    interesting = []
    for entry in sorted(root.iterdir()):
        if entry.name.startswith(".engram") or entry.name == ".git":
            continue
        if entry.name in {
            "pyproject.toml",
            "package.json",
            "go.mod",
            "Makefile",
            "docker-compose.yml",
            "docker-compose.test.yml",
            "compose.yml",
        }:
            interesting.append(entry.name)
    return ", ".join(interesting)


def _build_system_prompt() -> str:
    return (
        "You are Engram's Evolution Compiler. Convert execution friction into a deterministic, "
        "self-contained, zero-dependency Python 3.12+ hook script (exit 0=allow, exit 2=block with guidance), "
        "an MCP stdio JSON-RPC 2.0 tool, or a glob-scoped Markdown rule.\n"
        "Strict rules:\n"
        "- Use ONLY Python standard library modules (zero third-party imports).\n"
        "- Never use eval(), exec(), compile(), or __import__().\n"
        "- Hooks must read JSON from sys.stdin and call sys.exit(0) or sys.exit(2).\n"
        "Respond with a single JSON object matching the required schema."
    )


def _build_user_prompt(event: FrictionEvent, repo_hints: str) -> str:
    return json.dumps(
        {
            "friction_event": event.to_dict(),
            "repo_files": repo_hints,
            "schema": SYNTHESIS_JSON_SCHEMA,
        },
        indent=2,
    )


def _default_llm_transport(settings: ModelSettings, system_prompt: str, user_prompt: str) -> str:
    api_key = os.environ.get(settings.api_key_env, "").strip()
    headers = {"Content-Type": "application/json"}

    if settings.provider == "anthropic":
        if api_key:
            headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
        body = {
            "model": settings.model,
            "max_tokens": settings.max_output_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "tools": [
                {
                    "name": "emit_engram",
                    "description": "Emit the synthesized engram specification.",
                    "input_schema": SYNTHESIS_JSON_SCHEMA,
                }
            ],
            "tool_choice": {"type": "tool", "name": "emit_engram"},
        }
        data = _post_json(settings.endpoint, headers, body)
        for block in data.get("content", []):
            if block.get("type") == "tool_use" and isinstance(block.get("input"), dict):
                return json.dumps(block["input"])
            if block.get("type") == "text":
                return str(block.get("text", ""))
        raise SynthesisError("Anthropic response did not contain structured tool_use output")

    if settings.provider == "openai":
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        body = {
            "model": settings.model,
            "max_tokens": settings.max_output_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "engram_synthesis",
                    "strict": True,
                    "schema": SYNTHESIS_JSON_SCHEMA,
                },
            },
        }
        data = _post_json(settings.endpoint, headers, body)
        choices = data.get("choices") or []
        if not choices:
            raise SynthesisError("OpenAI response returned no choices")
        return str(choices[0].get("message", {}).get("content", ""))

    if settings.provider == "ollama":
        body = {
            "model": settings.model,
            "stream": False,
            "format": SYNTHESIS_JSON_SCHEMA,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data = _post_json(settings.endpoint, headers, body)
        return str(data.get("message", {}).get("content", ""))

    raise SynthesisError(f"unsupported provider {settings.provider!r}")


def _post_json(endpoint: str, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))