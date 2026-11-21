"""AST-validated synthesis engine for Engram hooks, composite MCP tools, and scoped rules."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from engram_compiler.detector import FrictionEvent, PatternType

EngramKind = Literal["hook", "tool", "rule"]

_DISALLOWED_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})

SYNTHESIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "kind",
        "target_tool",
        "trigger_pattern",
        "file_slug",
        "explanation",
    ],
    "properties": {
        "kind": {"type": "string", "enum": ["hook", "tool", "rule"]},
        "target_tool": {"type": "string"},
        "trigger_pattern": {"type": "string"},
        "file_slug": {"type": "string", "pattern": "^[a-z0-9_]{3,48}$"},
        "code": {"type": "string"},
        "rule_markdown": {"type": "string"},
        "globs": {"type": "array", "items": {"type": "string"}},
        "explanation": {"type": "string"},
    },
}


class ASTValidationError(ValueError):
    """Raised when synthesized Python code fails syntax, stdlib-only, or contract checks."""


class SynthesisError(RuntimeError):
    """Raised when synthesis cannot produce a valid engram artifact."""


@dataclass(frozen=True, slots=True)
class SynthesizedEngram:
    """Generated, AST-validated (for Python) candidate engram ready for shadow replay."""

    engram_id: str
    kind: EngramKind
    target_tool: str
    trigger_pattern: str
    file_path: str  # Repo-relative path, e.g. ".engram/hooks/eng_...py"
    content: str
    explanation: str
    failure_signature: str
    ast_validated: bool
    globs: tuple[str, ...] = field(default_factory=tuple)

    def write_to_repo(self, repo_root: str | Path) -> Path:
        """Persist the synthesized artifact safely inside <repo_root>/.engram/."""
        root = Path(repo_root).resolve()
        engram_dir = (root / ".engram").resolve()
        dest = (root / self.file_path).resolve()
        if not dest.is_relative_to(engram_dir):
            raise SynthesisError(f"Refusing to write artifact outside .engram/: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(self.content, encoding="utf-8")
        return dest


class StructuredLLMClient(Protocol):
    """Minimal protocol for direct structured JSON LLM generation (zero frameworks)."""

    def generate_json(self, system_prompt: str, user_prompt: str, schema: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DirectModelConfig:
    provider: str
    model: str
    endpoint: str
    api_key_env: str = ""
    max_output_tokens: int = 4096

    @classmethod
    def from_workspace(cls, repo_root: str | Path) -> DirectModelConfig | None:
        cfg_path = Path(repo_root) / ".engram" / "config.toml"
        if not cfg_path.exists():
            return None
        data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        model_cfg = data.get("model", {})
        provider = str(model_cfg.get("provider", "")).strip()
        model = str(model_cfg.get("model", "")).strip()
        endpoint = str(model_cfg.get("endpoint", "")).strip()
        if not provider or not model or not endpoint:
            return None
        return cls(
            provider=provider,
            model=model,
            endpoint=endpoint,
            api_key_env=str(model_cfg.get("api_key_env", "")).strip(),
            max_output_tokens=int(model_cfg.get("max_output_tokens", 4096)),
        )


class DirectHTTPJSONClient:
    """Direct stdlib urllib client speaking Anthropic, OpenAI, and Ollama JSON APIs."""

    def __init__(self, cfg: DirectModelConfig, api_key: str = "", timeout_seconds: float = 60.0) -> None:
        self.cfg = cfg
        self.api_key = api_key.strip() or (os.environ.get(cfg.api_key_env, "").strip() if cfg.api_key_env else "")
        self.timeout_seconds = timeout_seconds

    def is_configured(self) -> bool:
        if self.cfg.provider == "ollama":
            return bool(self.cfg.endpoint and self.cfg.model)
        if self.api_key:
            return True
        return "127.0.0.1" in self.cfg.endpoint or "localhost" in self.cfg.endpoint

    def generate_json(self, system_prompt: str, user_prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        schema_prompt = (
            f"{system_prompt}\n\n"
            f"Respond ONLY with a valid JSON object conforming strictly to this JSON Schema:\n"
            f"{json.dumps(schema, separators=(',', ':'))}"
        )

        if self.cfg.provider == "anthropic":
            raw_text = self._call_anthropic(schema_prompt, user_prompt)
        elif self.cfg.provider == "openai":
            raw_text = self._call_openai(schema_prompt, user_prompt, schema)
        elif self.cfg.provider == "ollama":
            raw_text = self._call_ollama(schema_prompt, user_prompt)
        else:
            raise SynthesisError(f"Unsupported model provider: {self.cfg.provider}")

        return extract_json_object(raw_text)

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        payload = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_output_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        resp = self._post_json(self.cfg.endpoint, headers, payload)
        blocks = resp.get("content", [])
        parts = [str(b.get("text", "")) for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
        return "\n".join(parts)

    def _call_openai(self, system_prompt: str, user_prompt: str, schema: dict[str, Any]) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "engram_synthesis",
                    "strict": False,
                    "schema": schema,
                },
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        resp = self._post_json(self.cfg.endpoint, headers, payload)
        choices = resp.get("choices", [])
        if not choices:
            raise SynthesisError("OpenAI response contained no choices")
        return str(choices[0].get("message", {}).get("content", ""))

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.cfg.model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        resp = self._post_json(self.cfg.endpoint, headers, payload)
        return str(resp.get("message", {}).get("content", ""))

    def _post_json(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:500]
            raise SynthesisError(f"LLM HTTP {exc.code}: {err_body}") from exc
        except urllib.error.URLError as exc:
            raise SynthesisError(f"LLM request failed: {exc.reason}") from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SynthesisError(f"LLM returned invalid JSON envelope: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SynthesisError("LLM response JSON envelope must be an object")
        return parsed


def validate_python_ast(code: str, *, kind: EngramKind) -> ast.Module:
    """Parse and validate synthesized Python code using Python's built-in ast module.

    Enforces:
    1. Valid Python 3.12 syntax via ast.parse()
    2. Zero third-party imports (only Python standard library modules allowed)
    3. No dynamic code execution builtins (eval, exec, compile, __import__)
    4. Required structural contract per kind ('hook' or 'tool')
    """
    if not code or not code.strip():
        raise ASTValidationError("Synthesized Python code is empty")

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise ASTValidationError(f"SyntaxError at line {exc.lineno}: {exc.msg}") from exc

    stdlib_modules = sys.stdlib_module_names
    imported_modules: set[str] = set()
    called_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".", 1)[0]
                imported_modules.add(root_pkg)
                if root_pkg not in stdlib_modules:
                    raise ASTValidationError(
                        f"Non-stdlib import '{alias.name}' prohibited in self-contained engrams"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                raise ASTValidationError("Relative imports are prohibited in self-contained engrams")
            if node.module:
                root_pkg = node.module.split(".", 1)[0]
                imported_modules.add(root_pkg)
                if root_pkg not in stdlib_modules:
                    raise ASTValidationError(
                        f"Non-stdlib import '{node.module}' prohibited in self-contained engrams"
                    )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
                if node.func.id in _DISALLOWED_BUILTINS:
                    raise ASTValidationError(f"Prohibited dynamic execution call '{node.func.id}()'")
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)

    if kind == "hook":
        _validate_hook_contract(tree, code)
    elif kind == "tool":
        _validate_mcp_tool_contract(code)

    return tree


def _validate_hook_contract(tree: ast.Module, code: str) -> None:
    has_exit_call = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "exit":
                has_exit_call = True
            elif isinstance(node.func, ast.Name) and node.func.id == "exit":
                has_exit_call = True
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == "SystemExit":
                has_exit_call = True
    if not has_exit_call:
        raise ASTValidationError("Hook script must explicitly exit (e.g. sys.exit(0) / sys.exit(2))")
    if "2" not in code:
        raise ASTValidationError("Hook script must handle deterministic blocking via exit code 2")


def _validate_mcp_tool_contract(code: str) -> None:
    for required_method in ("initialize", "tools/list", "tools/call"):
        if required_method not in code:
            raise ASTValidationError(f"MCP tool script must implement JSON-RPC method '{required_method}'")


class Synthesizer:
    """Compiles FrictionEvents into AST-validated Python hooks/tools or scoped Markdown rules."""

    def __init__(self, llm_client: StructuredLLMClient | None = None) -> None:
        self.llm_client = llm_client

    def synthesize(
        self,
        *,
        repo_root: str | Path,
        friction_events: list[FrictionEvent],
        engram_id: str | None = None,
    ) -> SynthesizedEngram:
        if not friction_events:
            raise SynthesisError("At least one friction event is required for synthesis")

        primary = friction_events[0]
        repo = Path(repo_root).resolve()
        eid = engram_id or new_engram_id(primary.failure_signature)

        repo_context = collect_repo_hints(repo, primary)

        # 1. Try LLM structured synthesis if configured, validating via ast.parse().
        if self.llm_client is not None:
            try:
                return self._synthesize_with_llm(eid, primary, repo_context)
            except (SynthesisError, ASTValidationError):
                # Fall back to deterministic synthesis when LLM output fails schema/AST validation.
                pass

        # 2. Deterministic AST-validated synthesis fallback (works offline & in tests).
        return self._synthesize_deterministic(eid, primary, repo_context)

    def _synthesize_with_llm(
        self,
        engram_id: str,
        event: FrictionEvent,
        repo_context: dict[str, Any],
    ) -> SynthesizedEngram:
        assert self.llm_client is not None
        system_prompt = (
            "You are the Engram Evolution Compiler. Convert the execution friction trace into a "
            "deterministic, zero-dependency, self-contained Python 3.12+ pre/post hook, a stdio MCP "
            "tool, or a glob-scoped Markdown rule. Python code MUST use only standard library modules "
            "and MUST NOT use eval/exec/compile/__import__. Hooks read JSON from sys.stdin and exit "
            "0 (allow) or exit 2 with actionable stdout guidance (block)."
        )
        user_prompt = json.dumps(
            {
                "friction_event": event.to_ipc_dict(),
                "command": event.command,
                "target_path": event.target_path,
                "error_excerpt": event.error_excerpt,
                "repo_hints": repo_context,
            },
            indent=2,
        )

        raw = self.llm_client.generate_json(system_prompt, user_prompt, SYNTHESIS_JSON_SCHEMA)
        return self._materialize_structured_payload(engram_id, event, raw)

    def _materialize_structured_payload(
        self,
        engram_id: str,
        event: FrictionEvent,
        data: dict[str, Any],
    ) -> SynthesizedEngram:
        kind = str(data.get("kind", "")).strip()
        if kind not in ("hook", "tool", "rule"):
            raise SynthesisError(f"Invalid engram kind: {kind!r}")

        slug = sanitize_slug(str(data.get("file_slug", "auto_fix")))
        target_tool = str(data.get("target_tool", event.tool_name or "bash")).strip()
        trigger_pattern = str(data.get("trigger_pattern", "")).strip()
        explanation = str(data.get("explanation", "")).strip() or event.summary

        if kind in ("hook", "tool"):
            code = str(data.get("code", ""))
            validate_python_ast(code, kind=kind)
            if kind == "hook":
                if not trigger_pattern:
                    trigger_pattern = build_command_regex(event.command)
                re.compile(trigger_pattern)
                file_path = f".engram/hooks/{engram_id}_{slug}.py"
            else:
                if not trigger_pattern:
                    trigger_pattern = slug
                file_path = f".engram/tools/{engram_id}_{slug}.py"

            return SynthesizedEngram(
                engram_id=engram_id,
                kind=kind,
                target_tool=target_tool,
                trigger_pattern=trigger_pattern,
                file_path=file_path,
                content=code.rstrip() + "\n",
                explanation=explanation,
                failure_signature=event.failure_signature,
                ast_validated=True,
            )

        # kind == "rule"
        globs_raw = data.get("globs") or ([event.target_path] if event.target_path else ["**/*"])
        globs = tuple(str(g).strip() for g in globs_raw if str(g).strip())
        if not trigger_pattern:
            trigger_pattern = globs[0]
        body = str(data.get("rule_markdown", "")).strip()
        if not body:
            raise SynthesisError("Synthesized rule_markdown must not be empty")
        markdown = format_scoped_rule_markdown(engram_id, globs, event.failure_signature, body)
        file_path = f".engram/rules/{engram_id}_{slug}.md"

        return SynthesizedEngram(
            engram_id=engram_id,
            kind="rule",
            target_tool=target_tool,
            trigger_pattern=trigger_pattern,
            file_path=file_path,
            content=markdown,
            explanation=explanation,
            failure_signature=event.failure_signature,
            ast_validated=False,
            globs=globs,
        )

    def _synthesize_deterministic(
        self,
        engram_id: str,
        event: FrictionEvent,
        repo_context: dict[str, Any],
    ) -> SynthesizedEngram:
        if event.pattern == PatternType.CIRCULAR_FILE_EDIT:
            target = event.target_path or "**/*"
            slug = sanitize_slug(f"guard_{Path(target).stem}")
            body = (
                f"# Avoid Circular Edits on `{target}`\n\n"
                f"Previous steps repeatedly rewrote `{target}` without converging.\n"
                f"1. Read the full file and its test expectations before editing.\n"
                f"2. Verify incremental changes with targeted tests instead of oscillating edits.\n"
            )
            markdown = format_scoped_rule_markdown(engram_id, (target,), event.failure_signature, body)
            return SynthesizedEngram(
                engram_id=engram_id,
                kind="rule",
                target_tool=event.tool_name or "write_file",
                trigger_pattern=target,
                file_path=f".engram/rules/{engram_id}_{slug}.md",
                content=markdown,
                explanation=f"Injects targeted guidance whenever {target} is modified to prevent circular rewrites.",
                failure_signature=event.failure_signature,
                ast_validated=False,
                globs=(target,),
            )

        # Synthesize a deterministic pre-tool Python hook for repeated bash/tool failures.
        cmd_regex = build_command_regex(event.command)
        port = extract_port_hint(event.error_excerpt or event.summary)
        compose_files = repo_context.get("compose_files", [])

        if port is not None:
            compose_hint = (
                f"docker compose -f {compose_files[0]} up -d"
                if compose_files
                else f"Start the local service listening on port {port}"
            )
            slug = "verify_service_port"
            code = _render_tcp_port_hook(port=port, compose_hint=compose_hint)
            explanation = (
                f"Verifies TCP service is accepting connections on 127.0.0.1:{port} before running "
                f"matching command; outputs actionable startup instructions on exit code 2."
            )
        elif "modulenotfounderror" in (event.error_excerpt + event.summary).lower() or "no module named" in (
            event.error_excerpt + event.summary
        ).lower():
            slug = "verify_python_env"
            code = _render_venv_hook()
            explanation = (
                "Checks that a project virtual environment or configured test runner exists before "
                "executing Python test commands; blocks with setup instructions on exit code 2."
            )
        else:
            slug = sanitize_slug(f"guard_{command_head_token(event.command)}")
            code = _render_preflight_hook(
                command_regex=cmd_regex,
                error_excerpt=event.error_excerpt or event.summary,
                compose_files=compose_files,
            )
            explanation = (
                f"Deterministic pre-tool guard for '{event.command or event.tool_name}' preventing "
                f"repeated failure ({event.error_excerpt or event.pattern})."
            )

        validate_python_ast(code, kind="hook")
        return SynthesizedEngram(
            engram_id=engram_id,
            kind="hook",
            target_tool=event.tool_name or "bash",
            trigger_pattern=cmd_regex,
            file_path=f".engram/hooks/{engram_id}_{slug}.py",
            content=code,
            explanation=explanation,
            failure_signature=event.failure_signature,
            ast_validated=True,
        )


def _render_tcp_port_hook(*, port: int, compose_hint: str) -> str:
    return (
        f'"""Auto-synthesized Engram hook: verify TCP service port {port} before execution."""\n\n'
        "import json\n"
        "import socket\n"
        "import sys\n\n"
        f"TARGET_HOST = \"127.0.0.1\"\n"
        f"TARGET_PORT = {port}\n"
        f"STARTUP_HINT = {json.dumps(compose_hint)}\n\n\n"
        "def main() -> None:\n"
        "    try:\n"
        "        json.load(sys.stdin)\n"
        "    except Exception:\n"
        "        pass\n"
        "    try:\n"
        "        with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.5):\n"
        "            sys.exit(0)\n"
        "    except OSError as exc:\n"
        "        print(\n"
        f'            f"Dependency service is not reachable on {{TARGET_HOST}}:{{TARGET_PORT}} ({{exc}}). "\n'
        '            f"Start it first with: {STARTUP_HINT}"\n'
        "        )\n"
        "        sys.exit(2)\n\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def _render_venv_hook() -> str:
    return (
        '"""Auto-synthesized Engram hook: verify local Python virtual environment before running tests."""\n\n'
        "import json\n"
        "import os\n"
        "import shutil\n"
        "import sys\n\n\n"
        "def main() -> None:\n"
        "    try:\n"
        "        json.load(sys.stdin)\n"
        "    except Exception:\n"
        "        pass\n"
        "    cwd = os.getcwd()\n"
        "    has_venv = any(\n"
        '        os.path.isdir(os.path.join(cwd, name)) for name in (".venv", "venv")\n'
        "    )\n"
        '    if has_venv or os.environ.get("VIRTUAL_ENV") or shutil.which("pytest"):\n'
        "        sys.exit(0)\n"
        "    print(\n"
        '        "Python test dependencies are missing in this environment. "\n'
        '        "Activate .venv or install project dependencies (e.g., uv sync) before running pytest."\n'
        "    )\n"
        "    sys.exit(2)\n\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def _render_preflight_hook(*, command_regex: str, error_excerpt: str, compose_files: list[str]) -> str:
    hint = (
        f"Check prerequisites (found compose file: {compose_files[0]}) before retrying."
        if compose_files
        else "Inspect repository prerequisites before retrying this command."
    )
    return (
        '"""Auto-synthesized Engram pre-tool failure guard."""\n\n'
        "import json\n"
        "import os\n"
        "import sys\n\n"
        f"MATCH_REGEX = {json.dumps(command_regex)}\n"
        f"PREVIOUS_ERROR = {json.dumps(error_excerpt)}\n"
        f"GUIDANCE = {json.dumps(hint)}\n\n\n"
        "def main() -> None:\n"
        "    try:\n"
        "        payload = json.load(sys.stdin)\n"
        "    except Exception:\n"
        "        payload = {}\n"
        '    cwd = payload.get("worktree_path") or os.getcwd()\n'
        '    ready_marker = os.path.join(cwd, ".engram_preflight_ok")\n'
        "    if os.path.exists(ready_marker):\n"
        "        sys.exit(0)\n"
        '    print(f"Blocked repeated failure pattern ({MATCH_REGEX}): {PREVIOUS_ERROR}. {GUIDANCE}")\n'
        "    sys.exit(2)\n\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def collect_repo_hints(repo_root: Path, event: FrictionEvent) -> dict[str, Any]:
    compose_files: list[str] = []
    for name in ("docker-compose.test.yml", "docker-compose.yml", "compose.yml", "compose.yaml"):
        if (repo_root / name).exists():
            compose_files.append(name)

    return {
        "compose_files": compose_files,
        "has_pyproject": (repo_root / "pyproject.toml").exists(),
        "has_package_json": (repo_root / "package.json").exists(),
        "has_go_mod": (repo_root / "go.mod").exists(),
        "target_path_exists": bool(event.target_path and (repo_root / event.target_path).exists()),
    }


def extract_port_hint(text: str) -> int | None:
    patterns = (
        re.compile(r"\bport\s+(\d{2,5})\b", re.IGNORECASE),
        re.compile(r"(?:127\.0\.0\.1|localhost):(\d{2,5})\b"),
    )
    for pat in patterns:
        m = pat.search(text)
        if m:
            port = int(m.group(1))
            if 1 <= port <= 65535:
                return port
    return None


def command_head_token(command: str) -> str:
    tokens = command.strip().split()
    if not tokens:
        return "command"
    return Path(tokens[0]).stem or "command"


def build_command_regex(command: str) -> str:
    tokens = command.strip().split()
    if not tokens:
        return ".*"
    head = re.escape(tokens[0])
    return rf"^{head}\b"


def sanitize_slug(raw: str) -> str:
    slug = re.sub(r"[^a-z0-9_]+", "_", raw.lower()).strip("_")
    return slug[:48] or "engram_artifact"


def new_engram_id(seed: str) -> str:
    raw = f"{time.time_ns()}:{seed}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:8].upper()
    return f"eng_{digest}"


def format_scoped_rule_markdown(
    engram_id: str,
    globs: tuple[str, ...],
    failure_signature: str,
    body: str,
) -> str:
    globs_json = json.dumps(list(globs))
    return (
        "---\n"
        f"id: {engram_id}\n"
        f"globs: {globs_json}\n"
        f"failure_signature: {json.dumps(failure_signature)}\n"
        "---\n\n"
        f"{body.strip()}\n"
    )


def extract_json_object(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise SynthesisError("LLM output did not contain a JSON object")
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise SynthesisError(f"Failed to parse extracted JSON object: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SynthesisError("Extracted JSON payload must be an object")
    return parsed