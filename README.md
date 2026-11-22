# ENGRAM

**Self-Evolving Local Agent Runtime & Deterministic Harness Compiler**

Named after the neuroscience term for a physical memory trace stored in tissue, **Engram** is a standalone, local-first agentic runtime that converts fleeting LLM failure loops and execution friction into permanent, executable, Git-versioned code artifacts (`.engram/`) inside your workspace.

Every session runs inside an isolated detached Git worktree with atomic step commits, dual-mode sandboxing, a secret-redacting egress proxy, and an asynchronous Python Evolution Compiler that synthesizes and shadow-verifies deterministic Python hooks, MCP stdio tools, and glob-scoped rules before activation.

---

## Non-Negotiable Engineering Invariants

1. **Zero Host Filesystem Mutation:** The agent runtime never writes directly to your primary working tree; all mutations occur inside detached Git worktrees (`.engram/.runtime/worktrees/`) until explicitly merged.
2. **Zero Orchestration Frameworks:** Zero LangChain, LlamaIndex, CrewAI, AutoGen, or PydanticAI. Direct HTTP/SSE/NDJSON wire protocols in Go, native `mcp-go` tool hosting, and stdlib-only Python 3.12+ AST synthesis.
3. **Human-Auditable Intelligence:** All learned memory compiles into readable Python scripts (`.engram/hooks/`, `.engram/tools/`) or Markdown rules (`.engram/rules/`)—never opaque binary weights.
4. **Shadow Verification Before Activation:** No self-generated hook or tool can enter `active` status until it passes `ast.parse()` static safety checks and isolated shadow worktree replay at `base_commit_sha`.
5. **Strict Context Hygiene:** Raw tool logs exceeding token budgets (default `2,000` tokens) are spilled to disk artifacts (`.engram/.runtime/artifacts/`) with bounded head+tail summary pointers injected into the LLM context.

---

## Four-Plane Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│ 4. OBSERVABILITY & TIME-TRAVEL UI (React / TypeScript embedded in Go)│
│    • DAG Execution Visualizer • Diff Inspector • Rule Approval Inbox │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │ RFC 6455 WebSocket / JSON-RPC 2.0
┌──────────────────────────────────▼───────────────────────────────────┐
│ 1. CONTROL PLANE DAEMON (Go 1.23+ Single Binary)                     │
│    • Custom Agent Loop • Git Worktree Manager • MCP Host • Hook Gate │
└──────┬───────────────────────────┬───────────────────────────┬───────┘
       │ JSON-RPC / Unix Socket    │ Docker / Seatbelt / bwrap │ SQLite WAL
┌──────▼───────────────────┐ ┌─────▼───────────────────┐ ┌─────▼───────┐
│ 3. EVOLUTION COMPILER    │ │ 2. EXECUTION SANDBOX    │ │ STATE STORE │
│    (Python 3.12+ & AST)  │ │    (Containers & Proxy) │ │ (WAL Mode)  │
│    • Friction Detector   │ │    • Strict / Native    │ │ • Sessions  │
│    • Hook/Tool Compiler  │ │    • HTTP/SOCKS5 Proxy  │ │ • Steps/SHA │
│    • Shadow Evaluator    │ │    • Secret Scrubber    │ │ • Engrams   │
└──────────────────────────┘ └─────────────────────────┘ └─────────────┘
```

### Tech Stack by Plane

| Plane | Tech Stack | Core Responsibilities |
| --- | --- | --- |
| **1. Control Plane Daemon** | Go 1.23+, Cobra, `mcp-go`, raw `net/http` SSE/NDJSON | Compiles to a single static binary (`CGO_ENABLED=0`). Runs the deterministic streaming agent loop, pre/post Python Hook Gate (exit `0` allow / exit `2` block), 2,000-token artifact compactor, and detached Git worktrees. |
| **2. Sandbox & Egress Proxy** | Git Worktrees, Docker/Podman, Seatbelt (`sandbox-exec`), `bubblewrap`, Go HTTP/SOCKS5 proxy | Isolates every session in a detached worktree, strips host secret env vars, routes outbound traffic through a domain-allowlisted local proxy, and scrubs secrets from outbound HTTP and LLM payloads via regex + Shannon entropy + `.env` matching. |
| **3. Evolution Compiler** | Python 3.12+, `ast`, `sqlite3`, `uv` (zero external deps) | Sidecar daemon over Unix Domain Socket JSON-RPC 2.0. Detects repeated errors, circular edits, and multi-step chains; synthesizes stdlib-only Python hooks/MCP tools/Markdown rules; validates via `ast.parse()` and shadow worktree replay. |
| **4. Local State & Web UI** | SQLite (WAL mode), React 19, TypeScript, Vite (`//go:embed`) | Stores full traces and step-to-SHA snapshots in `.engram/.runtime/state.db`. Serves an embedded Observability & Time-Travel SPA over RFC 6455 WebSocket + HTTP JSON-RPC 2.0. |

---

## Repository & On-Disk Layout

### Monorepo Structure

```text
engram/
├── cmd/engram/                 # CLI entrypoint (init, run, status, rewind, rules, ui)
├── internal/
│   ├── control/                # Streaming LLM router, agent loop, hook gate, context compactor, UI server
│   ├── worktree/               # Detached Git worktree lifecycle & atomic step-level shadow commits
│   ├── sandbox/                # Strict (Docker/Podman) & Native (Seatbelt/bwrap/Windows) runners
│   ├── proxy/                  # Domain-allowlisted HTTP/SOCKS5 proxy & regex/entropy secret scrubber
│   ├── mcp/                    # Native mcp-go host & synthesized stdio Python tool loader
│   ├── store/                  # Embedded WAL-mode SQLite schema & typed persistence layer
│   └── ipc/                    # Unix Domain Socket JSON-RPC 2.0 client & sidecar launcher
├── compiler/                   # Zero-dependency Python 3.12+ Evolution Compiler (uv / pyproject.toml)
│   └── engram_compiler/
│       ├── detector.py         # Friction, loop, and normalized failure-signature analyzer
│       ├── synthesizer.py      # AST-validated hook, MCP tool, and scoped rule compiler
│       ├── shadow_eval.py      # Isolated detached worktree replay verifier
│       └── server.py           # JSON-RPC 2.0 listener (/tmp/engram-<repo_hash>.sock)
├── ui/                         # React + TypeScript + Vite SPA embedded via ui/embed.go
├── benchmarks/                 # Multi-pass empirical continual-learning benchmark suite
├── scripts/install.sh          # Checksum-verified POSIX installer
├── .goreleaser.yaml            # Cross-platform binary, Homebrew cask, and Python wheel release config
└── Makefile                    # Unified build pipeline (UI -> Go binary -> Python wheel)
```

### Target Repository `.engram/` Workspace

Running `engram init` inside any Git repository creates a Git-trackable harness directory alongside a git-ignored `.runtime/` state folder:

```text
.engram/
├── .gitignore                  # Ignores .runtime/ automatically
├── config.toml                 # Model endpoints, sandbox policy, domain allowlist, evolution thresholds
├── manifest.json               # Active/pending registry of compiled hooks, tools, and scoped rules
├── hooks/                      # Deterministic Python pre/post tool validators (exit 0=allow, 2=block)
├── tools/                      # Synthesized MCP-compatible Python stdio tools
├── rules/                      # Glob-scoped Markdown rules (YAML frontmatter `globs: [...]`)
└── .runtime/                   # Git-ignored local execution state
    ├── state.db                # SQLite WAL telemetry & step-to-SHA replay database
    ├── artifacts/              # Spilled raw stdout/stderr logs exceeding 2,000 tokens
    └── worktrees/              # Detached Git worktrees per session
```

---

## Quick Start

### 1. Build from Source

Prerequisites: **Go 1.23+**, **Node.js 20+**, **Python 3.12+**, **Git**, and optionally **`uv`**.

```bash
# macOS / Linux (unified Makefile)
make all

# Windows PowerShell
cd ui && npm install && npm run build && cd ..
$env:CGO_ENABLED="0"
go build -trimpath -ldflags "-s -w" -o bin\engram.exe ./cmd/engram
cd compiler && python -m uv build && cd ..
```

*(For pre-built releases on macOS/Linux, see `scripts/install.sh` or Homebrew via `.goreleaser.yaml`.)*

### 2. Initialize a Repository

```bash
engram init --repo /path/to/your-repo
engram status --repo /path/to/your-repo
```

### 3. Configure Your LLM Provider (`.engram/config.toml`)

Engram speaks directly to **Anthropic**, **OpenAI**, and local **Ollama**:

```toml
# Example: Local Ollama (zero API cost)
[model]
provider = "ollama"
model = "qwen2.5-coder:7b"
endpoint = "http://127.0.0.1:11434/api/chat"
api_key_env = ""
max_output_tokens = 4096
```

For Anthropic (default) or OpenAI, set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in your shell environment.

### 4. Run Autonomous Tasks, Rewind, Manage Rules & Open the Dashboard

```bash
# Run a task inside an isolated detached Git worktree
engram run "Create hello.py that prints Hello Engram and run it with python" --repo /path/to/your-repo

# Rewind a session worktree to any prior step SHA
engram rewind <session-id> --step 1 --repo /path/to/your-repo

# Inspect, approve, or reject compiled engrams
engram rules list --repo /path/to/your-repo
engram rules show <engram-id> --repo /path/to/your-repo
engram rules approve <engram-id> --repo /path/to/your-repo
engram rules reject <engram-id> --repo /path/to/your-repo

# Launch the embedded Observability & Time-Travel UI (http://127.0.0.1:7420)
engram ui --repo /path/to/your-repo
```

---

## Empirical Continual-Learning Benchmark Proofs

The multi-pass evaluation harness (`benchmarks/run_benchmark.py`) measures **Run 1 (cold harness)** through **Run 3 (self-evolved harness)** across all three engram classes (`hook`, `tool`, `rule`) using real Git worktrees, the real Python Evolution Compiler (`detector.py` → `synthesizer.py` → `shadow_eval.py`), and real compiled artifact execution.

### Verified Results (`engram-continual-learning-v1`, `--mode local --runs 3`)

- **Pass Rate Gain (Run 1 → Run 3):** **`+66.7 pp`** (`33.3%` → `100.0%`)
- **Token Reduction (Run 1 → Run 3):** **`78.0%`** (`23,099` → `5,071` tokens)
- **Wall-Clock Speedup (Run 1 → Run 3):** **`1.90x`** (`3,374.7 ms` → `1,780.3 ms`)

#### Aggregate Pass Comparison

| Pass | Passed / Total | Pass Rate | Total Tokens | Mean Tokens/Task | Total Wall-Clock (ms) | Errors Prevented |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Run 1 (Cold Harness)** | 1/3 | 33.3% | 23,099 | 7,699.7 | 3,374.7 | 0 |
| **Run 2 (Self-Evolved)** | 3/3 | 100.0% | 5,071 | 1,690.3 | 1,818.2 | 3 |
| **Run 3 (Self-Evolved)** | 3/3 | 100.0% | 5,071 | 1,690.3 | 1,780.3 | 3 |

#### Per-Task Trace Measurements

| Task | Run | Passed | Steps | Errors | Prevented | Total Tokens | Wall-Clock (ms) | Compiled Engram |
| --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: | --- |
| `swe_db_port_prereq` | 1 | FAIL | 3 | 3 | 0 | 8,079 | 2,636.9 | `eng_1A1FFB7F81CF1DE36` (`hook`) |
| `swe_db_port_prereq` | 2 | PASS | 2 | 0 | 1 | 1,736 | 1,645.4 | — |
| `swe_db_port_prereq` | 3 | PASS | 2 | 0 | 1 | 1,736 | 1,613.0 | — |
| `swe_composite_migration_chain` | 1 | PASS | 4 | 0 | 0 | 9,140 | 560.2 | `eng_1A1FFB80D9B88CEED` (`tool`) |
| `swe_composite_migration_chain` | 2 | PASS | 1 | 0 | 1 | 1,530 | 171.8 | — |
| `swe_composite_migration_chain` | 3 | PASS | 1 | 0 | 1 | 1,530 | 167.2 | — |
| `swe_circular_async_edit` | 1 | FAIL | 3 | 2 | 0 | 5,880 | 177.5 | `eng_1A1FFB81172E785C8` (`rule`) |
| `swe_circular_async_edit` | 2 | PASS | 1 | 0 | 1 | 1,805 | 1.0 | — |
| `swe_circular_async_edit` | 3 | PASS | 1 | 0 | 1 | 1,805 | 0.1 | — |

## Real-World Stress Test (`pallets/click`)

To validate Engram outside synthetic benchmarks, we ran an unconfigured cold-start test against [`pallets/click`](https://github.com) with `pypi.org` omitted from `.engram/config.toml` (`sandbox.allowed_domains`):

* **Zero Host Mutation:** Isolated every agent session inside a detached Git worktree (`.engram/.runtime/worktrees/`), leaving the primary `click` repository completely clean (`git status` untouched).
* **Egress Proxy Enforcement:** Intercepted and blocked unauthorized outbound `pip install` attempts (`[egress-proxy] blocked connect -> pypi.org`).
* **Autonomous Hook Synthesis & Shadow Verification:** Upon detecting consecutive `pip` tunnel failures, the Python Evolution Compiler synthesized `.engram/hooks/eng_1A202FA5072521870_guard_python.py`, validated it via AST, and achieved a **100% shadow replay pass rate** before queuing it for human approval.
* **Deterministic Continual Learning (Run 2):** Once approved (`engram rules approve`), the active hook intercepted **9/9 (`100%`)** subsequent failing invocations in a fresh session via deterministic exit code `2` before they could hit the sandbox or network.


#### Reproduce Benchmarks

```bash
# Deterministic zero-API-cost evaluation across hooks, MCP tools, and rules:
cd benchmarks
python -m unittest test_benchmark.py -v
python run_benchmark.py --mode local --runs 3

# Live SWE-bench / repository evaluation using the compiled engram CLI:
python run_benchmark.py --mode live --runs 3 --tasks tasks.json --engram-bin ../bin/engram
```

Reports are written to `benchmarks/results/latest.json` and `benchmarks/results/latest.md`.

---

## Security & Sandboxing

- **Dual-Mode Sandboxing (`internal/sandbox/`):**
  - **`native` mode:** macOS Seatbelt (`sandbox-exec` restricting writes to the active worktree + `/tmp` and egress to `127.0.0.1`), Linux `bubblewrap` (`--ro-bind` system mounts + worktree-only write bind), and Windows worktree-scoped restricted execution.
  - **`strict` mode:** Ephemeral Docker/Podman containers (`--rm --init --cap-drop=ALL --security-opt=no-new-privileges:true --read-only --pids-limit=256`) with only the session worktree mounted at `/workspace`.
- **Host Secret Stripping:** Sensitive host environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AWS_*`, `GITHUB_TOKEN`, `DATABASE_URL`, `SSH_*`, etc.) are stripped before launching sandboxed child processes.
- **Egress Proxy & Secret Scrubbing (`internal/proxy/`):**
  - Local HTTP/CONNECT + RFC 1928 SOCKS5 proxy enforces default-deny `sandbox.allowed_domains` from `.engram/config.toml` and blocks raw IP / cloud metadata (`169.254.169.254`) SSRF attempts.
  - Layered regex + Shannon entropy + exact `.env` value scrubber blocks outbound HTTP secret exfiltration (`403 Forbidden`) and redacts accidental secret leaks from outbound LLM prompt payloads.

---

## Verification Test Suites

```bash
# 1. Go Control Plane, Store, Worktrees, MCP, Proxy, Sandbox, IPC & CLI tests
go test -v ./...

# 2. Python Evolution Compiler (Detector, AST Synthesizer, Shadow Evaluator, UDS Server)
cd compiler && python -m unittest discover -s tests -v

# 3. Embedded React + TypeScript UI typecheck & production bundle
cd ui && npm run typecheck && npm run build

# 4. Continual-Learning Benchmark verification
cd benchmarks && python -m unittest test_benchmark.py -v
```