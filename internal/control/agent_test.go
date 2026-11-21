package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"engram/internal/ipc"
	"engram/internal/sandbox"
	"engram/internal/store"
)

func initTestGitRepoForAgent(t *testing.T) Workspace {
	t.Helper()
	dir := t.TempDir()

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	runGit("init")
	runGit("config", "user.email", "agent-test@engram.local")
	runGit("config", "user.name", "Engram Test")
	runGit("config", "core.autocrlf", "false")

	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('v1')\n"), 0o644); err != nil {
		t.Fatalf("write main.py: %v", err)
	}
	runGit("add", "main.py")
	runGit("commit", "-m", "initial commit")

	ws, err := InitWorkspace(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("InitWorkspace() error = %v", err)
	}
	return ws
}

func TestModelRouterStreamsAnthropicOpenAIAndOllama(t *testing.T) {
	ctx := context.Background()

	// 1. Anthropic SSE
	anthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-anth-key" {
			t.Fatalf("missing x-api-key header")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"usage":{"input_tokens":120}}}`,
			``,
			`event: content_block_start`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking "}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"files."}}`,
			``,
			`event: content_block_start`,
			`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"read_file","input":{}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"main.py\"}"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":45}}`,
			``,
		}, "\n")+"\n")
	}))
	t.Cleanup(anthSrv.Close)

	anthRouter, err := NewModelRouter(ModelConfig{
		Provider:        "anthropic",
		Model:           "claude-sonnet-4-20250514",
		Endpoint:        anthSrv.URL,
		MaxOutputTokens: 1024,
	}, "test-anth-key", anthSrv.Client())
	if err != nil {
		t.Fatalf("NewModelRouter(anthropic) error = %v", err)
	}

	var anthDeltas strings.Builder
	anthRes, err := anthRouter.StreamChat(ctx, ChatRequest{
		SystemPrompt: "sys",
		Messages:     []Message{{Role: RoleUser, Content: "hi"}},
	}, func(d string) { anthDeltas.WriteString(d) })
	if err != nil {
		t.Fatalf("StreamChat(anthropic) error = %v", err)
	}
	if anthRes.Content != "Checking files." || anthDeltas.String() != "Checking files." {
		t.Fatalf("anthropic content = %q, deltas = %q", anthRes.Content, anthDeltas.String())
	}
	if len(anthRes.ToolCalls) != 1 || anthRes.ToolCalls[0].Name != "read_file" || string(anthRes.ToolCalls[0].Input) != `{"path":"main.py"}` {
		t.Fatalf("anthropic toolCalls = %+v", anthRes.ToolCalls)
	}
	if anthRes.TokensIn != 120 || anthRes.TokensOut != 45 {
		t.Fatalf("anthropic tokens = (%d, %d), want (120, 45)", anthRes.TokensIn, anthRes.TokensOut)
	}

	// 2. OpenAI SSE
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-oai-key" {
			t.Fatalf("missing Authorization header")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, strings.Join([]string{
			`data: {"choices":[{"delta":{"content":"Running "}}]}`,
			``,
			`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_abc","function":{"name":"bash","arguments":"{\"command\":"}}]}}]}`,
			``,
			`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"pytest\"}"}}]}}]}`,
			``,
			`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":80,"completion_tokens":22}}`,
			``,
			`data: [DONE]`,
			``,
		}, "\n")+"\n")
	}))
	t.Cleanup(oaiSrv.Close)

	oaiRouter, err := NewModelRouter(ModelConfig{
		Provider:        "openai",
		Model:           "gpt-4o",
		Endpoint:        oaiSrv.URL,
		MaxOutputTokens: 1024,
	}, "test-oai-key", oaiSrv.Client())
	if err != nil {
		t.Fatalf("NewModelRouter(openai) error = %v", err)
	}
	oaiRes, err := oaiRouter.StreamChat(ctx, ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "run tests"}},
	}, nil)
	if err != nil {
		t.Fatalf("StreamChat(openai) error = %v", err)
	}
	if oaiRes.Content != "Running " || len(oaiRes.ToolCalls) != 1 || string(oaiRes.ToolCalls[0].Input) != `{"command":"pytest"}` {
		t.Fatalf("openai response = %+v", oaiRes)
	}
	if oaiRes.TokensIn != 80 || oaiRes.TokensOut != 22 {
		t.Fatalf("openai tokens = (%d, %d), want (80, 22)", oaiRes.TokensIn, oaiRes.TokensOut)
	}

	// 3. Ollama NDJSON
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, `{"message":{"role":"assistant","content":"Done."},"done":false}`)
		fmt.Fprintln(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"id":"ol_1","function":{"name":"list_files","arguments":{"path":"."}}}]},"done":true,"done_reason":"stop","prompt_eval_count":64,"eval_count":18}`)
	}))
	t.Cleanup(ollamaSrv.Close)

	ollamaRouter, err := NewModelRouter(ModelConfig{
		Provider: "ollama",
		Model:    "qwen2.5-coder:32b",
		Endpoint: ollamaSrv.URL,
	}, "", ollamaSrv.Client())
	if err != nil {
		t.Fatalf("NewModelRouter(ollama) error = %v", err)
	}
	ollamaRes, err := ollamaRouter.StreamChat(ctx, ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "list"}},
	}, nil)
	if err != nil {
		t.Fatalf("StreamChat(ollama) error = %v", err)
	}
	if ollamaRes.Content != "Done." || len(ollamaRes.ToolCalls) != 1 || ollamaRes.ToolCalls[0].Name != "list_files" {
		t.Fatalf("ollama response = %+v", ollamaRes)
	}
	if ollamaRes.TokensIn != 64 || ollamaRes.TokensOut != 18 {
		t.Fatalf("ollama tokens = (%d, %d), want (64, 18)", ollamaRes.TokensIn, ollamaRes.TokensOut)
	}
}

func TestAgentLoopEndToEndWithHookBlockShadowCommitsAndContextSpill(t *testing.T) {
	pyBin, err := ResolvePythonBinary()
	if err != nil {
		t.Skipf("skipping python-hook agent loop test: %v", err)
	}

	ctx := context.Background()
	ws := initTestGitRepoForAgent(t)

	// Install an active deterministic pre-tool hook that blocks running main.py
	// until .ready exists in the isolated worktree.
	hookScript := `import json, os, sys
if not os.path.exists(os.path.join(os.getcwd(), ".ready")):
    print("Missing .ready marker in worktree. Write .ready before running main.py.")
    sys.exit(2)
sys.exit(0)
`
	hookRel := "hooks/eng_require_ready.py"
	if err := os.WriteFile(filepath.Join(ws.EngramDir(), hookRel), []byte(hookScript), 0o644); err != nil {
		t.Fatalf("write hook script: %v", err)
	}

	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_require_ready",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `main\.py`,
		FilePath:         hookRel,
		FailureSignature: "manual_ready_check",
		Status:           store.EngramStatusActive,
	}); err != nil {
		t.Fatalf("CreateEngram() error = %v", err)
	}

	// Build a large padded log > 600 bytes to test ContextCompactor spill with threshold=100 tokens.
	var turnCount atomic.Int32
	var turn3SawBlockedGuidance atomic.Bool
	var turn4SawArtifactPointer atomic.Bool

	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		n := turnCount.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")

		switch n {
		case 1:
			// Turn 1: LLM tries to run main.py immediately -> blocked by exit 2 hook!
			writeAnthropicToolTurn(w, "Let me run main.py first.", "t1", "bash", map[string]any{
				"command": fmt.Sprintf(`"%s" main.py`, pyBin),
			})
		case 2:
			// Verify hook exit 2 guidance was fed back into the LLM prompt.
			if strings.Contains(bodyStr, "Missing .ready marker in worktree") {
				turn3SawBlockedGuidance.Store(true)
			}
			// Turn 2: LLM writes .ready and updates main.py inside the isolated worktree.
			writeAnthropicMultiToolTurn(w, "Creating .ready and updating main.py.", []ToolCall{
				{ID: "t2a", Name: "write_file", Input: json.RawMessage(`{"path":".ready","content":"ok\n"}`)},
				{ID: "t2b", Name: "write_file", Input: json.RawMessage(`{"path":"main.py","content":"print('v2_verified')\n"}`)},
			})
		case 3:
			// Turn 3: LLM runs a command emitting > 100 tokens to trigger artifact spill (Invariant #5).
			cmd := fmt.Sprintf(`"%s" -c "print('START_LOG'); print('X' * 1200); print('END_LOG')"`, pyBin)
			writeAnthropicToolTurn(w, "Running verbose check.", "t3", "bash", map[string]any{
				"command": cmd,
			})
		case 4:
			// Verify raw 1200-char log was spilled and replaced by an artifact pointer in LLM prompt.
			if strings.Contains(bodyStr, "full raw artifact saved to:") && !strings.Contains(bodyStr, strings.Repeat("X", 800)) {
				turn4SawArtifactPointer.Store(true)
			}
			// Turn 4: Final response.
			writeAnthropicTextTurn(w, "Updated main.py to v2_verified and verified output.")
		default:
			t.Fatalf("unexpected LLM turn %d", n)
		}
	}))
	t.Cleanup(mockLLM.Close)

	cfg := DefaultConfig()
	cfg.Context.ArtifactTokenThreshold = 100
	cfg.Model.Endpoint = mockLLM.URL

	router, err := NewModelRouter(cfg.Model, "test-key", mockLLM.Client())
	if err != nil {
		t.Fatalf("NewModelRouter() error = %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	loop, err := NewAgentLoop(AgentLoopConfig{
		Workspace: ws,
		Config:    cfg,
		Manifest: Manifest{
			Version: "1.0",
			Hooks: []ManifestEntry{
				{
					ID:             "eng_require_ready",
					Kind:           store.EngramKindHook,
					TargetTool:     "bash",
					TriggerPattern: `main\.py`,
					FilePath:       hookRel,
					Status:         store.EngramStatusActive,
				},
			},
		},
		Store:     st,
		Router:    router,
		PythonBin: pyBin,
		Out:       &outBuf,
		ErrOut:    &errBuf,
	})
	if err != nil {
		t.Fatalf("NewAgentLoop() error = %v", err)
	}

	res, err := loop.Run(ctx, "Update main.py to print v2_verified and verify.")
	if err != nil {
		t.Fatalf("loop.Run() error = %v", err)
	}

	if !turn3SawBlockedGuidance.Load() {
		t.Fatalf("LLM did not receive deterministic hook exit-2 guidance")
	}
	if !turn4SawArtifactPointer.Load() {
		t.Fatalf("LLM received raw uncompacted log instead of disk artifact pointer (Invariant #5)")
	}
	if res.StepsRecorded != 5 {
		t.Fatalf("StepsRecorded = %d, want 5 (1 blocked + 2 writes + 1 bash + 1 final)", res.StepsRecorded)
	}

	// Verify session status is completed.
	sess, err := st.GetSession(ctx, res.SessionID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if sess.Status != store.SessionCompleted {
		t.Fatalf("session status = %q, want completed", sess.Status)
	}

	// Verify all 5 steps and their atomic Git commit SHAs + artifact spill path.
	steps, err := st.ListStepsBySession(ctx, res.SessionID)
	if err != nil {
		t.Fatalf("ListStepsBySession() error = %v", err)
	}
	if len(steps) != 5 {
		t.Fatalf("steps len = %d, want 5", len(steps))
	}
	if steps[0].ExitCode == nil || *steps[0].ExitCode != HookExitBlock {
		t.Fatalf("step 1 exit code = %v, want %d", steps[0].ExitCode, HookExitBlock)
	}
	if steps[2].GitCommitSHA == res.BaseCommitSHA {
		t.Fatalf("expected atomic shadow commit SHA after write_file")
	}
	if steps[3].RawArtifactPath == "" {
		t.Fatalf("expected step 4 RawArtifactPath to be populated")
	}
	if _, err := os.Stat(steps[3].RawArtifactPath); err != nil {
		t.Fatalf("artifact file missing on disk: %v", err)
	}

	// Invariant #1: primary host main.py must still be v1 while worktree has v2_verified.
	hostMain, err := os.ReadFile(filepath.Join(ws.RepoRoot, "main.py"))
	if err != nil {
		t.Fatalf("read host main.py: %v", err)
	}
	if string(hostMain) != "print('v1')\n" {
		t.Fatalf("host main.py mutated = %q, want print('v1')", string(hostMain))
	}
	wtMain, err := os.ReadFile(filepath.Join(res.WorktreePath, "main.py"))
	if err != nil {
		t.Fatalf("read worktree main.py: %v", err)
	}
	if string(wtMain) != "print('v2_verified')\n" {
		t.Fatalf("worktree main.py = %q, want print('v2_verified')", string(wtMain))
	}
}

func writeAnthropicToolTurn(w http.ResponseWriter, thought, id, name string, input map[string]any) {
	writeAnthropicMultiToolTurn(w, thought, []ToolCall{
		{ID: id, Name: name, Input: mustJSON(input)},
	})
}

func writeAnthropicMultiToolTurn(w http.ResponseWriter, thought string, calls []ToolCall) {
	fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":50}}}\n\n")
	idx := 0
	if thought != "" {
		fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n", idx)
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", idx, mustJSONString(thought))
		idx++
	}
	for _, c := range calls {
		fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"tool_use\",\"id\":%s,\"name\":%s,\"input\":{}}}\n\n",
			idx, mustJSONString(c.ID), mustJSONString(c.Name))
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":%s}}\n\n",
			idx, mustJSONString(string(c.Input)))
		idx++
	}
	fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":25}}\n\n")
}

func writeAnthropicTextTurn(w http.ResponseWriter, text string) {
	fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":40}}}\n\n")
	fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", mustJSONString(text))
	fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n")
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return json.RawMessage(b)
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestPhase2SecurityIntegrationScrubsLLMPayloadAndInjectsEgressProxy(t *testing.T) {
	ctx := context.Background()
	ws := initTestGitRepoForAgent(t)

	// Place a repo .env file containing a custom secret AND set a host API key env var.
	const dotEnvSecret = "pay_live_engram_dotenv_secret_99"
	const hostSecret = "sk-ant-host-secret-must-not-leak-1234567890"
	if err := os.WriteFile(filepath.Join(ws.RepoRoot, ".env"),
		[]byte("PAYMENTS_SECRET="+dotEnvSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	t.Setenv("ANTHROPIC_API_KEY", hostSecret)

	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var turnCount atomic.Int32
	var turn2Body atomic.Value

	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")

		switch turnCount.Add(1) {
		case 1:
			// Ask bash to print HTTP_PROXY, ANTHROPIC_API_KEY, and simulated leaked secrets.
			cmd := fmt.Sprintf(`echo "PROXY=${HTTP_PROXY} HOSTKEY=${ANTHROPIC_API_KEY} LEAK=%s PEM=-----BEGIN OPENSSH PRIVATE KEY-----"`, dotEnvSecret)
			if runtime.GOOS == "windows" {
				cmd = fmt.Sprintf(`echo PROXY=%%HTTP_PROXY%% HOSTKEY=%%ANTHROPIC_API_KEY%% LEAK=%s PEM=-----BEGIN OPENSSH PRIVATE KEY-----`, dotEnvSecret)
			}
			writeAnthropicToolTurn(w, "Inspecting environment.", "s1", "bash", map[string]any{
				"command": cmd,
			})
		case 2:
			turn2Body.Store(string(body))
			writeAnthropicTextTurn(w, "Security check complete.")
		default:
			t.Fatalf("unexpected turn")
		}
	}))
	t.Cleanup(mockLLM.Close)

	cfg := DefaultConfig()
	cfg.Model.Endpoint = mockLLM.URL
	cfg.Sandbox.Mode = "native"
	cfg.Sandbox.RedactSecrets = true

	router, err := NewModelRouter(cfg.Model, "router-only-key", mockLLM.Client())
	if err != nil {
		t.Fatalf("NewModelRouter() error = %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	loop, err := NewAgentLoop(AgentLoopConfig{
		Workspace: ws,
		Config:    cfg,
		Manifest:  DefaultManifest(),
		Store:     st,
		Router:    router,
		Out:       &outBuf,
		ErrOut:    &errBuf,
	})
	if err != nil {
		t.Fatalf("NewAgentLoop() error = %v", err)
	}

	if _, err := loop.Run(ctx, "Verify sandbox and secret redaction."); err != nil {
		t.Fatalf("loop.Run() error = %v", err)
	}

	payload, _ := turn2Body.Load().(string)
	if payload == "" {
		t.Fatalf("did not capture turn 2 LLM payload")
	}

	// 1. EgressProxy HTTP_PROXY must be injected into the sandboxed bash process.
	if !strings.Contains(payload, "PROXY=http://127.0.0.1:") {
		t.Fatalf("expected injected local EgressProxy URL in sandbox output:\n%s", payload)
	}
	// 2. Host ANTHROPIC_API_KEY must be stripped from the sandboxed child environment.
	if strings.Contains(payload, hostSecret) {
		t.Fatalf("host ANTHROPIC_API_KEY leaked into sandbox / LLM payload:\n%s", payload)
	}
	// 3. Repo .env secret and SSH private key marker must be scrubbed before leaving ModelRouter.
	if strings.Contains(payload, dotEnvSecret) {
		t.Fatalf(".env secret leaked in outbound LLM payload:\n%s", payload)
	}
	if strings.Contains(payload, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("SSH private key header leaked in outbound LLM payload:\n%s", payload)
	}
	if !strings.Contains(payload, "[REDACTED:known_env_value]") || !strings.Contains(payload, "[REDACTED:ssh_private_key]") {
		t.Fatalf("expected redaction markers in outbound LLM payload:\n%s", payload)
	}
}

type simulatedServiceSandbox struct {
	port           int
	serviceStarted atomic.Bool
	pytestCalls    atomic.Int32
	listener       net.Listener
}

func (s *simulatedServiceSandbox) Backend() string { return "sim-phase3" }

func (s *simulatedServiceSandbox) Run(_ context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	if strings.Contains(req.Command, "docker compose") {
		if !s.serviceStarted.Swap(true) {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
			if err != nil {
				return sandbox.ExecResult{Output: err.Error(), ExitCode: 1, Backend: s.Backend()}, nil
			}
			s.listener = ln
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
		}
		return sandbox.ExecResult{Output: "db container started\n", ExitCode: 0, Backend: s.Backend()}, nil
	}

	if strings.HasPrefix(strings.TrimSpace(req.Command), "pytest") {
		s.pytestCalls.Add(1)
		if !s.serviceStarted.Load() {
			return sandbox.ExecResult{
				Output:   fmt.Sprintf("psycopg.OperationalError: ConnectionRefusedError on port %d\n", s.port),
				ExitCode: 1,
				Backend:  s.Backend(),
			}, nil
		}
		return sandbox.ExecResult{Output: "12 passed in 0.4s\n", ExitCode: 0, Backend: s.Backend()}, nil
	}

	return sandbox.ExecResult{Output: "ok\n", ExitCode: 0, Backend: s.Backend()}, nil
}

func (s *simulatedServiceSandbox) Close() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func TestPhase3ClosedLoopRun1SynthesizesHookAndRun2PassesCleanly(t *testing.T) {
	pyBin, err := ResolvePythonBinary()
	if err != nil {
		t.Skipf("python not found: %v", err)
	}
	compilerDir, err := filepath.Abs(filepath.Join("..", "..", "compiler"))
	if err != nil {
		t.Fatalf("resolve compiler dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(compilerDir, "engram_compiler", "server.py")); err != nil {
		t.Skipf("python compiler not found at %q", compilerDir)
	}

	ctx := context.Background()
	ws := initTestGitRepoForAgent(t)
	if err := os.WriteFile(filepath.Join(ws.RepoRoot, "docker-compose.test.yml"),
		[]byte("services:\n  db: {}\n"), 0o644); err != nil {
		t.Fatalf("write docker-compose.test.yml: %v", err)
	}

	// Reserve an unused local TCP port for the simulated test DB.
	portProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	testPort := portProbe.Addr().(*net.TCPAddr).Port
	_ = portProbe.Close()

	// Start the real Python Evolution Compiler UDS sidecar.
	sockPath, err := ipc.SocketPathForRepo(ws.RepoRoot)
	if err != nil {
		t.Fatalf("SocketPathForRepo: %v", err)
	}
	sidecar, err := ipc.StartSidecar(ctx, pyBin, compilerDir, sockPath)
	if err != nil {
		t.Fatalf("StartSidecar: %v", err)
	}
	t.Cleanup(func() { _ = sidecar.Stop() })

	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// --- RUN 1 (Cold Harness): 3 consecutive pytest ConnectionRefusedError failures ---
	var run1Turns atomic.Int32
	mockLLMRun1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch run1Turns.Add(1) {
		case 1, 2, 3:
			writeAnthropicToolTurn(w, "Running pytest suite.", fmt.Sprintf("r1_%d", run1Turns.Load()), "bash", map[string]any{
				"command": "pytest tests/api",
			})
		case 4:
			writeAnthropicTextTurn(w, "Tests failed due to refused database connection.")
		default:
			t.Fatalf("unexpected Run 1 turn")
		}
	}))
	t.Cleanup(mockLLMRun1.Close)

	simRun1 := &simulatedServiceSandbox{port: testPort}
	t.Cleanup(simRun1.Close)

	cfg1 := DefaultConfig()
	cfg1.Model.Endpoint = mockLLMRun1.URL
	router1, err := NewModelRouter(cfg1.Model, "test-key", mockLLMRun1.Client())
	if err != nil {
		t.Fatalf("NewModelRouter(run1): %v", err)
	}

	loop1, err := NewAgentLoop(AgentLoopConfig{
		Workspace:       ws,
		Config:          cfg1,
		Manifest:        DefaultManifest(),
		Store:           st,
		Router:          router1,
		SandboxRunner:   simRun1,
		EvolutionClient: sidecar.Client(),
		PythonBin:       pyBin,
	})
	if err != nil {
		t.Fatalf("NewAgentLoop(run1): %v", err)
	}

	res1, err := loop1.Run(ctx, "Run API test suite")
	if err != nil {
		t.Fatalf("Run 1 error = %v", err)
	}
	if len(res1.SynthesizedEngrams) != 1 {
		t.Fatalf("Run 1 synthesized %d engrams, want 1", len(res1.SynthesizedEngrams))
	}
	compiled := res1.SynthesizedEngrams[0]
	if !compiled.ShadowVerified || compiled.Status != "active" || compiled.Kind != "hook" {
		t.Fatalf("Run 1 compiled engram = %+v, want active shadow-verified hook", compiled)
	}

	// --- RUN 2 (Self-Evolved Harness): identical task inherits compiled hook automatically ---
	_, cfg2, manifest2, err := LoadWorkspace(ctx, ws.RepoRoot)
	if err != nil {
		t.Fatalf("LoadWorkspace(run2): %v", err)
	}

	var run2Turns atomic.Int32
	var run2SawHookGuidance atomic.Bool
	mockLLMRun2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		switch run2Turns.Add(1) {
		case 1:
			// Agent tries the exact same pytest command first -> intercepted by synthesized hook (exit 2)!
			writeAnthropicToolTurn(w, "Running pytest suite.", "r2_1", "bash", map[string]any{
				"command": "pytest tests/api",
			})
		case 2:
			if strings.Contains(string(body), "docker-compose.test.yml") {
				run2SawHookGuidance.Store(true)
			}
			// Agent follows deterministic hook guidance and starts DB container first.
			writeAnthropicToolTurn(w, "Starting test DB container.", "r2_2", "bash", map[string]any{
				"command": "docker compose -f docker-compose.test.yml up -d",
			})
		case 3:
			// Agent retries pytest -> port is now open -> hook exits 0 -> pytest passes!
			writeAnthropicToolTurn(w, "Retrying pytest now that DB is up.", "r2_3", "bash", map[string]any{
				"command": "pytest tests/api",
			})
		case 4:
			writeAnthropicTextTurn(w, "All 12 API tests passed.")
		default:
			t.Fatalf("unexpected Run 2 turn")
		}
	}))
	t.Cleanup(mockLLMRun2.Close)

	simRun2 := &simulatedServiceSandbox{port: testPort}
	t.Cleanup(simRun2.Close)

	cfg2.Model.Endpoint = mockLLMRun2.URL
	router2, err := NewModelRouter(cfg2.Model, "test-key", mockLLMRun2.Client())
	if err != nil {
		t.Fatalf("NewModelRouter(run2): %v", err)
	}

	loop2, err := NewAgentLoop(AgentLoopConfig{
		Workspace:     ws,
		Config:        cfg2,
		Manifest:      manifest2,
		Store:         st,
		Router:        router2,
		SandboxRunner: simRun2,
		PythonBin:     pyBin,
	})
	if err != nil {
		t.Fatalf("NewAgentLoop(run2): %v", err)
	}

	res2, err := loop2.Run(ctx, "Run API test suite")
	if err != nil {
		t.Fatalf("Run 2 error = %v", err)
	}
	if !run2SawHookGuidance.Load() {
		t.Fatalf("Run 2 LLM did not receive synthesized hook guidance")
	}
	// On Run 2, pytest should have only executed ONCE (after the DB started; the failing attempt was prevented!).
	if simRun2.pytestCalls.Load() != 1 {
		t.Fatalf("Run 2 pytest executed %d times, want 1 (initial failing attempt blocked by hook)", simRun2.pytestCalls.Load())
	}
	if !strings.Contains(res2.FinalResponse, "12 API tests passed") {
		t.Fatalf("unexpected Run 2 response: %q", res2.FinalResponse)
	}

	// Verify SQLite engram metrics recorded the prevented error on Run 2.
	eng, err := st.GetEngram(ctx, compiled.EngramID)
	if err != nil {
		t.Fatalf("GetEngram(%q): %v", compiled.EngramID, err)
	}
	if eng.TimesPreventedError < 1 || eng.TimesTriggered < 2 {
		t.Fatalf("engram telemetry = triggered:%d prevented:%d, want >=2 triggered and >=1 prevented",
			eng.TimesTriggered, eng.TimesPreventedError)
	}
}
