package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
