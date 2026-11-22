package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"engram/internal/store"
	"engram/internal/worktree"
)

func TestUIServerHTTPRPCWebSocketDiffForkAndRuleInbox(t *testing.T) {
	ctx := context.Background()
	ws := initTestGitRepoForAgent(t)

	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	wtMgr, err := worktree.NewManager(ws.RepoRoot, ws.WorktreesDir())
	if err != nil {
		t.Fatalf("worktree.NewManager: %v", err)
	}

	// Create a real session worktree with 2 step commits for diff & fork tests.
	const sessID = "sess_ui_1"
	sessWT, err := wtMgr.Create(ctx, sessID, "")
	if err != nil {
		t.Fatalf("wtMgr.Create: %v", err)
	}
	t.Cleanup(func() { _ = wtMgr.Remove(ctx, sessWT.WorktreePath) })

	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "main.py"), []byte("print('step1')\n"), 0o644); err != nil {
		t.Fatalf("write step1 main.py: %v", err)
	}
	c1, err := wtMgr.CommitStep(ctx, sessWT.WorktreePath, 1, "step 1")
	if err != nil {
		t.Fatalf("CommitStep(1): %v", err)
	}

	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "main.py"), []byte("print('step2')\n"), 0o644); err != nil {
		t.Fatalf("write step2 main.py: %v", err)
	}
	c2, err := wtMgr.CommitStep(ctx, sessWT.WorktreePath, 2, "step 2")
	if err != nil {
		t.Fatalf("CommitStep(2): %v", err)
	}

	if err := st.CreateSession(ctx, store.Session{
		ID:            sessID,
		TaskPrompt:    "Upgrade main.py output",
		BaseCommitSHA: sessWT.BaseCommitSHA,
		WorktreePath:  sessWT.WorktreePath,
		Status:        store.SessionCompleted,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	zero := 0
	if err := st.CreateStep(ctx, store.Step{
		ID:           "st_1",
		SessionID:    sessID,
		StepIndex:    1,
		GitCommitSHA: c1.CommitSHA,
		ToolName:     "write_file",
		ExitCode:     &zero,
		TokensIn:     100,
		TokensOut:    20,
	}); err != nil {
		t.Fatalf("CreateStep(1): %v", err)
	}
	if err := st.CreateStep(ctx, store.Step{
		ID:           "st_2",
		SessionID:    sessID,
		StepIndex:    2,
		GitCommitSHA: c2.CommitSHA,
		ToolName:     "write_file",
		ExitCode:     &zero,
		TokensIn:     110,
		TokensOut:    25,
	}); err != nil {
		t.Fatalf("CreateStep(2): %v", err)
	}

	// Seed two engrams: one shadow-verified pending approval, one unverified (Invariant #4).
	if err := os.WriteFile(filepath.Join(ws.HooksDir(), "eng_verified.py"), []byte("import sys\nsys.exit(0)\n"), 0o644); err != nil {
		t.Fatalf("write eng_verified.py: %v", err)
	}
	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_verified",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/eng_verified.py",
		SourceSessionID:  sessID,
		FailureSignature: "sig_v1",
		Status:           store.EngramStatusPendingApproval,
		ShadowPassRate:   1.0,
	}); err != nil {
		t.Fatalf("CreateEngram(verified): %v", err)
	}
	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_unverified",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/eng_unverified.py",
		SourceSessionID:  sessID,
		FailureSignature: "sig_u1",
		Status:           store.EngramStatusShadowTesting,
		ShadowPassRate:   0.0,
	}); err != nil {
		t.Fatalf("CreateEngram(unverified): %v", err)
	}

	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html><body>Engram SPA</body></html>")},
	}
	uiSrv, err := NewUIServer(UIServerConfig{
		Workspace:   ws,
		Config:      DefaultConfig(),
		Store:       st,
		WorktreeMgr: wtMgr,
		StaticFS:    staticFS,
	})
	if err != nil {
		t.Fatalf("NewUIServer: %v", err)
	}

	ts := httptest.NewServer(uiSrv.Handler())
	t.Cleanup(ts.Close)

	// 1. Embedded SPA static serving.
	getResp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	htmlBytes, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || !strings.Contains(string(htmlBytes), "Engram SPA") {
		t.Fatalf("GET / = %d %q", getResp.StatusCode, string(htmlBytes))
	}

	// Helper for HTTP POST /api/rpc.
	callHTTPRPC := func(method string, params any) uiRPCResponse {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  method,
			"params":  params,
		})
		resp, err := ts.Client().Post(ts.URL+"/api/rpc", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("POST /api/rpc %s: %v", method, err)
		}
		defer resp.Body.Close()
		var parsed uiRPCResponse
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			t.Fatalf("decode RPC %s: %v", method, err)
		}
		return parsed
	}

	// 2. Step-by-step Git diff inspector (step 2 vs step 1).
	diffResp := callHTTPRPC("steps.diff", map[string]any{"session_id": sessID, "step_index": 2})
	if diffResp.Error != nil {
		t.Fatalf("steps.diff error = %+v", diffResp.Error)
	}
	diffMap := diffResp.Result.(map[string]any)
	diffStr := diffMap["diff"].(string)
	if !strings.Contains(diffStr, "-print('step1')") || !strings.Contains(diffStr, "+print('step2')") {
		t.Fatalf("unexpected step diff:\n%s", diffStr)
	}

	// 3. Time-travel fork at step 1 creates a new isolated detached worktree at step 1 SHA.
	forkResp := callHTTPRPC("sessions.fork", map[string]any{"session_id": sessID, "step_index": 1})
	if forkResp.Error != nil {
		t.Fatalf("sessions.fork error = %+v", forkResp.Error)
	}
	forkMap := forkResp.Result.(map[string]any)
	forkWTPath := forkMap["worktree_path"].(string)
	t.Cleanup(func() { _ = wtMgr.Remove(ctx, forkWTPath) })

	forkMain, err := os.ReadFile(filepath.Join(forkWTPath, "main.py"))
	if err != nil {
		t.Fatalf("read forked worktree main.py: %v", err)
	}
	if string(forkMain) != "print('step1')\n" {
		t.Fatalf("forked main.py = %q, want print('step1')", string(forkMain))
	}

	// 4. Rule Approval Inbox: Invariant #4 blocks unverified hook, approves verified hook.
	unverifiedResp := callHTTPRPC("engrams.approve", map[string]any{"engram_id": "eng_unverified"})
	if unverifiedResp.Error == nil {
		t.Fatalf("expected Invariant #4 error approving unverified hook")
	}

	approveResp := callHTTPRPC("engrams.approve", map[string]any{"engram_id": "eng_verified"})
	if approveResp.Error != nil {
		t.Fatalf("engrams.approve(verified) error = %+v", approveResp.Error)
	}
	eng, err := st.GetEngram(ctx, "eng_verified")
	if err != nil || eng.Status != store.EngramStatusActive {
		t.Fatalf("expected eng_verified active, got %+v err=%v", eng, err)
	}

	// 5. Real RFC 6455 WebSocket JSON-RPC round-trip on /ws.
	wsAddr := strings.TrimPrefix(ts.URL, "http://")
	wsReply := callTestWebSocketRPC(t, wsAddr, `{"jsonrpc":"2.0","id":"ws1","method":"sessions.trace","params":{"session_id":"sess_ui_1"}}`)
	if !strings.Contains(wsReply, `"id":"ws1"`) || !strings.Contains(wsReply, `"st_2"`) {
		t.Fatalf("unexpected WebSocket JSON-RPC reply: %s", wsReply)
	}
}

func callTestWebSocketRPC(t *testing.T, addr, payload string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write ws upgrade: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("ws upgrade status = %q, err = %v", statusLine, err)
	}

	var acceptHeader string
	for {
		ln, err := br.ReadString('\n')
		if err != nil || ln == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(ln), "sec-websocket-accept:") {
			acceptHeader = strings.TrimSpace(strings.SplitN(ln, ":", 2)[1])
		}
	}
	if acceptHeader != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("Sec-WebSocket-Accept = %q, want RFC 6455 vector %q", acceptHeader, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	}

	// Send masked RFC 6455 text frame.
	data := []byte(payload)
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	frame := []byte{0x81}
	if len(data) < 126 {
		frame = append(frame, 0x80|byte(len(data)))
	} else {
		frame = append(frame, 0x80|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(data)))
		frame = append(frame, ext[:]...)
	}
	frame = append(frame, mask[:]...)
	masked := make([]byte, len(data))
	for i := range data {
		masked[i] = data[i] ^ mask[i%4]
	}
	frame = append(frame, masked...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	opcode, reply, err := readWSMessage(br)
	if err != nil || opcode != 0x1 {
		t.Fatalf("readWSMessage opcode=%d err=%v", opcode, err)
	}
	return string(reply)
}
