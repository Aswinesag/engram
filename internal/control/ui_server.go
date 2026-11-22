package control

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"engram/internal/store"
	"engram/internal/worktree"
)

const (
	wsMagicGUID        = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxRPCMessageBytes = 4 << 20 // 4 MiB
)

// UIServerConfig wires the local Observability & Time-Travel UI server.
type UIServerConfig struct {
	Workspace   Workspace
	Config      Config
	Store       *store.Store
	WorktreeMgr *worktree.Manager
	StaticFS    fs.FS
}

// UIServer serves the embedded React/TypeScript SPA alongside HTTP and RFC 6455
// WebSocket JSON-RPC 2.0 endpoints for DAG visualization, Git diffs, time-travel
// rewind/forking, and the Rule Approval Inbox.
type UIServer struct {
	ws       Workspace
	cfg      Config
	store    *store.Store
	wtMgr    *worktree.Manager
	staticFS fs.FS
	mux      *http.ServeMux
}

// NewUIServer validates dependencies and constructs a ready-to-serve UIServer.
func NewUIServer(cfg UIServerConfig) (*UIServer, error) {
	if strings.TrimSpace(cfg.Workspace.RepoRoot) == "" {
		return nil, errors.New("control: UIServer requires Workspace.RepoRoot")
	}
	if cfg.Store == nil {
		return nil, errors.New("control: UIServer requires Store")
	}
	if cfg.WorktreeMgr == nil {
		mgr, err := worktree.NewManager(cfg.Workspace.RepoRoot, cfg.Workspace.WorktreesDir())
		if err != nil {
			return nil, err
		}
		cfg.WorktreeMgr = mgr
	}

	s := &UIServer{
		ws:       cfg.Workspace,
		cfg:      cfg.Config,
		store:    cfg.Store,
		wtMgr:    cfg.WorktreeMgr,
		staticFS: cfg.StaticFS,
		mux:      http.NewServeMux(),
	}

	s.mux.HandleFunc("/ws", s.handleWebSocket)
	s.mux.HandleFunc("/api/rpc", s.handleHTTPRPC)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	s.mux.HandleFunc("/", s.handleStaticSPA)

	return s, nil
}

// Handler returns the http.Handler serving the UI and JSON-RPC/WebSocket endpoints.
func (s *UIServer) Handler() http.Handler {
	return s.mux
}

// ApproveEngram promotes a shadow-verified engram to active status in SQLite
// (enforcing Invariant #4) and synchronizes .engram/manifest.json.
func ApproveEngram(ctx context.Context, ws Workspace, st *store.Store, engramID string) (store.Engram, error) {
	if err := st.UpdateEngramStatus(ctx, engramID, store.EngramStatusActive, nil); err != nil {
		return store.Engram{}, err
	}
	eng, err := st.GetEngram(ctx, engramID)
	if err != nil {
		return store.Engram{}, err
	}
	if err := syncEngramInManifest(ws, eng); err != nil {
		return eng, err
	}
	return eng, nil
}

// RejectEngram transitions an engram to rejected status in SQLite and manifest.json.
func RejectEngram(ctx context.Context, ws Workspace, st *store.Store, engramID string) (store.Engram, error) {
	if err := st.UpdateEngramStatus(ctx, engramID, store.EngramStatusRejected, nil); err != nil {
		return store.Engram{}, err
	}
	eng, err := st.GetEngram(ctx, engramID)
	if err != nil {
		return store.Engram{}, err
	}
	if err := syncEngramInManifest(ws, eng); err != nil {
		return eng, err
	}
	return eng, nil
}

// ReadEngramSource safely loads the human-auditable Python or Markdown source
// for an engram strictly within .engram/ (Invariant #3).
func ReadEngramSource(ws Workspace, relPath string) (string, error) {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return "", errors.New("control: empty engram file path")
	}
	cleaned := filepath.Clean(filepath.FromSlash(relPath))
	if filepath.IsAbs(cleaned) {
		return "", errors.New("control: absolute engram file path not allowed")
	}

	var candidate string
	if strings.HasPrefix(cleaned, EngramDirName+string(filepath.Separator)) {
		candidate = filepath.Join(ws.RepoRoot, cleaned)
	} else {
		candidate = filepath.Join(ws.EngramDir(), cleaned)
	}

	absEngram, err := filepath.Abs(ws.EngramDir())
	if err != nil {
		return "", err
	}
	absCand, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absEngram, absCand)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("control: engram source path escapes .engram directory")
	}

	data, err := os.ReadFile(absCand)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --- JSON-RPC 2.0 Dispatcher ---

type uiRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type uiRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type uiRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *uiRPCError     `json:"error,omitempty"`
}

// HandleRPC processes a single JSON-RPC 2.0 payload (shared by HTTP and WebSocket).
func (s *UIServer) HandleRPC(ctx context.Context, raw []byte) []byte {
	var req uiRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return marshalRPCResponse(uiRPCResponse{
			JSONRPC: "2.0",
			Error:   &uiRPCError{Code: -32700, Message: "parse error: " + err.Error()},
		})
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		return marshalRPCResponse(uiRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &uiRPCError{Code: -32600, Message: "invalid JSON-RPC 2.0 request"},
		})
	}

	res, rpcErr := s.dispatchMethod(ctx, req.Method, req.Params)
	if rpcErr != nil {
		return marshalRPCResponse(uiRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   rpcErr,
		})
	}
	return marshalRPCResponse(uiRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  res,
	})
}

func (s *UIServer) dispatchMethod(ctx context.Context, method string, rawParams json.RawMessage) (any, *uiRPCError) {
	switch method {
	case "workspace.info":
		return s.rpcWorkspaceInfo(ctx)
	case "sessions.list":
		return s.rpcSessionsList(ctx, rawParams)
	case "sessions.trace":
		return s.rpcSessionsTrace(ctx, rawParams)
	case "steps.diff":
		return s.rpcStepsDiff(ctx, rawParams)
	case "steps.artifact":
		return s.rpcStepsArtifact(ctx, rawParams)
	case "sessions.rewind":
		return s.rpcSessionsRewind(ctx, rawParams)
	case "sessions.fork":
		return s.rpcSessionsFork(ctx, rawParams)
	case "engrams.list":
		return s.rpcEngramsList(ctx, rawParams)
	case "engrams.approve":
		return s.rpcEngramsApprove(ctx, rawParams)
	case "engrams.reject":
		return s.rpcEngramsReject(ctx, rawParams)
	default:
		return nil, &uiRPCError{Code: -32601, Message: "method not found: " + method}
	}
}

func (s *UIServer) rpcWorkspaceInfo(ctx context.Context) (any, *uiRPCError) {
	active, err := s.store.ListEngrams(ctx, store.EngramFilter{Status: store.EngramStatusActive})
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	pending, err := s.store.ListEngrams(ctx, store.EngramFilter{Status: store.EngramStatusPendingApproval})
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	sessions, err := s.store.ListSessions(ctx, 1000)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	return map[string]any{
		"repo_root":             s.ws.RepoRoot,
		"model_provider":        s.cfg.Model.Provider,
		"model_name":            s.cfg.Model.Model,
		"sandbox_mode":          s.cfg.Sandbox.Mode,
		"redact_secrets":        s.cfg.Sandbox.RedactSecrets,
		"allowed_domains":       s.cfg.Sandbox.AllowedDomains,
		"active_engram_count":   len(active),
		"pending_engram_count":  len(pending),
		"session_count":         len(sessions),
		"artifact_token_budget": s.cfg.Context.ArtifactTokenThreshold,
	}, nil
}

func (s *UIServer) rpcSessionsList(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		Limit int `json:"limit"`
	}
	if len(rawParams) > 0 {
		_ = json.Unmarshal(rawParams, &params)
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	sessions, err := s.store.ListSessions(ctx, params.Limit)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	type sessionSummary struct {
		ID            string              `json:"id"`
		TaskPrompt    string              `json:"task_prompt"`
		BaseCommitSHA string              `json:"base_commit_sha"`
		HeadCommitSHA string              `json:"head_commit_sha"`
		WorktreePath  string              `json:"worktree_path"`
		Status        store.SessionStatus `json:"status"`
		StepCount     int                 `json:"step_count"`
		ErrorCount    int                 `json:"error_count"`
		TokensIn      int64               `json:"tokens_in"`
		TokensOut     int64               `json:"tokens_out"`
		DurationMS    int64               `json:"duration_ms"`
		CreatedAt     string              `json:"created_at"`
	}

	out := make([]sessionSummary, 0, len(sessions))
	for _, sess := range sessions {
		steps, err := s.store.ListStepsBySession(ctx, sess.ID)
		if err != nil {
			return nil, &uiRPCError{Code: -32603, Message: err.Error()}
		}
		headSHA := sess.BaseCommitSHA
		var tokensIn, tokensOut, durMS int64
		errCount := 0
		for _, st := range steps {
			headSHA = st.GitCommitSHA
			tokensIn += st.TokensIn
			tokensOut += st.TokensOut
			durMS += st.DurationMS
			if st.ExitCode != nil && *st.ExitCode != 0 {
				errCount++
			}
		}
		out = append(out, sessionSummary{
			ID:            sess.ID,
			TaskPrompt:    sess.TaskPrompt,
			BaseCommitSHA: sess.BaseCommitSHA,
			HeadCommitSHA: headSHA,
			WorktreePath:  sess.WorktreePath,
			Status:        sess.Status,
			StepCount:     len(steps),
			ErrorCount:    errCount,
			TokensIn:      tokensIn,
			TokensOut:     tokensOut,
			DurationMS:    durMS,
			CreatedAt:     sess.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	return map[string]any{"sessions": out}, nil
}

func (s *UIServer) rpcSessionsTrace(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.SessionID) == "" {
		return nil, &uiRPCError{Code: -32602, Message: "params.session_id is required"}
	}

	sess, err := s.store.GetSession(ctx, params.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "session not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	steps, err := s.store.ListStepsBySession(ctx, sess.ID)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	type dagEdge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	type stepDTO struct {
		ID                string `json:"id"`
		SessionID         string `json:"session_id"`
		StepIndex         int    `json:"step_index"`
		GitCommitSHA      string `json:"git_commit_sha"`
		ParentCommitSHA   string `json:"parent_commit_sha"`
		Thought           string `json:"thought"`
		ToolName          string `json:"tool_name"`
		ToolInputJSON     string `json:"tool_input_json"`
		ToolOutputSummary string `json:"tool_output_summary"`
		RawArtifactPath   string `json:"raw_artifact_path"`
		ExitCode          *int   `json:"exit_code"`
		DurationMS        int64  `json:"duration_ms"`
		TokensIn          int64  `json:"tokens_in"`
		TokensOut         int64  `json:"tokens_out"`
		CreatedAt         string `json:"created_at"`
	}

	stepDTOs := make([]stepDTO, 0, len(steps))
	edges := make([]dagEdge, 0, len(steps))
	prevSHA := sess.BaseCommitSHA
	prevNode := "base"

	for _, st := range steps {
		stepDTOs = append(stepDTOs, stepDTO{
			ID:                st.ID,
			SessionID:         st.SessionID,
			StepIndex:         st.StepIndex,
			GitCommitSHA:      st.GitCommitSHA,
			ParentCommitSHA:   prevSHA,
			Thought:           st.Thought,
			ToolName:          st.ToolName,
			ToolInputJSON:     st.ToolInputJSON,
			ToolOutputSummary: st.ToolOutputSummary,
			RawArtifactPath:   st.RawArtifactPath,
			ExitCode:          st.ExitCode,
			DurationMS:        st.DurationMS,
			TokensIn:          st.TokensIn,
			TokensOut:         st.TokensOut,
			CreatedAt:         st.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
		edges = append(edges, dagEdge{From: prevNode, To: st.ID})
		prevSHA = st.GitCommitSHA
		prevNode = st.ID
	}

	return map[string]any{
		"session": map[string]any{
			"id":              sess.ID,
			"task_prompt":     sess.TaskPrompt,
			"base_commit_sha": sess.BaseCommitSHA,
			"worktree_path":   sess.WorktreePath,
			"status":          sess.Status,
			"created_at":      sess.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		"steps": stepDTOs,
		"edges": edges,
	}, nil
}

func (s *UIServer) rpcStepsDiff(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		SessionID string `json:"session_id"`
		StepIndex int    `json:"step_index"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.SessionID) == "" || params.StepIndex <= 0 {
		return nil, &uiRPCError{Code: -32602, Message: "params.session_id and params.step_index (> 0) are required"}
	}

	sess, err := s.store.GetSession(ctx, params.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "session not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	targetStep, err := s.store.GetStepByIndex(ctx, sess.ID, params.StepIndex)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "step not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	fromSHA := sess.BaseCommitSHA
	if params.StepIndex > 1 {
		if prev, prevErr := s.store.GetStepByIndex(ctx, sess.ID, params.StepIndex-1); prevErr == nil {
			fromSHA = prev.GitCommitSHA
		}
	}

	diffText := ""
	if fromSHA != targetStep.GitCommitSHA {
		diffText, err = s.wtMgr.Diff(ctx, sess.WorktreePath, fromSHA, targetStep.GitCommitSHA)
		if err != nil {
			return nil, &uiRPCError{Code: -32603, Message: err.Error()}
		}
	}

	return map[string]any{
		"session_id": sess.ID,
		"step_index": targetStep.StepIndex,
		"from_sha":   fromSHA,
		"to_sha":     targetStep.GitCommitSHA,
		"diff":       diffText,
	}, nil
}

func (s *UIServer) rpcStepsArtifact(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		SessionID string `json:"session_id"`
		StepIndex int    `json:"step_index"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.SessionID) == "" || params.StepIndex <= 0 {
		return nil, &uiRPCError{Code: -32602, Message: "params.session_id and params.step_index (> 0) are required"}
	}

	step, err := s.store.GetStepByIndex(ctx, params.SessionID, params.StepIndex)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "step not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	if strings.TrimSpace(step.RawArtifactPath) == "" {
		return map[string]any{"path": "", "content": ""}, nil
	}

	absArtifacts, err := filepath.Abs(s.ws.ArtifactsDir())
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	absTarget, err := filepath.Abs(step.RawArtifactPath)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	rel, err := filepath.Rel(absArtifacts, absTarget)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, &uiRPCError{Code: -32003, Message: "artifact path escapes .engram/.runtime/artifacts"}
	}

	raw, err := os.ReadFile(absTarget)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}
	return map[string]any{
		"path":    filepath.ToSlash(absTarget),
		"content": string(raw),
	}, nil
}

func (s *UIServer) rpcSessionsRewind(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		SessionID string `json:"session_id"`
		StepIndex int    `json:"step_index"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.SessionID) == "" || params.StepIndex <= 0 {
		return nil, &uiRPCError{Code: -32602, Message: "params.session_id and params.step_index (> 0) are required"}
	}

	sess, err := s.store.GetSession(ctx, params.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "session not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	step, err := s.store.GetStepByIndex(ctx, sess.ID, params.StepIndex)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "step not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	if err := s.wtMgr.Rewind(ctx, sess.WorktreePath, step.GitCommitSHA); err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	return map[string]any{
		"session_id":     sess.ID,
		"step_index":     step.StepIndex,
		"git_commit_sha": step.GitCommitSHA,
		"worktree_path":  sess.WorktreePath,
	}, nil
}

func (s *UIServer) rpcSessionsFork(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		SessionID  string `json:"session_id"`
		StepIndex  int    `json:"step_index"`
		TaskPrompt string `json:"task_prompt"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.SessionID) == "" || params.StepIndex <= 0 {
		return nil, &uiRPCError{Code: -32602, Message: "params.session_id and params.step_index (> 0) are required"}
	}

	origSess, err := s.store.GetSession(ctx, params.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "session not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	targetStep, err := s.store.GetStepByIndex(ctx, origSess.ID, params.StepIndex)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "step not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	forkID := newID("sess")
	forkWT, err := s.wtMgr.Create(ctx, forkID, targetStep.GitCommitSHA)
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	prompt := strings.TrimSpace(params.TaskPrompt)
	if prompt == "" {
		prompt = fmt.Sprintf("[fork of %s@step-%d] %s", origSess.ID, targetStep.StepIndex, origSess.TaskPrompt)
	}

	forkSess := store.Session{
		ID:            forkID,
		TaskPrompt:    prompt,
		BaseCommitSHA: forkWT.BaseCommitSHA,
		WorktreePath:  forkWT.WorktreePath,
		Status:        store.SessionRunning,
	}
	if err := s.store.CreateSession(ctx, forkSess); err != nil {
		_ = s.wtMgr.Remove(ctx, forkWT.WorktreePath)
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	return map[string]any{
		"forked_session_id": forkSess.ID,
		"source_session_id": origSess.ID,
		"source_step_index": targetStep.StepIndex,
		"base_commit_sha":   forkSess.BaseCommitSHA,
		"worktree_path":     forkSess.WorktreePath,
		"task_prompt":       forkSess.TaskPrompt,
	}, nil
}

func (s *UIServer) rpcEngramsList(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		Status string `json:"status"`
		Kind   string `json:"kind"`
	}
	if len(rawParams) > 0 {
		_ = json.Unmarshal(rawParams, &params)
	}

	engrams, err := s.store.ListEngrams(ctx, store.EngramFilter{
		Status: store.EngramStatus(strings.TrimSpace(params.Status)),
		Kind:   store.EngramKind(strings.TrimSpace(params.Kind)),
	})
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	type engramDTO struct {
		ID                  string             `json:"id"`
		Kind                store.EngramKind   `json:"kind"`
		TriggerPattern      string             `json:"trigger_pattern"`
		FilePath            string             `json:"file_path"`
		SourceSessionID     string             `json:"source_session_id"`
		FailureSignature    string             `json:"failure_signature"`
		Status              store.EngramStatus `json:"status"`
		ShadowPassRate      float64            `json:"shadow_pass_rate"`
		TimesTriggered      int64              `json:"times_triggered"`
		TimesPreventedError int64              `json:"times_prevented_error"`
		SourceCode          string             `json:"source_code"`
		CreatedAt           string             `json:"created_at"`
	}

	out := make([]engramDTO, 0, len(engrams))
	for _, e := range engrams {
		src, _ := ReadEngramSource(s.ws, e.FilePath)
		out = append(out, engramDTO{
			ID:                  e.ID,
			Kind:                e.Kind,
			TriggerPattern:      e.TriggerPattern,
			FilePath:            e.FilePath,
			SourceSessionID:     e.SourceSessionID,
			FailureSignature:    e.FailureSignature,
			Status:              e.Status,
			ShadowPassRate:      e.ShadowPassRate,
			TimesTriggered:      e.TimesTriggered,
			TimesPreventedError: e.TimesPreventedError,
			SourceCode:          src,
			CreatedAt:           e.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}
	return map[string]any{"engrams": out}, nil
}

func (s *UIServer) rpcEngramsApprove(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		EngramID string `json:"engram_id"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.EngramID) == "" {
		return nil, &uiRPCError{Code: -32602, Message: "params.engram_id is required"}
	}

	eng, err := ApproveEngram(ctx, s.ws, s.store, params.EngramID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "engram not found"}
	}
	if errors.Is(err, store.ErrShadowVerificationRequired) {
		return nil, &uiRPCError{Code: -32001, Message: err.Error()}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	return map[string]any{
		"id":               eng.ID,
		"status":           eng.Status,
		"shadow_pass_rate": eng.ShadowPassRate,
	}, nil
}

func (s *UIServer) rpcEngramsReject(ctx context.Context, rawParams json.RawMessage) (any, *uiRPCError) {
	var params struct {
		EngramID string `json:"engram_id"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil || strings.TrimSpace(params.EngramID) == "" {
		return nil, &uiRPCError{Code: -32602, Message: "params.engram_id is required"}
	}

	eng, err := RejectEngram(ctx, s.ws, s.store, params.EngramID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &uiRPCError{Code: -32004, Message: "engram not found"}
	}
	if err != nil {
		return nil, &uiRPCError{Code: -32603, Message: err.Error()}
	}

	return map[string]any{
		"id":     eng.ID,
		"status": eng.Status,
	}, nil
}

func syncEngramInManifest(ws Workspace, e store.Engram) error {
	manifest := DefaultManifest()
	if data, err := os.ReadFile(ws.ManifestPath()); err == nil {
		_ = json.Unmarshal(data, &manifest)
	}

	filePath := filepath.ToSlash(e.FilePath)
	if !strings.HasPrefix(filePath, ".engram/") {
		filePath = ".engram/" + strings.TrimPrefix(filePath, "/")
	}

	upsert := func(entries []ManifestEntry) []ManifestEntry {
		for i := range entries {
			if entries[i].ID == e.ID {
				entries[i].Status = e.Status
				entries[i].ShadowPassRate = e.ShadowPassRate
				entries[i].TriggerPattern = e.TriggerPattern
				entries[i].FilePath = filePath
				return entries
			}
		}
		return append(entries, ManifestEntry{
			ID:             e.ID,
			Kind:           e.Kind,
			TriggerPattern: e.TriggerPattern,
			FilePath:       filePath,
			Status:         e.Status,
			ShadowPassRate: e.ShadowPassRate,
		})
	}

	switch e.Kind {
	case store.EngramKindHook:
		manifest.Hooks = upsert(manifest.Hooks)
	case store.EngramKindTool:
		manifest.Tools = upsert(manifest.Tools)
	case store.EngramKindRule:
		manifest.Rules = upsert(manifest.Rules)
	}
	return SaveManifest(ws, manifest)
}

// --- HTTP Handlers & Embedded SPA ---

func (s *UIServer) handleHTTPRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRPCMessageBytes+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxRPCMessageBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	respBytes := s.HandleRPC(r.Context(), body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *UIServer) handleStaticSPA(w http.ResponseWriter, r *http.Request) {
	if s.staticFS == nil {
		http.NotFound(w, r)
		return
	}
	reqPath := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if reqPath == "" {
		reqPath = "index.html"
	}

	if _, err := fs.Stat(s.staticFS, reqPath); err == nil {
		http.FileServer(http.FS(s.staticFS)).ServeHTTP(w, r)
		return
	}

	// SPA client-side route fallback to index.html.
	indexBytes, err := fs.ReadFile(s.staticFS, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexBytes)
}

// --- Zero-Dependency RFC 6455 WebSocket JSON-RPC Server ---

func (s *UIServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected WebSocket upgrade", http.StatusUpgradeRequired)
		return
	}
	wsKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if wsKey == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	acceptHash := sha1.Sum([]byte(wsKey + wsMagicGUID))
	acceptKey := base64.StdEncoding.EncodeToString(acceptHash[:])
	handshake := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"
	if _, err := io.WriteString(conn, handshake); err != nil {
		return
	}

	var writeMu sync.Mutex
	writeFrame := func(opcode byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeWSFrame(conn, opcode, payload)
	}

	reader := bufRW.Reader
	for {
		opcode, payload, err := readWSMessage(reader)
		if err != nil {
			return
		}
		switch opcode {
		case 0x8: // Close
			_ = writeFrame(0x8, nil)
			return
		case 0x9: // Ping
			if err := writeFrame(0xA, payload); err != nil {
				return
			}
		case 0xA: // Pong
			continue
		case 0x1, 0x2: // Text / Binary JSON-RPC frame
			respBytes := s.HandleRPC(context.Background(), payload)
			if err := writeFrame(0x1, respBytes); err != nil {
				return
			}
		}
	}
}

func readWSMessage(r *bufio.Reader) (byte, []byte, error) {
	var (
		msgOpcode byte
		assembled []byte
	)
	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return 0, nil, err
		}
		fin := (hdr[0] & 0x80) != 0
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		switch payloadLen {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(r, ext); err != nil {
				return 0, nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(r, ext); err != nil {
				return 0, nil, err
			}
			payloadLen = binary.BigEndian.Uint64(ext)
		}

		if payloadLen > maxRPCMessageBytes || uint64(len(assembled))+payloadLen > maxRPCMessageBytes {
			return 0, nil, errors.New("websocket frame exceeds max RPC size")
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		frameData := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, frameData); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range frameData {
				frameData[i] ^= maskKey[i%4]
			}
		}

		// Control frames (Close/Ping/Pong) are never fragmented.
		if opcode >= 0x8 {
			return opcode, frameData, nil
		}
		if opcode != 0x0 {
			msgOpcode = opcode
		}
		assembled = append(assembled, frameData...)
		if fin {
			return msgOpcode, assembled, nil
		}
	}
}

func writeWSFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | (opcode & 0x0F)}
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, ext[:]...)
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func marshalRPCResponse(resp uiRPCResponse) []byte {
	b, _ := json.Marshal(resp)
	return b
}
