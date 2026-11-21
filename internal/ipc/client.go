package ipc

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	JSONRPCVersion = "2.0"

	PatternRepeatedToolError = "REPEATED_TOOL_ERROR"
	PatternCircularFileEdit  = "CIRCULAR_FILE_EDIT"
	PatternMultiStepCommand  = "MULTI_STEP_COMMAND_PATTERN"

	DefaultDialTimeout = 5 * time.Second
	DefaultCallTimeout = 90 * time.Second
)

// FrictionEvent matches the Section 5 Go <-> Python Evolution Compiler IPC contract.
type FrictionEvent struct {
	StepRange [2]int `json:"step_range"`
	Pattern   string `json:"pattern"`
	ToolName  string `json:"tool_name"`
	Summary   string `json:"summary"`
}

// SynthesizeParams is the params object for JSON-RPC method `compiler.synthesize`.
type SynthesizeParams struct {
	SessionID      string          `json:"session_id"`
	RepoRoot       string          `json:"repo_root"`
	BaseCommitSHA  string          `json:"base_commit_sha"`
	FrictionEvents []FrictionEvent `json:"friction_events"`
	RegressionCmd  string          `json:"regression_cmd,omitempty"`
}

// SynthesizeResult is the result object returned by `compiler.synthesize`.
type SynthesizeResult struct {
	EngramID         string  `json:"engram_id"`
	Kind             string  `json:"kind"`
	TargetTool       string  `json:"target_tool"`
	CommandRegex     string  `json:"command_regex"`
	FilePath         string  `json:"file_path"`
	ShadowVerified   bool    `json:"shadow_verified"`
	ShadowPassRate   float64 `json:"shadow_pass_rate"`
	Status           string  `json:"status"`
	FailureSignature string  `json:"failure_signature"`
	Explanation      string  `json:"explanation"`
}

// PingResult is the result object returned by `compiler.ping`.
type PingResult struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// RPCError represents a structured JSON-RPC 2.0 error returned by the compiler sidecar.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("ipc: rpc error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RepoHash computes the deterministic 12-hex-char repository hash matching server.py.
func RepoHash(repoRoot string) (string, error) {
	abs, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("ipc: resolve repo root %q: %w", repoRoot, err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	canonical := filepath.ToSlash(filepath.Clean(abs))
	if runtime.GOOS == "windows" {
		canonical = strings.ToLower(canonical)
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])[:12], nil
}

// SocketPathForRepo returns /tmp/engram-<repo_hash>.sock on POSIX and
// <temp>/engram-<repo_hash>.sock on Windows, matching server.py.
func SocketPathForRepo(repoRoot string) (string, error) {
	h, err := RepoHash(repoRoot)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), fmt.Sprintf("engram-%s.sock", h)), nil
	}
	return filepath.Join("/tmp", fmt.Sprintf("engram-%s.sock", h)), nil
}

// Client is a Unix Domain Socket JSON-RPC 2.0 client for the Python Evolution Compiler.
type Client struct {
	socketPath  string
	dialTimeout time.Duration
	callTimeout time.Duration
}

// NewClient creates a UDS JSON-RPC client targeting socketPath.
func NewClient(socketPath string, callTimeout time.Duration) *Client {
	if callTimeout <= 0 {
		callTimeout = DefaultCallTimeout
	}
	return &Client{
		socketPath:  socketPath,
		dialTimeout: DefaultDialTimeout,
		callTimeout: callTimeout,
	}
}

// SocketPath returns the Unix Domain Socket path this client connects to.
func (c *Client) SocketPath() string { return c.socketPath }

// Ping verifies the Python Evolution Compiler sidecar is reachable and responsive.
func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	var out PingResult
	if err := c.call(ctx, "compiler.ping", map[string]any{}, &out); err != nil {
		return PingResult{}, err
	}
	return out, nil
}

// Synthesize invokes `compiler.synthesize` over the Unix Domain Socket to analyze
// friction, synthesize an AST-validated engram, and run shadow worktree replay.
func (c *Client) Synthesize(ctx context.Context, params SynthesizeParams) (SynthesizeResult, error) {
	if strings.TrimSpace(params.SessionID) == "" {
		return SynthesizeResult{}, errors.New("ipc: session_id is required")
	}
	if strings.TrimSpace(params.RepoRoot) == "" {
		return SynthesizeResult{}, errors.New("ipc: repo_root is required")
	}

	var out SynthesizeResult
	if err := c.call(ctx, "compiler.synthesize", params, &out); err != nil {
		return SynthesizeResult{}, err
	}
	return out, nil
}

func (c *Client) call(ctx context.Context, method string, params any, resultDest any) error {
	if strings.TrimSpace(c.socketPath) == "" {
		return errors.New("ipc: socket path must not be empty")
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		callCtx, cancel = context.WithTimeout(ctx, c.callTimeout)
		defer cancel()
	}

	dialer := &net.Dialer{Timeout: c.dialTimeout}
	conn, err := dialer.DialContext(callCtx, "unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("ipc: dial unix socket %q: %w", c.socketPath, err)
	}
	defer conn.Close()

	if deadline, ok := callCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	reqID := newRequestID()
	payload, err := json.Marshal(rpcRequest{
		JSONRPC: JSONRPCVersion,
		ID:      reqID,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("ipc: marshal %s request: %w", method, err)
	}
	payload = append(payload, '\n')

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("ipc: write %s request: %w", method, err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("ipc: read %s response: %w", method, err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("ipc: decode %s response: %w", method, err)
	}
	if resp.ID != "" && resp.ID != reqID {
		return fmt.Errorf("ipc: mismatched response id %q (want %q)", resp.ID, reqID)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if resultDest != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, resultDest); err != nil {
			return fmt.Errorf("ipc: decode %s result: %w", method, err)
		}
	}
	return nil
}

// Sidecar manages a local Python Evolution Compiler background process.
type Sidecar struct {
	cmd        *exec.Cmd
	socketPath string
	client     *Client
}

// StartSidecar launches `python -m engram_compiler.server --socket <socketPath>`
// and waits until `compiler.ping` succeeds.
func StartSidecar(ctx context.Context, pythonBin, compilerDir, socketPath string) (*Sidecar, error) {
	if strings.TrimSpace(pythonBin) == "" {
		return nil, errors.New("ipc: pythonBin is required to start compiler sidecar")
	}
	if strings.TrimSpace(socketPath) == "" {
		return nil, errors.New("ipc: socketPath is required to start compiler sidecar")
	}

	cmd := exec.Command(pythonBin, "-m", "engram_compiler.server", "--socket", socketPath)
	env := append(os.Environ(), "PYTHONUNBUFFERED=1")
	if strings.TrimSpace(compilerDir) != "" {
		absDir, err := filepath.Abs(compilerDir)
		if err != nil {
			return nil, fmt.Errorf("ipc: resolve compilerDir: %w", err)
		}
		if existing := os.Getenv("PYTHONPATH"); existing != "" {
			env = append(env, "PYTHONPATH="+absDir+string(os.PathListSeparator)+existing)
		} else {
			env = append(env, "PYTHONPATH="+absDir)
		}
	}
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ipc: start compiler sidecar: %w", err)
	}

	sidecar := &Sidecar{
		cmd:        cmd,
		socketPath: socketPath,
		client:     NewClient(socketPath, DefaultCallTimeout),
	}

	// Poll compiler.ping until the UDS listener is ready or timeout expires.
	waitCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if _, err := sidecar.client.Ping(waitCtx); err == nil {
			return sidecar, nil
		} else {
			lastErr = err
		}

		select {
		case <-waitCtx.Done():
			_ = sidecar.Stop()
			return nil, fmt.Errorf("ipc: compiler sidecar did not become ready on %q: %v", socketPath, lastErr)
		case <-ticker.C:
		}
	}
}

// Client returns the JSON-RPC Client connected to this sidecar.
func (s *Sidecar) Client() *Client { return s.client }

// Stop terminates the background sidecar process and removes its socket file.
func (s *Sidecar) Stop() error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	_ = os.Remove(s.socketPath)
	return nil
}

func newRequestID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UTC().UnixNano())
	}
	return "req_" + hex.EncodeToString(b[:])
}
