package mcp

import (
	"context"
	"encoding/json"
	"engram/internal/sandbox"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHostBuiltinToolsScopedToWorktree(t *testing.T) {
	ctx := context.Background()
	wtDir := t.TempDir()

	host, err := NewHost(ctx, wtDir)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	tools := host.Tools()
	if len(tools) != 4 {
		t.Fatalf("Tools() count = %d, want 4 (%+v)", len(tools), tools)
	}

	// write_file inside worktree.
	writeRes, err := host.CallTool(ctx, "write_file", json.RawMessage(`{"path":"src/hello.txt","content":"hello engram\n"}`))
	if err != nil {
		t.Fatalf("CallTool(write_file) error = %v", err)
	}
	if writeRes.IsError || !writeRes.MutatesFiles || writeRes.ExitCode != 0 {
		t.Fatalf("write_file result = %+v, want success + MutatesFiles=true", writeRes)
	}

	// read_file inside worktree.
	readRes, err := host.CallTool(ctx, "read_file", json.RawMessage(`{"path":"src/hello.txt"}`))
	if err != nil {
		t.Fatalf("CallTool(read_file) error = %v", err)
	}
	if readRes.IsError || readRes.MutatesFiles || readRes.Output != "hello engram\n" {
		t.Fatalf("read_file result = %+v", readRes)
	}

	// list_files inside worktree.
	listRes, err := host.CallTool(ctx, "list_files", json.RawMessage(`{"path":"src"}`))
	if err != nil {
		t.Fatalf("CallTool(list_files) error = %v", err)
	}
	if listRes.IsError || listRes.MutatesFiles || !strings.Contains(listRes.Output, "hello.txt") {
		t.Fatalf("list_files result = %+v", listRes)
	}

	// bash success.
	bashOK, err := host.CallTool(ctx, "bash", json.RawMessage(`{"command":"echo engram_ok"}`))
	if err != nil {
		t.Fatalf("CallTool(bash ok) error = %v", err)
	}
	if bashOK.IsError || bashOK.ExitCode != 0 || !strings.Contains(bashOK.Output, "engram_ok") {
		t.Fatalf("bash ok result = %+v", bashOK)
	}

	// bash non-zero exit code propagation.
	failCmd := `{"command":"exit 7"}`
	bashFail, err := host.CallTool(ctx, "bash", json.RawMessage(failCmd))
	if err != nil {
		t.Fatalf("CallTool(bash fail) error = %v", err)
	}
	if !bashFail.IsError || bashFail.ExitCode != 7 {
		t.Fatalf("bash fail result = %+v, want IsError=true and ExitCode=7", bashFail)
	}
}

func TestHostRejectsWorktreePathEscape(t *testing.T) {
	ctx := context.Background()
	parentDir := t.TempDir()
	wtDir := filepath.Join(parentDir, "wt")
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatalf("mkdir wt: %v", err)
	}
	outsideFile := filepath.Join(parentDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("top-secret\n"), 0o644); err != nil {
		t.Fatalf("write secret.txt: %v", err)
	}

	host, err := NewHost(ctx, wtDir)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	readEscape, err := host.CallTool(ctx, "read_file", json.RawMessage(`{"path":"../secret.txt"}`))
	if err != nil {
		t.Fatalf("CallTool(read_file escape) unexpected transport error = %v", err)
	}
	if !readEscape.IsError || !strings.Contains(readEscape.Output, "escapes isolated worktree") {
		t.Fatalf("expected path escape rejection, got %+v", readEscape)
	}

	writeEscape, err := host.CallTool(ctx, "write_file", json.RawMessage(`{"path":"../pwned.txt","content":"bad"}`))
	if err != nil {
		t.Fatalf("CallTool(write_file escape) unexpected transport error = %v", err)
	}
	if !writeEscape.IsError {
		t.Fatalf("expected write_file escape rejection, got %+v", writeEscape)
	}
	if _, err := os.Stat(filepath.Join(parentDir, "pwned.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pwned.txt was created outside worktree!")
	}
}

func TestHostMountSynthesizedPythonStdioMCPTool(t *testing.T) {
	pyBin, err := findTestPython()
	if err != nil {
		t.Skipf("skipping stdio python MCP test: %v", err)
	}

	ctx := context.Background()
	wtDir := t.TempDir()
	toolsDir := filepath.Join(t.TempDir(), ".engram", "tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatalf("mkdir toolsDir: %v", err)
	}

	// Minimal zero-dependency MCP JSON-RPC 2.0 server over stdio.
	mcpScript := `import json, os, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    msg_id = msg.get("id")
    method = msg.get("method")
    if msg_id is None:
        continue
    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "eng_01J9Y_safe_migrate", "version": "1.0.0"},
            },
        }
    elif method == "tools/list":
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "safe_migrate",
                        "description": "Run deterministic DB migration in worktree",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        },
                    }
                ]
            },
        }
    elif method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        wt = os.environ.get("ENGRAM_WORKTREE_PATH", "")
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": f"migrated:{args.get('target')}:{os.path.basename(wt)}"}],
                "isError": False,
            },
        }
    else:
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"unknown method {method}"},
        }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
`
	toolPath := filepath.Join(toolsDir, "eng_01J9Y_safe_migrate.py")
	if err := os.WriteFile(toolPath, []byte(mcpScript), 0o644); err != nil {
		t.Fatalf("write synthesized MCP tool: %v", err)
	}

	host, err := NewHost(ctx, wtDir)
	if err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	// Verify path traversal outside .engram/tools/ is rejected.
	if err := host.MountSynthesizedTool(ctx, pyBin, toolsDir, "eng_bad", "../evil.py"); !errors.Is(err, ErrUnsafeToolPath) {
		t.Fatalf("MountSynthesizedTool(../evil.py) err = %v, want ErrUnsafeToolPath", err)
	}

	// Mount valid synthesized MCP tool.
	if err := host.MountSynthesizedTool(ctx, pyBin, toolsDir, "eng_01J9Y", "tools/eng_01J9Y_safe_migrate.py"); err != nil {
		t.Fatalf("MountSynthesizedTool() error = %v", err)
	}

	res, err := host.CallTool(ctx, "safe_migrate", json.RawMessage(`{"target":"head"}`))
	if err != nil {
		t.Fatalf("CallTool(safe_migrate) error = %v", err)
	}
	want := "migrated:head:" + filepath.Base(wtDir)
	if res.IsError || res.Output != want || res.ServerName != "eng_01J9Y" {
		t.Fatalf("safe_migrate result = %+v, want Output=%q ServerName=eng_01J9Y", res, want)
	}
}

func findTestPython() (string, error) {
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3"}
	}
	for _, name := range candidates {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(p), `\microsoft\windowsapps\`) {
			continue
		}
		return p, nil
	}
	return "", errors.New("python not found")
}

type stubSandboxRunner struct {
	lastReq sandbox.ExecRequest
	result  sandbox.ExecResult
}

func (s *stubSandboxRunner) Backend() string { return "stub-sandbox" }

func (s *stubSandboxRunner) Run(_ context.Context, req sandbox.ExecRequest) (sandbox.ExecResult, error) {
	s.lastReq = req
	return s.result, nil
}

func TestHostBashUsesInjectedSandboxRunner(t *testing.T) {
	ctx := context.Background()
	wtDir := t.TempDir()

	stub := &stubSandboxRunner{
		result: sandbox.ExecResult{
			Output:   "sandboxed-output",
			ExitCode: 0,
			Backend:  "stub-sandbox",
		},
	}

	host, err := NewHostWithOptions(ctx, wtDir, HostOptions{CommandRunner: stub})
	if err != nil {
		t.Fatalf("NewHostWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	res, err := host.CallTool(ctx, "bash", json.RawMessage(`{"command":"pytest -q","timeout_seconds":12}`))
	if err != nil {
		t.Fatalf("CallTool(bash) error = %v", err)
	}
	if res.IsError || res.Output != "sandboxed-output" {
		t.Fatalf("bash result = %+v, want sandboxed-output", res)
	}
	if stub.lastReq.Command != "pytest -q" || stub.lastReq.Timeout.Seconds() != 12 {
		t.Fatalf("sandbox runner received unexpected req = %+v", stub.lastReq)
	}
}
