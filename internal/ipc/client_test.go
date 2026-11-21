package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestClientTalksToUnixJSONRPCServer(t *testing.T) {
	// Keep AF_UNIX socket path well below the 108-byte OS sun_path limit.
	sockDir, err := os.MkdirTemp("", "eng-ipc-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "c.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix, %q): %v", sockPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req rpcRequest
				_ = json.Unmarshal(line, &req)

				var resp map[string]any
				switch req.Method {
				case "compiler.ping":
					resp = map[string]any{
						"jsonrpc": "2.0",
						"id":      req.ID,
						"result":  map[string]any{"status": "ok", "version": "1.0.0"},
					}
				case "compiler.synthesize":
					resp = map[string]any{
						"jsonrpc": "2.0",
						"id":      req.ID,
						"result": map[string]any{
							"engram_id":        "eng_01J9X4M9",
							"kind":             "hook",
							"target_tool":      "bash",
							"command_regex":    `^pytest\b`,
							"file_path":        ".engram/hooks/eng_01J9X4M9_verify_test_db.py",
							"shadow_verified":  true,
							"shadow_pass_rate": 1.0,
							"status":           "active",
							"explanation":      "Verifies PostgreSQL test container on port 5432.",
						},
					}
				default:
					resp = map[string]any{
						"jsonrpc": "2.0",
						"id":      req.ID,
						"error":   map[string]any{"code": -32601, "message": "method not found"},
					}
				}
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(conn)
		}
	}()

	ctx := context.Background()
	client := NewClient(sockPath, 10*time.Second)

	ping, err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if ping.Status != "ok" || ping.Version != "1.0.0" {
		t.Fatalf("Ping() = %+v", ping)
	}

	res, err := client.Synthesize(ctx, SynthesizeParams{
		SessionID:     "sess_01J9W8K2",
		RepoRoot:      "/tmp/repo",
		BaseCommitSHA: "a1b2c3d4",
		FrictionEvents: []FrictionEvent{
			{
				StepRange: [2]int{4, 7},
				Pattern:   PatternRepeatedToolError,
				ToolName:  "bash",
				Summary:   "pytest failed 3 times with ConnectionRefusedError on port 5432",
			},
		},
	})
	if err != nil {
		t.Fatalf("Synthesize() error = %v", err)
	}
	if res.EngramID != "eng_01J9X4M9" || !res.ShadowVerified || res.CommandRegex != `^pytest\b` {
		t.Fatalf("Synthesize() = %+v", res)
	}
}

func TestClientEndToEndWithPythonEvolutionCompiler(t *testing.T) {
	pyBin, err := findPythonForIPC()
	if err != nil {
		t.Skipf("python not found: %v", err)
	}

	compilerDir, err := filepath.Abs(filepath.Join("..", "..", "compiler"))
	if err != nil {
		t.Fatalf("resolve compiler dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(compilerDir, "engram_compiler", "server.py")); err != nil {
		t.Skipf("python compiler not present at %q", compilerDir)
	}

	// Create a real temp Git repository for shadow worktree verification.
	repo := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init")
	runGit("config", "user.email", "ipc-test@engram.local")
	runGit("config", "user.name", "Engram IPC Test")
	runGit("config", "core.autocrlf", "false")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# ipc test\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGit("add", "README.md")
	runGit("commit", "-m", "init")
	baseSHA := runGit("rev-parse", "HEAD")

	sockPath, err := SocketPathForRepo(repo)
	if err != nil {
		t.Fatalf("SocketPathForRepo() error = %v", err)
	}

	ctx := context.Background()
	sidecar, err := StartSidecar(ctx, pyBin, compilerDir, sockPath)
	if err != nil {
		t.Fatalf("StartSidecar() error = %v", err)
	}
	t.Cleanup(func() { _ = sidecar.Stop() })

	// Find a guaranteed unused TCP port for the connection-refused hook synthesis.
	portLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unused port: %v", err)
	}
	unusedPort := portLn.Addr().(*net.TCPAddr).Port
	_ = portLn.Close()

	res, err := sidecar.Client().Synthesize(ctx, SynthesizeParams{
		SessionID:     "sess_ipc_e2e",
		RepoRoot:      repo,
		BaseCommitSHA: baseSHA,
		FrictionEvents: []FrictionEvent{
			{
				StepRange: [2]int{1, 3},
				Pattern:   PatternRepeatedToolError,
				ToolName:  "bash",
				Summary:   "Agent ran 'pytest tests/api' 3 times failing with ConnectionRefusedError on port " + itoa(unusedPort),
			},
		},
	})
	if err != nil {
		t.Fatalf("Synthesize() via Python sidecar error = %v", err)
	}
	if !res.ShadowVerified || res.Kind != "hook" || res.Status != "active" {
		t.Fatalf("unexpected synthesize result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(res.FilePath))); err != nil {
		t.Fatalf("expected synthesized hook at %q: %v", res.FilePath, err)
	}
}

func findPythonForIPC() (string, error) {
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

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
