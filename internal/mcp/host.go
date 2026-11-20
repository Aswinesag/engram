package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	mcpproto "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	BuiltinServerName     = "builtin"
	DefaultCommandTimeout = 60 * time.Second
)

var (
	// ErrToolNotFound is returned when CallTool references an unregistered tool name.
	ErrToolNotFound = errors.New("mcp: tool not found")

	// ErrUnsafeToolPath rejects synthesized tool scripts outside .engram/tools/.
	ErrUnsafeToolPath = errors.New("mcp: synthesized tool path escapes .engram/tools directory")

	// ErrOutsideWorktree enforces Invariant #1 for built-in file tools.
	ErrOutsideWorktree = errors.New("mcp: path escapes isolated worktree boundary")
)

// ToolDefinition describes an MCP tool exposed to the LLM router.
type ToolDefinition struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"input_schema"`
	ServerName   string          `json:"server_name"`
	MutatesFiles bool            `json:"mutates_files"`
}

// ToolResult captures normalized execution telemetry from any MCP tool call.
type ToolResult struct {
	ToolName     string
	ServerName   string
	Output       string
	IsError      bool
	ExitCode     int
	MutatesFiles bool
}

type mountedServer struct {
	name   string
	client client.MCPClient
}

type toolRoute struct {
	serverName string
	client     client.MCPClient
	def        ToolDefinition
}

// Host is Engram's native Model Context Protocol host built directly on mcp-go.
// Built-in worktree tools, external community MCP servers, and self-synthesized
// Python tools in .engram/tools/ all execute uniformly through Host.
type Host struct {
	worktreePath string

	mu      sync.RWMutex
	servers map[string]*mountedServer
	routes  map[string]toolRoute
}

// NewHost initializes an MCP Host bound to an isolated session worktree and
// mounts the built-in worktree-scoped MCP server in-process.
func NewHost(ctx context.Context, worktreePath string) (*Host, error) {
	if strings.TrimSpace(worktreePath) == "" {
		return nil, errors.New("mcp: worktreePath must not be empty")
	}

	absWT, err := filepath.Abs(worktreePath)
	if err != nil {
		return nil, fmt.Errorf("mcp: resolve worktreePath: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(absWT); err == nil {
		absWT = resolved
	}
	info, err := os.Stat(absWT)
	if err != nil {
		return nil, fmt.Errorf("mcp: stat worktreePath %q: %w", absWT, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("mcp: worktreePath %q is not a directory", absWT)
	}

	h := &Host{
		worktreePath: filepath.Clean(absWT),
		servers:      make(map[string]*mountedServer),
		routes:       make(map[string]toolRoute),
	}

	builtinSrv := newBuiltinWorktreeServer(h.worktreePath)
	inProcClient, err := client.NewInProcessClient(builtinSrv)
	if err != nil {
		return nil, fmt.Errorf("mcp: create in-process builtin client: %w", err)
	}
	if err := inProcClient.Start(ctx); err != nil {
		_ = inProcClient.Close()
		return nil, fmt.Errorf("mcp: start in-process builtin client: %w", err)
	}

	if err := h.registerClient(ctx, BuiltinServerName, inProcClient); err != nil {
		_ = inProcClient.Close()
		return nil, err
	}

	return h, nil
}

// WorktreePath returns the canonical isolated worktree path bound to this Host.
func (h *Host) WorktreePath() string { return h.worktreePath }

// MountStdioServer spawns an MCP server over stdio JSON-RPC, completes the MCP
// initialize handshake, discovers its tools, and mounts them into the routing table.
func (h *Host) MountStdioServer(ctx context.Context, name, command string, env []string, args ...string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("mcp: server name must not be empty")
	}
	if strings.TrimSpace(command) == "" {
		return errors.New("mcp: server command must not be empty")
	}

	stdioClient, err := client.NewStdioMCPClient(command, env, args...)
	if err != nil {
		return fmt.Errorf("mcp: launch stdio server %q: %w", name, err)
	}

	if err := h.registerClient(ctx, name, stdioClient); err != nil {
		_ = stdioClient.Close()
		return err
	}
	return nil
}

// MountSynthesizedTool validates that relFilePath resides inside toolsDir
// (.engram/tools/) and mounts the synthesized Python MCP tool server over stdio.
func (h *Host) MountSynthesizedTool(ctx context.Context, pythonBin, toolsDir, engramID, relFilePath string) error {
	if strings.TrimSpace(pythonBin) == "" {
		return errors.New("mcp: pythonBin must not be empty")
	}
	scriptPath, err := resolveToolScriptPath(toolsDir, relFilePath)
	if err != nil {
		return err
	}

	env := []string{
		"ENGRAM_WORKTREE_PATH=" + h.worktreePath,
		"ENGRAM_TOOL_ID=" + engramID,
		"PYTHONUNBUFFERED=1",
	}
	return h.MountStdioServer(ctx, engramID, pythonBin, env, scriptPath)
}

func (h *Host) registerClient(ctx context.Context, name string, c client.MCPClient) error {
	h.mu.RLock()
	_, duplicate := h.servers[name]
	h.mu.RUnlock()
	if duplicate {
		return fmt.Errorf("mcp: server %q is already mounted", name)
	}

	initReq := mcpproto.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpproto.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpproto.Implementation{
		Name:    "engram-host",
		Version: "1.0.0",
	}

	if _, err := c.Initialize(ctx, initReq); err != nil {
		return fmt.Errorf("mcp: initialize server %q: %w", name, err)
	}

	toolsRes, err := c.ListTools(ctx, mcpproto.ListToolsRequest{})
	if err != nil {
		return fmt.Errorf("mcp: list tools on server %q: %w", name, err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.servers[name]; exists {
		return fmt.Errorf("mcp: server %q is already mounted", name)
	}

	pending := make([]toolRoute, 0, len(toolsRes.Tools))
	for _, t := range toolsRes.Tools {
		if existing, conflict := h.routes[t.Name]; conflict {
			return fmt.Errorf("mcp: tool %q from server %q conflicts with server %q",
				t.Name, name, existing.serverName)
		}

		schemaBytes, err := marshalToolSchema(t)
		if err != nil {
			return fmt.Errorf("mcp: marshal schema for tool %q: %w", t.Name, err)
		}

		pending = append(pending, toolRoute{
			serverName: name,
			client:     c,
			def: ToolDefinition{
				Name:         t.Name,
				Description:  t.Description,
				InputSchema:  schemaBytes,
				ServerName:   name,
				MutatesFiles: toolMutatesFiles(name, t.Name),
			},
		})
	}

	h.servers[name] = &mountedServer{name: name, client: c}
	for _, route := range pending {
		h.routes[route.def.Name] = route
	}
	return nil
}

// Tools returns all registered MCP tool definitions sorted deterministically by name.
func (h *Host) Tools() []ToolDefinition {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]ToolDefinition, 0, len(h.routes))
	for _, route := range h.routes {
		out = append(out, route.def)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// CallTool invokes a registered MCP tool by name with JSON arguments.
func (h *Host) CallTool(ctx context.Context, toolName string, inputJSON json.RawMessage) (ToolResult, error) {
	h.mu.RLock()
	route, ok := h.routes[toolName]
	h.mu.RUnlock()
	if !ok {
		return ToolResult{}, fmt.Errorf("%w: %s", ErrToolNotFound, toolName)
	}

	args := map[string]any{}
	if len(bytes.TrimSpace(inputJSON)) > 0 {
		if err := json.Unmarshal(inputJSON, &args); err != nil {
			return ToolResult{}, fmt.Errorf("mcp: decode arguments for tool %q: %w", toolName, err)
		}
	}

	req := mcpproto.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args

	res, err := route.client.CallTool(ctx, req)
	if err != nil {
		return ToolResult{}, fmt.Errorf("mcp: call tool %q on server %q: %w", toolName, route.serverName, err)
	}

	output := extractResultText(res)
	exitCode := 0
	if res.IsError {
		exitCode = extractExitCode(output)
	}

	return ToolResult{
		ToolName:     toolName,
		ServerName:   route.serverName,
		Output:       output,
		IsError:      res.IsError,
		ExitCode:     exitCode,
		MutatesFiles: route.def.MutatesFiles,
	}, nil
}

// Close shuts down all mounted MCP servers and releases stdio subprocesses.
func (h *Host) Close() error {
	h.mu.Lock()
	servers := h.servers
	h.servers = make(map[string]*mountedServer)
	h.routes = make(map[string]toolRoute)
	h.mu.Unlock()

	var errs []error
	for name, srv := range servers {
		if err := srv.client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("mcp: close server %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func newBuiltinWorktreeServer(worktreePath string) *server.MCPServer {
	s := server.NewMCPServer(
		"engram-worktree-builtin",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	s.AddTool(
		mcpproto.NewTool(
			"read_file",
			mcpproto.WithDescription("Read a UTF-8 text file inside the isolated session worktree."),
			mcpproto.WithString("path", mcpproto.Required(), mcpproto.Description("Relative path inside the worktree")),
		),
		func(_ context.Context, req mcpproto.CallToolRequest) (*mcpproto.CallToolResult, error) {
			relPath, err := req.RequireString("path")
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			fullPath, err := resolveWorktreePath(worktreePath, relPath)
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			data, err := os.ReadFile(fullPath)
			if err != nil {
				return mcpproto.NewToolResultError(fmt.Sprintf("read_file failed: %v", err)), nil
			}
			return mcpproto.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcpproto.NewTool(
			"write_file",
			mcpproto.WithDescription("Write or overwrite a file inside the isolated session worktree."),
			mcpproto.WithString("path", mcpproto.Required(), mcpproto.Description("Relative path inside the worktree")),
			mcpproto.WithString("content", mcpproto.Required(), mcpproto.Description("Full file content to write")),
		),
		func(_ context.Context, req mcpproto.CallToolRequest) (*mcpproto.CallToolResult, error) {
			relPath, err := req.RequireString("path")
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			content, err := req.RequireString("content")
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			fullPath, err := resolveWorktreePath(worktreePath, relPath)
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
				return mcpproto.NewToolResultError(fmt.Sprintf("mkdir failed: %v", err)), nil
			}
			if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
				return mcpproto.NewToolResultError(fmt.Sprintf("write_file failed: %v", err)), nil
			}
			return mcpproto.NewToolResultText(fmt.Sprintf("wrote %d bytes to %s", len(content), filepath.ToSlash(relPath))), nil
		},
	)

	s.AddTool(
		mcpproto.NewTool(
			"list_files",
			mcpproto.WithDescription("List directory entries inside the isolated session worktree."),
			mcpproto.WithString("path", mcpproto.Description("Optional relative subdirectory inside the worktree (defaults to '.')")),
		),
		func(_ context.Context, req mcpproto.CallToolRequest) (*mcpproto.CallToolResult, error) {
			relPath := req.GetString("path", ".")
			if strings.TrimSpace(relPath) == "" {
				relPath = "."
			}
			fullPath, err := resolveWorktreePath(worktreePath, relPath)
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			entries, err := os.ReadDir(fullPath)
			if err != nil {
				return mcpproto.NewToolResultError(fmt.Sprintf("list_files failed: %v", err)), nil
			}
			var lines []string
			for _, e := range entries {
				if e.Name() == ".git" {
					continue
				}
				name := e.Name()
				if e.IsDir() {
					name += "/"
				}
				lines = append(lines, name)
			}
			return mcpproto.NewToolResultText(strings.Join(lines, "\n")), nil
		},
	)

	s.AddTool(
		mcpproto.NewTool(
			"bash",
			mcpproto.WithDescription("Execute a shell command inside the isolated session worktree."),
			mcpproto.WithString("command", mcpproto.Required(), mcpproto.Description("Shell command to run")),
			mcpproto.WithNumber("timeout_seconds", mcpproto.Description("Optional timeout in seconds (default 60)")),
		),
		func(ctx context.Context, req mcpproto.CallToolRequest) (*mcpproto.CallToolResult, error) {
			command, err := req.RequireString("command")
			if err != nil {
				return mcpproto.NewToolResultError(err.Error()), nil
			}
			timeout := DefaultCommandTimeout
			if secs := req.GetFloat("timeout_seconds", 0); secs > 0 {
				timeout = time.Duration(secs * float64(time.Second))
			}

			runCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.CommandContext(runCtx, "cmd", "/C", command)
			} else {
				cmd = exec.CommandContext(runCtx, "sh", "-c", command)
			}
			cmd.Dir = worktreePath

			var combined bytes.Buffer
			cmd.Stdout = &combined
			cmd.Stderr = &combined

			runErr := cmd.Run()
			output := combined.String()
			if runErr == nil {
				return mcpproto.NewToolResultText(output), nil
			}

			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return mcpproto.NewToolResultError(fmt.Sprintf("exit_code=124\ncommand timed out after %s\n%s", timeout, output)), nil
			}

			exitCode := 1
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
			return mcpproto.NewToolResultError(fmt.Sprintf("exit_code=%d\n%s", exitCode, output)), nil
		},
	)

	return s
}

func resolveWorktreePath(worktreeRoot, userPath string) (string, error) {
	userPath = strings.TrimSpace(userPath)
	if userPath == "" {
		return "", fmt.Errorf("%w: empty path", ErrOutsideWorktree)
	}
	if filepath.IsAbs(userPath) {
		return "", fmt.Errorf("%w: absolute path %q not allowed", ErrOutsideWorktree, userPath)
	}

	candidate := filepath.Clean(filepath.Join(worktreeRoot, filepath.FromSlash(userPath)))
	rel, err := filepath.Rel(worktreeRoot, candidate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOutsideWorktree, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %q", ErrOutsideWorktree, userPath)
	}

	// Verify existing symlinks do not escape worktreeRoot.
	if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
		relResolved, relErr := filepath.Rel(worktreeRoot, resolved)
		if relErr != nil || relResolved == ".." || strings.HasPrefix(relResolved, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%w: symlink target escapes worktree", ErrOutsideWorktree)
		}
	}

	return candidate, nil
}

func resolveToolScriptPath(toolsDir, relFilePath string) (string, error) {
	relFilePath = strings.TrimSpace(relFilePath)
	if relFilePath == "" {
		return "", fmt.Errorf("%w: empty tool file_path", ErrUnsafeToolPath)
	}
	if filepath.IsAbs(relFilePath) {
		return "", fmt.Errorf("%w: absolute path %q not allowed", ErrUnsafeToolPath, relFilePath)
	}

	absToolsDir, err := filepath.Abs(toolsDir)
	if err != nil {
		return "", err
	}

	cleaned := filepath.Clean(filepath.FromSlash(relFilePath))
	// Accept either "tools/foo.py", ".engram/tools/foo.py", or "foo.py".
	basePrefix := "tools" + string(filepath.Separator)
	engramPrefix := ".engram" + string(filepath.Separator) + basePrefix
	switch {
	case strings.HasPrefix(cleaned, engramPrefix):
		cleaned = strings.TrimPrefix(cleaned, engramPrefix)
	case strings.HasPrefix(cleaned, basePrefix):
		cleaned = strings.TrimPrefix(cleaned, basePrefix)
	}

	candidate := filepath.Clean(filepath.Join(absToolsDir, cleaned))
	rel, err := filepath.Rel(absToolsDir, candidate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeToolPath, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %q is outside %q", ErrUnsafeToolPath, candidate, absToolsDir)
	}
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("mcp: tool script %q not accessible: %w", candidate, err)
	}
	return candidate, nil
}

func marshalToolSchema(t mcpproto.Tool) (json.RawMessage, error) {
	if len(bytes.TrimSpace(t.RawInputSchema)) > 0 {
		return t.RawInputSchema, nil
	}
	schema := t.InputSchema
	if schema.Type == "" {
		schema.Type = "object"
	}
	b, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func toolMutatesFiles(serverName, toolName string) bool {
	if serverName == BuiltinServerName {
		switch toolName {
		case "read_file", "list_files":
			return false
		default:
			return true
		}
	}
	// External and synthesized MCP tools are conservatively treated as potentially mutating
	// so the runtime takes an atomic shadow commit check afterward.
	return true
}

func extractResultText(res *mcpproto.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	var parts []string
	for _, item := range res.Content {
		if tc, ok := mcpproto.AsTextContent(item); ok && tc != nil {
			parts = append(parts, tc.Text)
			continue
		}
		if text := mcpproto.GetTextFromContent(item); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

func extractExitCode(errOutput string) int {
	firstLine, _, _ := strings.Cut(errOutput, "\n")
	if strings.HasPrefix(firstLine, "exit_code=") {
		if code, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(firstLine, "exit_code="))); err == nil {
			return code
		}
	}
	return 1
}
