package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"engram/internal/store"
)

const (
	// HookExitAllow allows tool execution to proceed.
	HookExitAllow = 0
	// HookExitBlock deterministically blocks tool execution and returns guidance to the model.
	HookExitBlock = 2

	DefaultHookTimeout = 15 * time.Second
)

// HookPhase identifies whether a hook runs before or after tool execution.
type HookPhase string

const (
	HookPhasePre  HookPhase = "pre"
	HookPhasePost HookPhase = "post"
	HookPhaseBoth HookPhase = "both"
)

var (
	// ErrUnsafeHookPath rejects hook scripts outside .engram/hooks/.
	ErrUnsafeHookPath = errors.New("control: hook script path escapes .engram/hooks directory")

	// ErrPythonNotFound is returned when no Python interpreter is available for hook execution.
	ErrPythonNotFound = errors.New("control: python interpreter not found in PATH")
)

// HookSpec defines a deterministic Python validator hook.
type HookSpec struct {
	ID             string
	Phase          HookPhase
	TargetTool     string
	TriggerPattern string
	FilePath       string // Relative to .engram/ or repo root (must resolve inside .engram/hooks/)
}

// HookInvocation carries the structured tool call context evaluated by the HookGate.
type HookInvocation struct {
	Phase        HookPhase
	SessionID    string
	StepIndex    int
	WorktreePath string
	ToolName     string
	ToolInput    json.RawMessage
	ToolOutput   string
	ExitCode     *int
}

// HookDecision summarizes the outcome of evaluating all matching hooks for an invocation.
type HookDecision struct {
	Allowed        bool
	BlockedBy      string
	Guidance       string
	TriggeredHooks []string
}

// HookGateConfig configures Python hook execution behavior.
type HookGateConfig struct {
	Workspace Workspace
	Store     *store.Store
	PythonBin string
	Timeout   time.Duration
}

type compiledHook struct {
	spec       HookSpec
	scriptPath string
	regex      *regexp.Regexp
}

// HookGate executes deterministic pre/post Python hooks inside the isolated worktree.
type HookGate struct {
	ws        Workspace
	store     *store.Store
	pythonBin string
	timeout   time.Duration
	hooks     []compiledHook
}

// NewHookGate validates and compiles a list of HookSpecs into an executable HookGate.
func NewHookGate(cfg HookGateConfig, specs []HookSpec) (*HookGate, error) {
	if strings.TrimSpace(cfg.Workspace.RepoRoot) == "" {
		return nil, errors.New("control: HookGate requires Workspace.RepoRoot")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultHookTimeout
	}

	pyBin := strings.TrimSpace(cfg.PythonBin)
	if pyBin == "" {
		resolved, err := ResolvePythonBinary()
		if err != nil && len(specs) > 0 {
			return nil, err
		}
		pyBin = resolved
	}

	compiled := make([]compiledHook, 0, len(specs))
	for _, spec := range specs {
		if spec.Phase == "" {
			spec.Phase = HookPhasePre
		}
		if spec.TriggerPattern == "" {
			spec.TriggerPattern = ".*"
		}

		re, err := regexp.Compile(spec.TriggerPattern)
		if err != nil {
			return nil, fmt.Errorf("control: compile trigger regex for hook %q: %w", spec.ID, err)
		}

		scriptPath, err := resolveHookScriptPath(cfg.Workspace, spec.FilePath)
		if err != nil {
			return nil, fmt.Errorf("control: resolve hook %q: %w", spec.ID, err)
		}

		compiled = append(compiled, compiledHook{
			spec:       spec,
			scriptPath: scriptPath,
			regex:      re,
		})
	}

	return &HookGate{
		ws:        cfg.Workspace,
		store:     cfg.Store,
		pythonBin: pyBin,
		timeout:   timeout,
		hooks:     compiled,
	}, nil
}

// LoadActiveHookSpecs gathers active hooks from SQLite and manifest.json,
// deduplicated by hook ID with SQLite status taking precedence.
func LoadActiveHookSpecs(ctx context.Context, st *store.Store, manifest Manifest) ([]HookSpec, error) {
	manifestByID := make(map[string]ManifestEntry, len(manifest.Hooks))
	for _, entry := range manifest.Hooks {
		manifestByID[entry.ID] = entry
	}

	seen := make(map[string]struct{})
	var specs []HookSpec

	if st != nil {
		dbHooks, err := st.ListEngrams(ctx, store.EngramFilter{
			Status: store.EngramStatusActive,
			Kind:   store.EngramKindHook,
		})
		if err != nil {
			return nil, fmt.Errorf("control: load active hooks from store: %w", err)
		}
		for _, h := range dbHooks {
			seen[h.ID] = struct{}{}
			targetTool := ""
			if m, ok := manifestByID[h.ID]; ok {
				targetTool = m.TargetTool
			}
			specs = append(specs, HookSpec{
				ID:             h.ID,
				Phase:          HookPhasePre,
				TargetTool:     targetTool,
				TriggerPattern: h.TriggerPattern,
				FilePath:       h.FilePath,
			})
		}
	}

	for _, entry := range manifest.Hooks {
		if entry.Status != store.EngramStatusActive {
			continue
		}
		if _, exists := seen[entry.ID]; exists {
			continue
		}
		specs = append(specs, HookSpec{
			ID:             entry.ID,
			Phase:          HookPhasePre,
			TargetTool:     entry.TargetTool,
			TriggerPattern: entry.TriggerPattern,
			FilePath:       entry.FilePath,
		})
	}

	return specs, nil
}

// Evaluate runs all matching hooks for inv in registration order.
// Exit code 0 allows execution to continue; exit code 2 immediately blocks and
// returns deterministic guidance to feed back to the LLM.
func (g *HookGate) Evaluate(ctx context.Context, inv HookInvocation) (HookDecision, error) {
	if inv.Phase == "" {
		inv.Phase = HookPhasePre
	}

	decision := HookDecision{Allowed: true}
	if len(g.hooks) == 0 {
		return decision, nil
	}

	if g.pythonBin == "" {
		resolved, err := ResolvePythonBinary()
		if err != nil {
			return HookDecision{}, err
		}
		g.pythonBin = resolved
	}

	matchTarget := extractMatchTarget(inv.ToolName, inv.ToolInput)

	for _, h := range g.hooks {
		if !hookMatches(h, inv.Phase, inv.ToolName, matchTarget) {
			continue
		}

		decision.TriggeredHooks = append(decision.TriggeredHooks, h.spec.ID)
		exitCode, output, err := g.runHookScript(ctx, h, inv)
		if err != nil {
			return HookDecision{}, fmt.Errorf("control: hook %q execution failed: %w", h.spec.ID, err)
		}

		switch exitCode {
		case HookExitAllow:
			g.recordMetrics(ctx, h.spec.ID, 1, 0)
		case HookExitBlock:
			g.recordMetrics(ctx, h.spec.ID, 1, 1)
			guidance := strings.TrimSpace(output)
			if guidance == "" {
				guidance = fmt.Sprintf("Tool call %q was blocked by deterministic hook %s (exit code 2).", inv.ToolName, h.spec.ID)
			}
			decision.Allowed = false
			decision.BlockedBy = h.spec.ID
			decision.Guidance = guidance
			return decision, nil
		default:
			return HookDecision{}, fmt.Errorf("control: hook %q exited with unexpected code %d: %s",
				h.spec.ID, exitCode, strings.TrimSpace(output))
		}
	}

	return decision, nil
}

type hookPayload struct {
	Phase        HookPhase       `json:"phase"`
	SessionID    string          `json:"session_id"`
	StepIndex    int             `json:"step_index"`
	WorktreePath string          `json:"worktree_path"`
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolOutput   string          `json:"tool_output,omitempty"`
	ExitCode     *int            `json:"exit_code,omitempty"`
}

func (g *HookGate) runHookScript(ctx context.Context, h compiledHook, inv HookInvocation) (int, string, error) {
	runCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	toolInput := inv.ToolInput
	if len(bytes.TrimSpace(toolInput)) == 0 {
		toolInput = json.RawMessage(`{}`)
	}

	payloadBytes, err := json.Marshal(hookPayload{
		Phase:        inv.Phase,
		SessionID:    inv.SessionID,
		StepIndex:    inv.StepIndex,
		WorktreePath: inv.WorktreePath,
		ToolName:     inv.ToolName,
		ToolInput:    toolInput,
		ToolOutput:   inv.ToolOutput,
		ExitCode:     inv.ExitCode,
	})
	if err != nil {
		return -1, "", fmt.Errorf("marshal hook payload: %w", err)
	}

	cmd := exec.CommandContext(runCtx, g.pythonBin, h.scriptPath)
	if strings.TrimSpace(inv.WorktreePath) != "" {
		cmd.Dir = inv.WorktreePath
	}
	cmd.Stdin = bytes.NewReader(payloadBytes)
	cmd.Env = append(os.Environ(),
		"ENGRAM_HOOK_ID="+h.spec.ID,
		"ENGRAM_HOOK_PHASE="+string(inv.Phase),
		"ENGRAM_SESSION_ID="+inv.SessionID,
		"ENGRAM_WORKTREE_PATH="+inv.WorktreePath,
		"ENGRAM_TOOL_NAME="+inv.ToolName,
		"PYTHONUNBUFFERED=1",
	)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	err = cmd.Run()
	if err == nil {
		return 0, combined.String(), nil
	}

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return -1, combined.String(), fmt.Errorf("hook timed out after %s", g.timeout)
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), combined.String(), nil
	}
	return -1, combined.String(), err
}

func (g *HookGate) recordMetrics(ctx context.Context, hookID string, triggered, prevented int64) {
	if g.store == nil || hookID == "" {
		return
	}
	_ = g.store.IncrementEngramMetrics(ctx, hookID, triggered, prevented)
}

func hookMatches(h compiledHook, phase HookPhase, toolName, matchTarget string) bool {
	if h.spec.Phase != HookPhaseBoth && h.spec.Phase != phase {
		return false
	}
	if h.spec.TargetTool != "" && h.spec.TargetTool != toolName {
		return false
	}
	return h.regex.MatchString(matchTarget)
}

func extractMatchTarget(toolName string, toolInput json.RawMessage) string {
	if len(bytes.TrimSpace(toolInput)) > 0 {
		var fields map[string]any
		if err := json.Unmarshal(toolInput, &fields); err == nil {
			for _, key := range []string{"command", "cmd", "path", "file_path"} {
				if v, ok := fields[key].(string); ok && strings.TrimSpace(v) != "" {
					return v
				}
			}
		}
		return string(toolInput)
	}
	return toolName
}

func resolveHookScriptPath(ws Workspace, relPath string) (string, error) {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return "", fmt.Errorf("%w: empty hook file_path", ErrUnsafeHookPath)
	}
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("%w: absolute path %q not allowed", ErrUnsafeHookPath, relPath)
	}

	cleaned := filepath.Clean(filepath.FromSlash(relPath))
	var candidate string
	if strings.HasPrefix(cleaned, EngramDirName+string(filepath.Separator)) {
		candidate = filepath.Join(ws.RepoRoot, cleaned)
	} else {
		candidate = filepath.Join(ws.EngramDir(), cleaned)
	}

	absHooksDir, err := filepath.Abs(ws.HooksDir())
	if err != nil {
		return "", err
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}

	relToHooks, err := filepath.Rel(absHooksDir, absCandidate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeHookPath, err)
	}
	if relToHooks == "." || relToHooks == ".." || strings.HasPrefix(relToHooks, ".."+string(filepath.Separator)) || filepath.IsAbs(relToHooks) {
		return "", fmt.Errorf("%w: %q is outside %q", ErrUnsafeHookPath, absCandidate, absHooksDir)
	}
	if _, err := os.Stat(absCandidate); err != nil {
		return "", fmt.Errorf("hook script %q not accessible: %w", absCandidate, err)
	}
	return absCandidate, nil
}

// ResolvePythonBinary finds an executable Python interpreter across platforms,
// avoiding Windows Microsoft Store alias stubs when a real python binary exists.
func ResolvePythonBinary() (string, error) {
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3"}
	}

	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(path), `\microsoft\windowsapps\`) {
			continue
		}
		return path, nil
	}
	return "", ErrPythonNotFound
}
