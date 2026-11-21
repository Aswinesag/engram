package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"engram/internal/ipc"
	"engram/internal/mcp"
	"engram/internal/proxy"
	"engram/internal/sandbox"
	"engram/internal/store"
	"engram/internal/worktree"
)

const DefaultMaxSteps = 50

var (
	// ErrMaxStepsExceeded is returned when an agent session reaches its step cap.
	ErrMaxStepsExceeded = errors.New("control: agent session exceeded maximum step limit")
)

// EvolutionClient abstracts the Unix Domain Socket IPC client for the Python
// Evolution Compiler (implemented by *ipc.Client).
type EvolutionClient interface {
	Synthesize(ctx context.Context, params ipc.SynthesizeParams) (ipc.SynthesizeResult, error)
}

// AgentLoopConfig wires all deterministic runtime, sandbox, proxy, and evolution subsystems.
type AgentLoopConfig struct {
	Workspace       Workspace
	Config          Config
	Manifest        Manifest
	Store           *store.Store
	Router          *ModelRouter
	WorktreeMgr     *worktree.Manager
	SandboxRunner   sandbox.Runner     // Optional override; defaults to Config.Sandbox.Mode
	EgressProxy     *proxy.EgressProxy // Optional override; defaults to per-session local proxy
	Scrubber        *proxy.Scrubber    // Optional override; defaults to .env-aware Scrubber when RedactSecrets=true
	EvolutionClient EvolutionClient    // Optional UDS JSON-RPC client to Python Evolution Compiler
	PythonBin       string
	MaxSteps        int
	SystemPrompt    string
	Out             io.Writer
	ErrOut          io.Writer
}

// AgentRunResult summarizes a completed or terminated session.
type AgentRunResult struct {
	SessionID          string
	WorktreePath       string
	BaseCommitSHA      string
	HeadCommitSHA      string
	FinalResponse      string
	StepsRecorded      int
	ConsecutiveErrors  int
	SynthesizedEngrams []ipc.SynthesizeResult
}

// AgentLoop executes the zero-framework, step-committed streaming agent loop.
type AgentLoop struct {
	cfg       AgentLoopConfig
	compactor *ContextCompactor
}

// NewAgentLoop validates dependencies and constructs an AgentLoop.
func NewAgentLoop(cfg AgentLoopConfig) (*AgentLoop, error) {
	if strings.TrimSpace(cfg.Workspace.RepoRoot) == "" {
		return nil, errors.New("control: AgentLoop requires Workspace.RepoRoot")
	}
	if cfg.Store == nil {
		return nil, errors.New("control: AgentLoop requires Store")
	}
	if cfg.Router == nil {
		return nil, errors.New("control: AgentLoop requires ModelRouter")
	}
	if cfg.WorktreeMgr == nil {
		mgr, err := worktree.NewManager(cfg.Workspace.RepoRoot, cfg.Workspace.WorktreesDir())
		if err != nil {
			return nil, err
		}
		cfg.WorktreeMgr = mgr
	}
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = DefaultMaxSteps
	}
	if strings.TrimSpace(cfg.SystemPrompt) == "" {
		cfg.SystemPrompt = defaultAgentSystemPrompt()
	}

	compactor, err := NewContextCompactor(cfg.Workspace.ArtifactsDir(), cfg.Config.Context.ArtifactTokenThreshold)
	if err != nil {
		return nil, err
	}

	return &AgentLoop{
		cfg:       cfg,
		compactor: compactor,
	}, nil
}

// Run executes taskPrompt inside an isolated detached Git worktree with a
// per-session domain-allowlisted egress proxy, dual-mode command sandboxing,
// automatic secret scrubbing, deterministic Python hooks, strict context hygiene,
// and closed-loop friction compilation via the Python Evolution Compiler.
func (a *AgentLoop) Run(ctx context.Context, taskPrompt string) (result AgentRunResult, runErr error) {
	taskPrompt = strings.TrimSpace(taskPrompt)
	if taskPrompt == "" {
		return AgentRunResult{}, errors.New("control: taskPrompt must not be empty")
	}

	// 1. Configure secret scrubber (including repo .env values) and attach to ModelRouter.
	scrubber, err := a.buildScrubber()
	if err != nil {
		return AgentRunResult{}, err
	}
	if scrubber != nil {
		a.cfg.Router.SetScrubber(scrubber)
		a.cfg.Router.SetSecretScrubHandler(func(findings []proxy.Finding) {
			if a.cfg.ErrOut == nil {
				return
			}
			rules := make([]string, 0, len(findings))
			for _, f := range findings {
				rules = append(rules, f.Rule)
			}
			fmt.Fprintf(a.cfg.ErrOut, "[security] redacted %d secret(s) from outbound LLM payload (%s)\n",
				len(findings), strings.Join(rules, ", "))
		})
	}

	// 2. Start per-session HTTP/SOCKS5 egress proxy enforcing config.toml allowed_domains.
	egressProxy := a.cfg.EgressProxy
	ownsProxy := false
	if egressProxy == nil {
		var err error
		egressProxy, err = proxy.NewEgressProxy(proxy.ProxyConfig{
			AllowedDomains: a.cfg.Config.Sandbox.AllowedDomains,
			Scrubber:       scrubber,
			SecretAction:   proxy.SecretActionBlock,
			OnEvent: func(ev proxy.AuditEvent) {
				if !ev.Allowed && a.cfg.ErrOut != nil {
					fmt.Fprintf(a.cfg.ErrOut, "[egress-proxy] blocked %s -> %s (%s)\n",
						ev.Protocol, ev.Target, ev.Reason)
				}
			},
		})
		if err != nil {
			return AgentRunResult{}, err
		}
		if err := egressProxy.Start(ctx); err != nil {
			return AgentRunResult{}, err
		}
		ownsProxy = true
	}
	if ownsProxy {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = egressProxy.Close(closeCtx)
		}()
	}

	// 3. Provision dual-mode sandbox runner routed through the local egress proxy.
	sandboxRunner := a.cfg.SandboxRunner
	if sandboxRunner == nil {
		var err error
		sandboxRunner, err = sandbox.NewRunner(sandbox.Config{
			Mode:           sandbox.Mode(a.cfg.Config.Sandbox.Mode),
			ContainerImage: a.cfg.Config.Sandbox.ContainerImage,
			ProxyEnv:       egressProxy.ProxyEnv(),
		})
		if err != nil {
			return AgentRunResult{}, err
		}
	}

	// 4. Provision detached Git worktree (Invariant #1: Zero Host Filesystem Mutation).
	sessionID := newID("sess")
	sessWT, err := a.cfg.WorktreeMgr.Create(ctx, sessionID, "")
	if err != nil {
		return AgentRunResult{}, err
	}

	result.SessionID = sessionID
	result.WorktreePath = sessWT.WorktreePath
	result.BaseCommitSHA = sessWT.BaseCommitSHA
	result.HeadCommitSHA = sessWT.BaseCommitSHA

	sess := store.Session{
		ID:            sessionID,
		TaskPrompt:    taskPrompt,
		BaseCommitSHA: sessWT.BaseCommitSHA,
		WorktreePath:  sessWT.WorktreePath,
		Status:        store.SessionRunning,
	}
	if err := a.cfg.Store.CreateSession(ctx, sess); err != nil {
		return result, err
	}

	finalStatus := store.SessionFailed
	defer func() {
		if runErr == nil {
			finalStatus = store.SessionCompleted
		} else if errors.Is(ctx.Err(), context.Canceled) || errors.Is(runErr, context.Canceled) {
			finalStatus = store.SessionAborted
		}
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.cfg.Store.UpdateSessionStatus(updateCtx, sessionID, finalStatus)
	}()

	host, err := mcp.NewHostWithOptions(ctx, sessWT.WorktreePath, mcp.HostOptions{
		CommandRunner: sandboxRunner,
	})
	if err != nil {
		return result, err
	}
	defer func() {
		_ = host.Close()
	}()

	if err := a.mountActiveTools(ctx, host); err != nil {
		return result, err
	}

	gate, err := a.reloadHookGate(ctx)
	if err != nil {
		return result, err
	}

	messages := []Message{
		{Role: RoleUser, Content: taskPrompt},
	}
	tools := host.Tools()
	stepIndex := 0
	errorTrigger := a.cfg.Config.Evolution.ConsecutiveErrorTrigger
	if errorTrigger <= 0 {
		errorTrigger = DefaultConsecutiveErrorTrigger
	}

	consecutiveErrors := 0
	errorStreakStart := 0
	fileEditCounts := make(map[string]int)
	fileEditFirstStep := make(map[string]int)
	triggeredFriction := make(map[string]struct{})
	var pendingSessionFriction []ipc.FrictionEvent

	for stepIndex < a.cfg.MaxSteps {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		turnStart := time.Now()
		resp, err := a.cfg.Router.StreamChat(ctx, ChatRequest{
			SystemPrompt: a.cfg.SystemPrompt,
			Messages:     messages,
			Tools:        tools,
		}, func(delta string) {
			if a.cfg.Out != nil {
				_, _ = io.WriteString(a.cfg.Out, delta)
			}
		})
		if err != nil {
			return result, err
		}
		turnDurationMS := time.Since(turnStart).Milliseconds()

		messages = append(messages, Message{
			Role:      RoleAssistant,
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		if len(resp.ToolCalls) == 0 {
			stepIndex++
			headSHA, err := a.cfg.WorktreeMgr.HeadSHA(ctx, sessWT.WorktreePath)
			if err != nil {
				return result, err
			}
			if err := a.cfg.Store.CreateStep(ctx, store.Step{
				ID:           newID("step"),
				SessionID:    sessionID,
				StepIndex:    stepIndex,
				GitCommitSHA: headSHA,
				Thought:      resp.Content,
				DurationMS:   turnDurationMS,
				TokensIn:     resp.TokensIn,
				TokensOut:    resp.TokensOut,
			}); err != nil {
				return result, err
			}

			if a.cfg.Out != nil && resp.Content != "" && !strings.HasSuffix(resp.Content, "\n") {
				_, _ = io.WriteString(a.cfg.Out, "\n")
			}

			// If uncompiled friction occurred during the session, invoke Evolution Compiler at session end.
			if len(pendingSessionFriction) > 0 && a.cfg.EvolutionClient != nil {
				if synthRes, ok := a.invokeEvolutionCompiler(ctx, sessionID, sessWT.BaseCommitSHA, pendingSessionFriction); ok {
					result.SynthesizedEngrams = append(result.SynthesizedEngrams, synthRes)
				}
			}

			result.FinalResponse = resp.Content
			result.HeadCommitSHA = headSHA
			result.StepsRecorded = stepIndex
			result.ConsecutiveErrors = consecutiveErrors
			return result, nil
		}

		for callIdx, tc := range resp.ToolCalls {
			if stepIndex >= a.cfg.MaxSteps {
				return result, ErrMaxStepsExceeded
			}
			stepIndex++

			var (
				tokensIn  int64
				tokensOut int64
				thought   string
			)
			if callIdx == 0 {
				tokensIn = resp.TokensIn
				tokensOut = resp.TokensOut
				thought = resp.Content
			}

			stepStart := time.Now()
			toolInputJSON := strings.TrimSpace(string(tc.Input))
			if toolInputJSON == "" {
				toolInputJSON = "{}"
			}

			// 1. Pre-Tool Deterministic Hook Gate.
			preDecision, err := gate.Evaluate(ctx, HookInvocation{
				Phase:        HookPhasePre,
				SessionID:    sessionID,
				StepIndex:    stepIndex,
				WorktreePath: sessWT.WorktreePath,
				ToolName:     tc.Name,
				ToolInput:    tc.Input,
			})
			if err != nil {
				return result, err
			}

			if !preDecision.Allowed {
				headSHA, err := a.cfg.WorktreeMgr.HeadSHA(ctx, sessWT.WorktreePath)
				if err != nil {
					return result, err
				}
				blockedCode := HookExitBlock
				if err := a.cfg.Store.CreateStep(ctx, store.Step{
					ID:                newID("step"),
					SessionID:         sessionID,
					StepIndex:         stepIndex,
					GitCommitSHA:      headSHA,
					Thought:           thought,
					ToolName:          tc.Name,
					ToolInputJSON:     toolInputJSON,
					ToolOutputSummary: preDecision.Guidance,
					ExitCode:          &blockedCode,
					DurationMS:        turnDurationMS + time.Since(stepStart).Milliseconds(),
					TokensIn:          tokensIn,
					TokensOut:         tokensOut,
				}); err != nil {
					return result, err
				}

				if a.cfg.ErrOut != nil {
					fmt.Fprintf(a.cfg.ErrOut, "[hook %s blocked %s] %s\n", preDecision.BlockedBy, tc.Name, preDecision.Guidance)
				}

				messages = append(messages, Message{
					Role:       RoleTool,
					ToolCallID: tc.ID,
					ToolName:   tc.Name,
					Content:    preDecision.Guidance,
					IsError:    true,
				})
				continue
			}

			// 2. Execute Tool via Sandboxed MCP Host inside the isolated worktree.
			toolRes, callErr := host.CallTool(ctx, tc.Name, tc.Input)
			rawOutput := toolRes.Output
			exitCode := toolRes.ExitCode
			isError := toolRes.IsError
			mutatesFiles := toolRes.MutatesFiles
			if callErr != nil {
				rawOutput = callErr.Error()
				exitCode = 1
				isError = true
				mutatesFiles = true
			}

			// 3. Post-Tool Deterministic Hook Gate.
			postDecision, err := gate.Evaluate(ctx, HookInvocation{
				Phase:        HookPhasePost,
				SessionID:    sessionID,
				StepIndex:    stepIndex,
				WorktreePath: sessWT.WorktreePath,
				ToolName:     tc.Name,
				ToolInput:    tc.Input,
				ToolOutput:   rawOutput,
				ExitCode:     &exitCode,
			})
			if err != nil {
				return result, err
			}
			if !postDecision.Allowed {
				isError = true
				if exitCode == 0 {
					exitCode = HookExitBlock
				}
				rawOutput = strings.TrimSpace(rawOutput + "\n[post-hook " + postDecision.BlockedBy + "]: " + postDecision.Guidance)
			}

			// 4. Atomic Step Shadow Commit.
			var headSHA string
			if mutatesFiles {
				shadow, err := a.cfg.WorktreeMgr.CommitStep(ctx, sessWT.WorktreePath, stepIndex,
					fmt.Sprintf("engram: step %d (%s)", stepIndex, tc.Name))
				if err != nil {
					return result, err
				}
				headSHA = shadow.CommitSHA
			} else {
				headSHA, err = a.cfg.WorktreeMgr.HeadSHA(ctx, sessWT.WorktreePath)
				if err != nil {
					return result, err
				}
			}
			result.HeadCommitSHA = headSHA

			// 5. Strict Context Hygiene (Invariant #5): spill >2,000-token raw outputs to disk.
			compacted, err := a.compactor.Compact(sessionID, stepIndex, tc.Name, rawOutput)
			if err != nil {
				return result, err
			}

			if err := a.cfg.Store.CreateStep(ctx, store.Step{
				ID:                newID("step"),
				SessionID:         sessionID,
				StepIndex:         stepIndex,
				GitCommitSHA:      headSHA,
				Thought:           thought,
				ToolName:          tc.Name,
				ToolInputJSON:     toolInputJSON,
				ToolOutputSummary: compacted.Summary,
				RawArtifactPath:   compacted.RawArtifactPath,
				ExitCode:          &exitCode,
				DurationMS:        turnDurationMS + time.Since(stepStart).Milliseconds(),
				TokensIn:          tokensIn,
				TokensOut:         tokensOut,
			}); err != nil {
				return result, err
			}

			// 6. Real-Time Friction Detection & Closed-Loop Evolution Compiler Trigger.
			var immediateFriction []ipc.FrictionEvent

			if exitCode != 0 {
				if consecutiveErrors == 0 {
					errorStreakStart = stepIndex
				}
				consecutiveErrors++
				if consecutiveErrors >= errorTrigger {
					key := fmt.Sprintf("err:%s:%d", tc.Name, errorStreakStart)
					if _, already := triggeredFriction[key]; !already {
						triggeredFriction[key] = struct{}{}
						cmdText := extractCommandSummary(tc.Name, tc.Input)
						ev := ipc.FrictionEvent{
							StepRange: [2]int{errorStreakStart, stepIndex},
							Pattern:   ipc.PatternRepeatedToolError,
							ToolName:  tc.Name,
							Summary: fmt.Sprintf("Agent ran '%s' %d consecutive times failing with: %s",
								cmdText, consecutiveErrors, firstErrorLine(rawOutput)),
						}
						immediateFriction = append(immediateFriction, ev)
						if a.cfg.ErrOut != nil {
							fmt.Fprintf(a.cfg.ErrOut, "[friction] %d consecutive tool errors detected (session=%s, step=%d)\n",
								consecutiveErrors, sessionID, stepIndex)
						}
					}
				}
			} else {
				consecutiveErrors = 0
				errorStreakStart = 0
			}

			if tc.Name == "write_file" || tc.Name == "edit_file" || tc.Name == "apply_patch" {
				if targetPath := extractPathFromInput(tc.Input); targetPath != "" {
					if fileEditCounts[targetPath] == 0 {
						fileEditFirstStep[targetPath] = stepIndex
					}
					fileEditCounts[targetPath]++
					if fileEditCounts[targetPath] >= errorTrigger {
						key := "circular:" + targetPath
						if _, already := triggeredFriction[key]; !already {
							triggeredFriction[key] = struct{}{}
							ev := ipc.FrictionEvent{
								StepRange: [2]int{fileEditFirstStep[targetPath], stepIndex},
								Pattern:   ipc.PatternCircularFileEdit,
								ToolName:  tc.Name,
								Summary: fmt.Sprintf("Agent edited '%s' %d times in a circular file edit loop.",
									targetPath, fileEditCounts[targetPath]),
							}
							immediateFriction = append(immediateFriction, ev)
						}
					}
				}
			}

			if len(immediateFriction) > 0 {
				if a.cfg.EvolutionClient != nil {
					if synthRes, ok := a.invokeEvolutionCompiler(ctx, sessionID, sessWT.BaseCommitSHA, immediateFriction); ok {
						result.SynthesizedEngrams = append(result.SynthesizedEngrams, synthRes)
						// Hot-reload active HookGate immediately if a shadow-verified hook became active.
						if synthRes.ShadowVerified && synthRes.Kind == string(store.EngramKindHook) && synthRes.Status == string(store.EngramStatusActive) {
							if updatedGate, reloadErr := a.reloadHookGate(ctx); reloadErr == nil {
								gate = updatedGate
							}
						}
					}
				} else {
					pendingSessionFriction = append(pendingSessionFriction, immediateFriction...)
				}
			}

			messages = append(messages, Message{
				Role:       RoleTool,
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
				Content:    compacted.Summary,
				IsError:    isError,
			})
		}
	}

	result.StepsRecorded = stepIndex
	result.ConsecutiveErrors = consecutiveErrors
	return result, ErrMaxStepsExceeded
}

func (a *AgentLoop) invokeEvolutionCompiler(
	ctx context.Context,
	sessionID, baseCommitSHA string,
	events []ipc.FrictionEvent,
) (ipc.SynthesizeResult, bool) {
	if a.cfg.EvolutionClient == nil || len(events) == 0 {
		return ipc.SynthesizeResult{}, false
	}

	synthRes, err := a.cfg.EvolutionClient.Synthesize(ctx, ipc.SynthesizeParams{
		SessionID:      sessionID,
		RepoRoot:       a.cfg.Workspace.RepoRoot,
		BaseCommitSHA:  baseCommitSHA,
		FrictionEvents: events,
	})
	if err != nil {
		if a.cfg.ErrOut != nil {
			fmt.Fprintf(a.cfg.ErrOut, "[evolution] compiler.synthesize failed: %v\n", err)
		}
		return ipc.SynthesizeResult{}, false
	}

	if a.cfg.ErrOut != nil {
		fmt.Fprintf(a.cfg.ErrOut, "[evolution] synthesized %s %s (%s, shadow_verified=%t, status=%s)\n",
			synthRes.Kind, synthRes.EngramID, synthRes.FilePath, synthRes.ShadowVerified, synthRes.Status)
	}
	return synthRes, true
}

func (a *AgentLoop) reloadHookGate(ctx context.Context) (*HookGate, error) {
	manifest := a.cfg.Manifest
	if data, err := os.ReadFile(a.cfg.Workspace.ManifestPath()); err == nil {
		var diskManifest Manifest
		if jsonErr := json.Unmarshal(data, &diskManifest); jsonErr == nil {
			manifest = diskManifest
		}
	}

	hookSpecs, err := LoadActiveHookSpecs(ctx, a.cfg.Store, manifest)
	if err != nil {
		return nil, err
	}
	return NewHookGate(HookGateConfig{
		Workspace: a.cfg.Workspace,
		Store:     a.cfg.Store,
		PythonBin: a.cfg.PythonBin,
	}, hookSpecs)
}

func (a *AgentLoop) buildScrubber() (*proxy.Scrubber, error) {
	if a.cfg.Scrubber != nil {
		return a.cfg.Scrubber, nil
	}
	if !a.cfg.Config.Sandbox.RedactSecrets {
		return nil, nil
	}

	var dotEnvSecrets []string
	envPath := filepath.Join(a.cfg.Workspace.RepoRoot, ".env")
	if secrets, err := proxy.LoadDotEnvSecrets(envPath); err == nil {
		dotEnvSecrets = append(dotEnvSecrets, secrets...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return proxy.NewScrubber(proxy.ScrubberConfig{
		AdditionalSecrets: dotEnvSecrets,
	}), nil
}

func (a *AgentLoop) mountActiveTools(ctx context.Context, host *mcp.Host) error {
	activeTools, err := a.cfg.Store.ListEngrams(ctx, store.EngramFilter{
		Status: store.EngramStatusActive,
		Kind:   store.EngramKindTool,
	})
	if err != nil {
		return fmt.Errorf("control: list active synthesized tools: %w", err)
	}
	if len(activeTools) == 0 {
		return nil
	}

	pyBin := strings.TrimSpace(a.cfg.PythonBin)
	if pyBin == "" {
		resolved, err := ResolvePythonBinary()
		if err != nil {
			return err
		}
		pyBin = resolved
	}

	for _, t := range activeTools {
		if err := host.MountSynthesizedTool(ctx, pyBin, a.cfg.Workspace.ToolsDir(), t.ID, t.FilePath); err != nil {
			return err
		}
	}
	return nil
}

func extractCommandSummary(toolName string, input json.RawMessage) string {
	var fields map[string]any
	if err := json.Unmarshal(input, &fields); err == nil {
		for _, k := range []string{"command", "cmd"} {
			if v, ok := fields[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return toolName
}

func extractPathFromInput(input json.RawMessage) string {
	var fields map[string]any
	if err := json.Unmarshal(input, &fields); err == nil {
		for _, k := range []string{"path", "file_path"} {
			if v, ok := fields[k].(string); ok && strings.TrimSpace(v) != "" {
				return filepath.ToSlash(strings.TrimSpace(v))
			}
		}
	}
	return ""
}

func firstErrorLine(output string) string {
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && !strings.HasPrefix(ln, "exit_code=") {
			if len(ln) > 180 {
				return ln[:180]
			}
			return ln
		}
	}
	return "non-zero exit code"
}

func defaultAgentSystemPrompt() string {
	return strings.TrimSpace(`
You are Engram, an autonomous software engineering agent operating inside an isolated detached Git worktree.
- Use the provided MCP tools to inspect files, edit files, and run verification commands.
- All file edits are automatically snapshotted as atomic Git commits after each step.
- If a deterministic hook blocks a tool call with exit code 2, read its guidance carefully and satisfy the prerequisite before retrying.
- If a tool output is truncated with an artifact path pointer, use read_file or targeted shell commands only if you need specific lines from that artifact.
- When the task is verified and complete, respond concisely with a summary of changes and verification results.
`)
}

func newID(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("%s_%x_%s", prefix, time.Now().UTC().UnixMilli(), hex.EncodeToString(b[:]))
}
