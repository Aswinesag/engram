package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"engram/internal/mcp"
	"engram/internal/store"
	"engram/internal/worktree"
)

const DefaultMaxSteps = 50

var (
	// ErrMaxStepsExceeded is returned when an agent session reaches its step cap.
	ErrMaxStepsExceeded = errors.New("control: agent session exceeded maximum step limit")
)

// AgentLoopConfig wires all Phase 1 deterministic runtime subsystems together.
type AgentLoopConfig struct {
	Workspace    Workspace
	Config       Config
	Manifest     Manifest
	Store        *store.Store
	Router       *ModelRouter
	WorktreeMgr  *worktree.Manager
	PythonBin    string
	MaxSteps     int
	SystemPrompt string
	Out          io.Writer
	ErrOut       io.Writer
}

// AgentRunResult summarizes a completed or terminated session.
type AgentRunResult struct {
	SessionID         string
	WorktreePath      string
	BaseCommitSHA     string
	HeadCommitSHA     string
	FinalResponse     string
	StepsRecorded     int
	ConsecutiveErrors int
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

// Run executes taskPrompt inside an isolated detached Git worktree, recording atomic
// step commits, applying deterministic pre/post Python hooks, and enforcing context hygiene.
func (a *AgentLoop) Run(ctx context.Context, taskPrompt string) (result AgentRunResult, runErr error) {
	taskPrompt = strings.TrimSpace(taskPrompt)
	if taskPrompt == "" {
		return AgentRunResult{}, errors.New("control: taskPrompt must not be empty")
	}

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

	host, err := mcp.NewHost(ctx, sessWT.WorktreePath)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = host.Close()
	}()

	if err := a.mountActiveTools(ctx, host); err != nil {
		return result, err
	}

	hookSpecs, err := LoadActiveHookSpecs(ctx, a.cfg.Store, a.cfg.Manifest)
	if err != nil {
		return result, err
	}
	gate, err := NewHookGate(HookGateConfig{
		Workspace: a.cfg.Workspace,
		Store:     a.cfg.Store,
		PythonBin: a.cfg.PythonBin,
	}, hookSpecs)
	if err != nil {
		return result, err
	}

	messages := []Message{
		{Role: RoleUser, Content: taskPrompt},
	}
	tools := host.Tools()
	stepIndex := 0
	consecutiveErrors := 0

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

		// Record assistant turn in conversation history.
		messages = append(messages, Message{
			Role:      RoleAssistant,
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		// If no tool calls were requested, record the final reasoning step and finish.
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
			// Attribute LLM turn tokens and thought to the first tool step of the turn
			// so session token sums remain exact.
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

			// 2. Execute Tool via MCP Host inside the isolated worktree.
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

			// 4. Atomic Step Shadow Commit (only commits when worktree files actually changed).
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

			if exitCode != 0 {
				consecutiveErrors++
				if a.cfg.ErrOut != nil && consecutiveErrors >= a.cfg.Config.Evolution.ConsecutiveErrorTrigger {
					fmt.Fprintf(a.cfg.ErrOut, "[friction] %d consecutive tool errors detected (session=%s, step=%d)\n",
						consecutiveErrors, sessionID, stepIndex)
				}
			} else {
				consecutiveErrors = 0
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

// Unused import guard for filepath when needed by callers.
var _ = filepath.Clean
