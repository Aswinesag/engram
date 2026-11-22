package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"engram/internal/control"
	"engram/internal/ipc"
	"engram/internal/store"
	"engram/internal/worktree"
	"engram/ui"
)

// RunRequest captures the validated inputs for `engram run`.
type RunRequest struct {
	Workspace  control.Workspace
	Config     control.Config
	Manifest   control.Manifest
	Store      *store.Store
	TaskPrompt string
	Out        io.Writer
	ErrOut     io.Writer
}

// AgentRunner executes a task inside an isolated worktree session.
type AgentRunner interface {
	Run(ctx context.Context, req RunRequest) error
}

// WorktreeRewinder resets a session's detached worktree to a target step SHA.
type WorktreeRewinder interface {
	Rewind(ctx context.Context, ws control.Workspace, sess store.Session, target store.Step) error
}

// Dependencies decouples CLI wiring from runtime subsystems during testing and rollout.
type Dependencies struct {
	Runner   AgentRunner
	Rewinder WorktreeRewinder
}

type defaultAgentRunner struct{}

func (defaultAgentRunner) Run(ctx context.Context, req RunRequest) error {
	router, err := control.NewModelRouter(req.Config.Model, "", nil)
	if err != nil {
		return err
	}

	wtMgr, err := worktree.NewManager(req.Workspace.RepoRoot, req.Workspace.WorktreesDir())
	if err != nil {
		return err
	}

	var evoClient control.EvolutionClient
	if sockPath, sockErr := ipc.SocketPathForRepo(req.Workspace.RepoRoot); sockErr == nil {
		candidate := ipc.NewClient(sockPath, 0)
		pingCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		_, pingErr := candidate.Ping(pingCtx)
		cancel()

		if pingErr == nil {
			evoClient = candidate
		} else if compilerDir := strings.TrimSpace(os.Getenv("ENGRAM_COMPILER_DIR")); compilerDir != "" {
			if pyBin, pyErr := control.ResolvePythonBinary(); pyErr == nil {
				if sidecar, scErr := ipc.StartSidecar(ctx, pyBin, compilerDir, sockPath); scErr == nil {
					defer func() { _ = sidecar.Stop() }()
					evoClient = sidecar.Client()
				}
			}
		}
	}

	loop, err := control.NewAgentLoop(control.AgentLoopConfig{
		Workspace:       req.Workspace,
		Config:          req.Config,
		Manifest:        req.Manifest,
		Store:           req.Store,
		Router:          router,
		WorktreeMgr:     wtMgr,
		EvolutionClient: evoClient,
		Out:             req.Out,
		ErrOut:          req.ErrOut,
	})
	if err != nil {
		return err
	}

	res, err := loop.Run(ctx, req.TaskPrompt)
	if err != nil {
		if res.SessionID != "" && req.ErrOut != nil {
			fmt.Fprintf(req.ErrOut, "\nSession %s terminated (head: %s, worktree: %s)\n",
				res.SessionID, shortSHA(res.HeadCommitSHA), res.WorktreePath)
		}
		return err
	}

	if req.Out != nil {
		fmt.Fprintf(req.Out, "\nSession: %s (steps: %d, head: %s, worktree: %s)\n",
			res.SessionID, res.StepsRecorded, shortSHA(res.HeadCommitSHA), res.WorktreePath)
	}
	return nil
}

type defaultWorktreeRewinder struct{}

func (defaultWorktreeRewinder) Rewind(ctx context.Context, ws control.Workspace, sess store.Session, target store.Step) error {
	mgr, err := worktree.NewManager(ws.RepoRoot, ws.WorktreesDir())
	if err != nil {
		return err
	}
	return mgr.Rewind(ctx, sess.WorktreePath, target.GitCommitSHA)
}

func defaultDependencies() Dependencies {
	return Dependencies{
		Runner:   defaultAgentRunner{},
		Rewinder: defaultWorktreeRewinder{},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := NewRootCmd(defaultDependencies())
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// NewRootCmd constructs the Engram Cobra command tree.
func NewRootCmd(deps Dependencies) *cobra.Command {
	if deps.Runner == nil {
		deps.Runner = defaultAgentRunner{}
	}
	if deps.Rewinder == nil {
		deps.Rewinder = defaultWorktreeRewinder{}
	}

	var repoDir string

	root := &cobra.Command{
		Use:           "engram",
		Short:         "Self-evolving local agent runtime & deterministic harness compiler",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&repoDir, "repo", ".", "path inside the target Git repository")

	root.AddCommand(
		newInitCmd(&repoDir),
		newStatusCmd(&repoDir),
		newRewindCmd(&repoDir, deps.Rewinder),
		newRunCmd(&repoDir, deps.Runner),
		newUICmd(&repoDir),
		newRulesCmd(&repoDir),
	)

	return root
}

func newInitCmd(repoDir *string) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a Git-trackable .engram/ workspace and SQLite WAL state store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ws, err := control.InitWorkspace(cmd.Context(), *repoDir, force)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Initialized Engram workspace in %s\n", ws.EngramDir())
			fmt.Fprintf(out, "  config:    %s\n", ws.ConfigPath())
			fmt.Fprintf(out, "  manifest:  %s\n", ws.ManifestPath())
			fmt.Fprintf(out, "  state db:  %s (SQLite WAL)\n", ws.StateDBPath())
			fmt.Fprintf(out, "  runtime:   %s (git-ignored)\n", ws.RuntimeDir())
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config.toml and manifest.json with defaults")
	return cmd
}

func newStatusCmd(repoDir *string) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show workspace configuration, compiled engrams, and recent sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			ws, cfg, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}

			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			sessions, err := st.ListSessions(ctx, limit)
			if err != nil {
				return err
			}
			activeEngrams, err := st.ListEngrams(ctx, store.EngramFilter{Status: store.EngramStatusActive})
			if err != nil {
				return err
			}
			pendingEngrams, err := st.ListEngrams(ctx, store.EngramFilter{Status: store.EngramStatusPendingApproval})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Repository: %s\n", ws.RepoRoot)
			fmt.Fprintf(out, "Model:      %s (%s)\n", cfg.Model.Model, cfg.Model.Provider)
			fmt.Fprintf(out, "Sandbox:    %s (redact_secrets=%t)\n", cfg.Sandbox.Mode, cfg.Sandbox.RedactSecrets)
			fmt.Fprintf(out, "Engrams:    %d active, %d pending approval\n", len(activeEngrams), len(pendingEngrams))

			if len(sessions) == 0 {
				fmt.Fprintln(out, "\nSessions:   none")
				return nil
			}

			fmt.Fprintln(out, "\nRecent Sessions:")
			tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tSTEP\tHEAD SHA\tTASK")
			for _, sess := range sessions {
				stepStr := "0"
				headSHA := shortSHA(sess.BaseCommitSHA)
				latest, err := st.LatestStep(ctx, sess.ID)
				if err == nil {
					stepStr = fmt.Sprintf("%d", latest.StepIndex)
					headSHA = shortSHA(latest.GitCommitSHA)
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					sess.ID,
					sess.Status,
					stepStr,
					headSHA,
					truncate(sess.TaskPrompt, 60),
				)
			}
			return tw.Flush()
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 10, "maximum number of recent sessions to display")
	return cmd
}

func newRewindCmd(repoDir *string, rewinder WorktreeRewinder) *cobra.Command {
	var stepIndex int

	cmd := &cobra.Command{
		Use:   "rewind <session-id>",
		Short: "Rewind an isolated session worktree to a recorded step commit SHA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if stepIndex < 0 {
				return errors.New("step index must be >= 0")
			}

			ctx := cmd.Context()
			sessionID := args[0]

			ws, _, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}

			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			sess, err := st.GetSession(ctx, sessionID)
			if err != nil {
				return fmt.Errorf("load session %q: %w", sessionID, err)
			}

			targetStep, err := st.GetStepByIndex(ctx, sessionID, stepIndex)
			if err != nil {
				return fmt.Errorf("load step %d for session %q: %w", stepIndex, sessionID, err)
			}

			if err := rewinder.Rewind(ctx, ws, sess, targetStep); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Rewound session %s to step %d (%s)\n",
				sess.ID, targetStep.StepIndex, shortSHA(targetStep.GitCommitSHA))
			return nil
		},
	}

	cmd.Flags().IntVar(&stepIndex, "step", -1, "target step index to rewind to (required)")
	_ = cmd.MarkFlagRequired("step")
	return cmd
}

func newRunCmd(repoDir *string, runner AgentRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <task-prompt>",
		Short: "Run an autonomous agent session inside an isolated detached Git worktree",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			taskPrompt := strings.TrimSpace(strings.Join(args, " "))
			if taskPrompt == "" {
				return errors.New("task prompt must not be empty")
			}

			ws, cfg, manifest, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}

			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			return runner.Run(ctx, RunRequest{
				Workspace:  ws,
				Config:     cfg,
				Manifest:   manifest,
				Store:      st,
				TaskPrompt: taskPrompt,
				Out:        cmd.OutOrStdout(),
				ErrOut:     cmd.ErrOrStderr(),
			})
		},
	}

	return cmd
}

func newUICmd(repoDir *string) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Launch the embedded Observability & Time-Travel Web UI",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			ws, cfg, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}

			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			wtMgr, err := worktree.NewManager(ws.RepoRoot, ws.WorktreesDir())
			if err != nil {
				return err
			}

			distFS, err := ui.DistFS()
			if err != nil {
				return fmt.Errorf("load embedded UI assets: %w", err)
			}

			uiSrv, err := control.NewUIServer(control.UIServerConfig{
				Workspace:   ws,
				Config:      cfg,
				Store:       st,
				WorktreeMgr: wtMgr,
				StaticFS:    distFS,
			})
			if err != nil {
				return err
			}

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", addr, err)
			}

			srv := &http.Server{
				Handler:           uiSrv.Handler(),
				ReadHeaderTimeout: 15 * time.Second,
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Engram UI listening at http://%s (WebSocket: ws://%s/ws)\n",
				ln.Addr().String(), ln.Addr().String())

			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.Serve(ln)
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
				return nil
			case err := <-errCh:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			}
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7420", "local listen address for the Observability UI")
	return cmd
}

func newRulesCmd(repoDir *string) *cobra.Command {
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect, approve, or reject compiled engrams (hooks, tools, and scoped rules)",
	}

	var statusFilter, kindFilter string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List compiled engrams in SQLite",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			ws, _, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}
			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			engrams, err := st.ListEngrams(ctx, store.EngramFilter{
				Status: store.EngramStatus(strings.TrimSpace(statusFilter)),
				Kind:   store.EngramKind(strings.TrimSpace(kindFilter)),
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if len(engrams) == 0 {
				fmt.Fprintln(out, "No engrams found.")
				return nil
			}

			tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tKIND\tSTATUS\tSHADOW\tPREVENTED\tTRIGGER\tPATH")
			for _, e := range engrams {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%.0f%%\t%d/%d\t%s\t%s\n",
					e.ID, e.Kind, e.Status, e.ShadowPassRate*100,
					e.TimesPreventedError, e.TimesTriggered,
					truncate(e.TriggerPattern, 24), e.FilePath)
			}
			return tw.Flush()
		},
	}
	listCmd.Flags().StringVar(&statusFilter, "status", "", "filter by status (shadow_testing, pending_approval, active, rejected)")
	listCmd.Flags().StringVar(&kindFilter, "kind", "", "filter by kind (hook, tool, rule)")

	showCmd := &cobra.Command{
		Use:   "show <engram-id>",
		Short: "Display human-auditable metadata and source code for an engram",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ws, _, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}
			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			eng, err := st.GetEngram(ctx, args[0])
			if err != nil {
				return err
			}
			src, err := control.ReadEngramSource(ws, eng.FilePath)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ID:        %s\nKind:      %s\nStatus:    %s\nTrigger:   %s\nShadow:    %.0f%%\nFile:      %s\n\n%s",
				eng.ID, eng.Kind, eng.Status, eng.TriggerPattern, eng.ShadowPassRate*100, eng.FilePath, src)
			if !strings.HasSuffix(src, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	approveCmd := &cobra.Command{
		Use:   "approve <engram-id>",
		Short: "Approve and activate a shadow-verified engram",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ws, _, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}
			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			eng, err := control.ApproveEngram(ctx, ws, st, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Approved engram %s (status=%s)\n", eng.ID, eng.Status)
			return nil
		},
	}

	rejectCmd := &cobra.Command{
		Use:   "reject <engram-id>",
		Short: "Reject an engram so it is excluded from runtime activation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ws, _, _, err := control.LoadWorkspace(ctx, *repoDir)
			if err != nil {
				return err
			}
			st, err := store.Open(ctx, ws.StateDBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			eng, err := control.RejectEngram(ctx, ws, st, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Rejected engram %s (status=%s)\n", eng.ID, eng.Status)
			return nil
		},
	}

	rulesCmd.AddCommand(listCmd, showCmd, approveCmd, rejectCmd)
	return rulesCmd
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
