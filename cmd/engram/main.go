package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"engram/internal/control"
	"engram/internal/store"
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

// Dependencies decouples CLI wiring from runtime subsystems during incremental phase rollout.
type Dependencies struct {
	Runner   AgentRunner
	Rewinder WorktreeRewinder
}

func main() {
	cmd := NewRootCmd(Dependencies{})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// NewRootCmd constructs the Engram Cobra command tree.
func NewRootCmd(deps Dependencies) *cobra.Command {
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

			if rewinder == nil {
				return fmt.Errorf("worktree rewinder is not configured (target commit %s)", targetStep.GitCommitSHA)
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

			if runner == nil {
				return errors.New("agent runtime is not configured")
			}

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
