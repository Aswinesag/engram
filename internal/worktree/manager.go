package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// ErrUnsafeWorktreePath enforces Invariant #1 (Zero Host Filesystem Mutation):
	// mutating operations are rejected unless the target path is strictly inside
	// the managed .engram/.runtime/worktrees/ directory.
	ErrUnsafeWorktreePath = errors.New("worktree: target path is outside managed worktrees directory")

	// ErrInvalidSessionID is returned when a session ID is empty or contains path separators.
	ErrInvalidSessionID = errors.New("worktree: invalid session id")

	// ErrInvalidCommit is returned when a commit reference or SHA cannot be resolved.
	ErrInvalidCommit = errors.New("worktree: invalid git commit reference")
)

// SessionWorktree describes an active isolated detached Git worktree.
type SessionWorktree struct {
	SessionID     string
	RepoRoot      string
	WorktreePath  string
	BaseCommitSHA string
}

// ShadowCommit captures the result of an atomic step-level commit inside a worktree.
type ShadowCommit struct {
	CommitSHA string
	Changed   bool
}

// Manager orchestrates isolated detached Git worktrees, atomic step shadow
// commits, and SHA-based time-travel rewinds.
type Manager struct {
	repoRoot     string
	worktreesDir string
}

// NewManager constructs a Manager bound to a repository root and its managed
// worktrees directory (typically <repoRoot>/.engram/.runtime/worktrees).
func NewManager(repoRoot, worktreesDir string) (*Manager, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return nil, errors.New("worktree: repoRoot must not be empty")
	}
	if strings.TrimSpace(worktreesDir) == "" {
		return nil, errors.New("worktree: worktreesDir must not be empty")
	}

	canonRepo, err := canonicalizePath(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("worktree: canonicalize repoRoot: %w", err)
	}
	canonWorktrees, err := canonicalizePath(worktreesDir)
	if err != nil {
		return nil, fmt.Errorf("worktree: canonicalize worktreesDir: %w", err)
	}

	if samePath(canonRepo, canonWorktrees) {
		return nil, fmt.Errorf("%w: worktreesDir cannot equal repoRoot", ErrUnsafeWorktreePath)
	}

	return &Manager{
		repoRoot:     canonRepo,
		worktreesDir: canonWorktrees,
	}, nil
}

// RepoRoot returns the canonical repository root path.
func (m *Manager) RepoRoot() string { return m.repoRoot }

// WorktreesDir returns the canonical managed worktrees directory path.
func (m *Manager) WorktreesDir() string { return m.worktreesDir }

// Create provisions a detached Git worktree (`git worktree add --detach`) for
// sessionID at baseRef (defaulting to HEAD when baseRef is empty).
func (m *Manager) Create(ctx context.Context, sessionID, baseRef string) (SessionWorktree, error) {
	if err := validateSessionID(sessionID); err != nil {
		return SessionWorktree{}, err
	}
	if strings.TrimSpace(baseRef) == "" {
		baseRef = "HEAD"
	}

	baseSHA, err := m.resolveCommit(ctx, m.repoRoot, baseRef)
	if err != nil {
		return SessionWorktree{}, err
	}

	if err := os.MkdirAll(m.worktreesDir, 0o755); err != nil {
		return SessionWorktree{}, fmt.Errorf("worktree: create worktrees dir: %w", err)
	}

	wtPath := filepath.Join(m.worktreesDir, sessionID)
	if err := m.ensureManagedPath(wtPath); err != nil {
		return SessionWorktree{}, err
	}

	if _, err := os.Stat(wtPath); err == nil {
		return SessionWorktree{}, fmt.Errorf("worktree: path %q already exists", wtPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return SessionWorktree{}, fmt.Errorf("worktree: stat %q: %w", wtPath, err)
	}

	if _, err := runGit(ctx, m.repoRoot, nil, "worktree", "add", "--detach", wtPath, baseSHA); err != nil {
		return SessionWorktree{}, fmt.Errorf("worktree: create detached worktree for %q: %w", sessionID, err)
	}

	canonWT, err := canonicalizePath(wtPath)
	if err != nil {
		return SessionWorktree{}, fmt.Errorf("worktree: canonicalize worktree path: %w", err)
	}

	return SessionWorktree{
		SessionID:     sessionID,
		RepoRoot:      m.repoRoot,
		WorktreePath:  canonWT,
		BaseCommitSHA: baseSHA,
	}, nil
}

// CommitStep stages all modifications inside worktreePath and creates an atomic
// shadow commit. If the worktree working tree is clean, it returns the current
// HEAD SHA with Changed=false.
func (m *Manager) CommitStep(ctx context.Context, worktreePath string, stepIndex int, message string) (ShadowCommit, error) {
	if err := m.ensureManagedPath(worktreePath); err != nil {
		return ShadowCommit{}, err
	}

	statusOut, err := runGit(ctx, worktreePath, nil, "status", "--porcelain")
	if err != nil {
		return ShadowCommit{}, fmt.Errorf("worktree: check status: %w", err)
	}

	if strings.TrimSpace(statusOut) == "" {
		headSHA, err := m.HeadSHA(ctx, worktreePath)
		if err != nil {
			return ShadowCommit{}, err
		}
		return ShadowCommit{CommitSHA: headSHA, Changed: false}, nil
	}

	if _, err := runGit(ctx, worktreePath, nil, "add", "-A"); err != nil {
		return ShadowCommit{}, fmt.Errorf("worktree: stage step %d changes: %w", stepIndex, err)
	}

	commitMsg := strings.TrimSpace(message)
	if commitMsg == "" {
		commitMsg = fmt.Sprintf("engram: shadow step %d", stepIndex)
	}

	gitEnv := []string{
		"GIT_AUTHOR_NAME=Engram Runtime",
		"GIT_AUTHOR_EMAIL=engram@local",
		"GIT_COMMITTER_NAME=Engram Runtime",
		"GIT_COMMITTER_EMAIL=engram@local",
	}
	if _, err := runGit(ctx, worktreePath, gitEnv, "commit", "--no-verify", "-m", commitMsg); err != nil {
		return ShadowCommit{}, fmt.Errorf("worktree: commit step %d: %w", stepIndex, err)
	}

	headSHA, err := m.HeadSHA(ctx, worktreePath)
	if err != nil {
		return ShadowCommit{}, err
	}
	return ShadowCommit{CommitSHA: headSHA, Changed: true}, nil
}

// Rewind resets a managed detached worktree back to targetCommitSHA and removes
// any untracked files created in subsequent steps.
func (m *Manager) Rewind(ctx context.Context, worktreePath, targetCommitSHA string) error {
	if err := m.ensureManagedPath(worktreePath); err != nil {
		return err
	}
	if strings.TrimSpace(targetCommitSHA) == "" {
		return fmt.Errorf("%w: empty target commit SHA", ErrInvalidCommit)
	}

	resolvedSHA, err := m.resolveCommit(ctx, worktreePath, targetCommitSHA)
	if err != nil {
		return err
	}

	if _, err := runGit(ctx, worktreePath, nil, "reset", "--hard", resolvedSHA); err != nil {
		return fmt.Errorf("worktree: reset to %s: %w", resolvedSHA, err)
	}
	if _, err := runGit(ctx, worktreePath, nil, "clean", "-fd"); err != nil {
		return fmt.Errorf("worktree: clean untracked files after reset: %w", err)
	}
	return nil
}

// HeadSHA returns the current HEAD commit SHA of worktreePath.
func (m *Manager) HeadSHA(ctx context.Context, worktreePath string) (string, error) {
	if err := m.ensureManagedPath(worktreePath); err != nil {
		return "", err
	}
	out, err := runGit(ctx, worktreePath, nil, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("worktree: read HEAD SHA: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// Diff returns the unified git diff between two commit SHAs inside the repository.
func (m *Manager) Diff(ctx context.Context, worktreePath, fromSHA, toSHA string) (string, error) {
	if err := m.ensureManagedPath(worktreePath); err != nil {
		return "", err
	}
	fromResolved, err := m.resolveCommit(ctx, worktreePath, fromSHA)
	if err != nil {
		return "", err
	}
	toResolved, err := m.resolveCommit(ctx, worktreePath, toSHA)
	if err != nil {
		return "", err
	}
	out, err := runGit(ctx, worktreePath, nil, "diff", fromResolved, toResolved)
	if err != nil {
		return "", fmt.Errorf("worktree: diff %s..%s: %w", fromResolved, toResolved, err)
	}
	return out, nil
}

// Remove deletes a detached worktree and prunes stale Git worktree metadata.
func (m *Manager) Remove(ctx context.Context, worktreePath string) error {
	if err := m.ensureManagedPath(worktreePath); err != nil {
		return err
	}

	if _, err := runGit(ctx, m.repoRoot, nil, "worktree", "remove", "--force", worktreePath); err != nil {
		return fmt.Errorf("worktree: remove %q: %w", worktreePath, err)
	}
	if _, err := runGit(ctx, m.repoRoot, nil, "worktree", "prune"); err != nil {
		return fmt.Errorf("worktree: prune metadata: %w", err)
	}
	return nil
}

func (m *Manager) resolveCommit(ctx context.Context, dir, ref string) (string, error) {
	out, err := runGit(ctx, dir, nil, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%w (%s): %v", ErrInvalidCommit, ref, err)
	}
	sha := strings.TrimSpace(out)
	if sha == "" {
		return "", fmt.Errorf("%w: empty resolved SHA for %q", ErrInvalidCommit, ref)
	}
	return sha, nil
}

func (m *Manager) ensureManagedPath(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("%w: empty worktree path", ErrUnsafeWorktreePath)
	}
	canonTarget, err := canonicalizePath(target)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeWorktreePath, err)
	}
	if samePath(canonTarget, m.repoRoot) || samePath(canonTarget, m.worktreesDir) {
		return ErrUnsafeWorktreePath
	}

	rel, err := filepath.Rel(m.worktreesDir, canonTarget)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeWorktreePath, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: %q is not inside %q", ErrUnsafeWorktreePath, canonTarget, m.worktreesDir)
	}
	return nil
}

func validateSessionID(sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return ErrInvalidSessionID
	}
	if sessionID == "." || sessionID == ".." || strings.ContainsAny(sessionID, `/\`) {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	return nil
}

func runGit(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = strings.TrimSpace(stdout.String())
		}
		if errMsg != "" {
			return "", fmt.Errorf("git %s: %s (%w)", strings.Join(args, " "), errMsg, err)
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

func canonicalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	// Walk upward until an existing ancestor is found so EvalSymlinks resolves
	// platform symlinks (e.g. macOS /var -> /private/var) even for new paths.
	cur := abs
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			parts := append([]string{resolved}, tail...)
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return abs, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
