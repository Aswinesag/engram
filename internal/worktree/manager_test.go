package worktree

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initTestRepo(t *testing.T) (repoRoot, worktreesDir string) {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	run("init")
	run("config", "user.email", "test@engram.local")
	run("config", "user.name", "Engram Test")
	run("config", "core.autocrlf", "false")

	if err := os.WriteFile(filepath.Join(dir, "app.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatalf("write app.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".engram/.runtime/\n"), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}
	run("add", "app.txt", ".gitignore")
	run("commit", "-m", "initial commit")

	worktreesDir = filepath.Join(dir, ".engram", ".runtime", "worktrees")
	return dir, worktreesDir
}

func TestCreateDetachedWorktreeIsolatesHostWorkingTree(t *testing.T) {
	ctx := context.Background()
	repoRoot, wtDir := initTestRepo(t)

	mgr, err := NewManager(repoRoot, wtDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	sessWT, err := mgr.Create(ctx, "sess_01J9W8K2", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_ = mgr.Remove(ctx, sessWT.WorktreePath)
	})

	if sessWT.BaseCommitSHA == "" {
		t.Fatalf("expected non-empty BaseCommitSHA")
	}

	// Worktree must be detached (symbolic-ref HEAD fails on detached HEAD).
	symRef := exec.Command("git", "-C", sessWT.WorktreePath, "symbolic-ref", "-q", "HEAD")
	if err := symRef.Run(); err == nil {
		t.Fatalf("expected worktree HEAD to be detached")
	}

	// Mutating a file in the worktree must NOT mutate the host repository.
	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "app.txt"), []byte("v2-in-worktree\n"), 0o644); err != nil {
		t.Fatalf("write worktree app.txt: %v", err)
	}
	hostBytes, err := os.ReadFile(filepath.Join(repoRoot, "app.txt"))
	if err != nil {
		t.Fatalf("read host app.txt: %v", err)
	}
	if string(hostBytes) != "v1\n" {
		t.Fatalf("host app.txt mutated = %q, want %q", string(hostBytes), "v1\n")
	}
}

func TestCommitStepRewindAndDiff(t *testing.T) {
	ctx := context.Background()
	repoRoot, wtDir := initTestRepo(t)

	mgr, err := NewManager(repoRoot, wtDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	sessWT, err := mgr.Create(ctx, "sess_steps_1", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_ = mgr.Remove(ctx, sessWT.WorktreePath)
	})

	// Step 1: clean worktree -> no commit created, Changed == false.
	step1, err := mgr.CommitStep(ctx, sessWT.WorktreePath, 1, "read-only step")
	if err != nil {
		t.Fatalf("CommitStep(1) error = %v", err)
	}
	if step1.Changed {
		t.Fatalf("CommitStep(1).Changed = true, want false")
	}
	if step1.CommitSHA != sessWT.BaseCommitSHA {
		t.Fatalf("CommitStep(1).CommitSHA = %q, want %q", step1.CommitSHA, sessWT.BaseCommitSHA)
	}

	// Step 2: modify tracked file -> shadow commit created.
	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "app.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatalf("write app.txt: %v", err)
	}
	step2, err := mgr.CommitStep(ctx, sessWT.WorktreePath, 2, "update app.txt to v2")
	if err != nil {
		t.Fatalf("CommitStep(2) error = %v", err)
	}
	if !step2.Changed || step2.CommitSHA == step1.CommitSHA {
		t.Fatalf("CommitStep(2) = %+v, expected new commit SHA", step2)
	}

	// Step 3: modify tracked file AND create a new untracked-until-staged file.
	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "app.txt"), []byte("v3\n"), 0o644); err != nil {
		t.Fatalf("write app.txt v3: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "extra.txt"), []byte("extra\n"), 0o644); err != nil {
		t.Fatalf("write extra.txt: %v", err)
	}
	step3, err := mgr.CommitStep(ctx, sessWT.WorktreePath, 3, "add extra.txt and v3")
	if err != nil {
		t.Fatalf("CommitStep(3) error = %v", err)
	}
	if !step3.Changed || step3.CommitSHA == step2.CommitSHA {
		t.Fatalf("CommitStep(3) = %+v, expected new commit SHA", step3)
	}

	// Diff between step2 and step3 must show extra.txt and v3.
	diffText, err := mgr.Diff(ctx, sessWT.WorktreePath, step2.CommitSHA, step3.CommitSHA)
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}
	if !strings.Contains(diffText, "extra.txt") || !strings.Contains(diffText, "+v3") {
		t.Fatalf("unexpected diff output:\n%s", diffText)
	}

	// Leave an uncommitted untracked scratch file before rewinding to step 2.
	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "scratch.tmp"), []byte("tmp\n"), 0o644); err != nil {
		t.Fatalf("write scratch.tmp: %v", err)
	}

	// Rewind to step 2.
	if err := mgr.Rewind(ctx, sessWT.WorktreePath, step2.CommitSHA); err != nil {
		t.Fatalf("Rewind(step2) error = %v", err)
	}

	headAfterRewind, err := mgr.HeadSHA(ctx, sessWT.WorktreePath)
	if err != nil {
		t.Fatalf("HeadSHA() error = %v", err)
	}
	if headAfterRewind != step2.CommitSHA {
		t.Fatalf("HEAD after rewind = %q, want %q", headAfterRewind, step2.CommitSHA)
	}

	appBytes, err := os.ReadFile(filepath.Join(sessWT.WorktreePath, "app.txt"))
	if err != nil {
		t.Fatalf("read app.txt after rewind: %v", err)
	}
	if string(appBytes) != "v2\n" {
		t.Fatalf("app.txt after rewind = %q, want %q", string(appBytes), "v2\n")
	}

	for _, removedFile := range []string{"extra.txt", "scratch.tmp"} {
		if _, err := os.Stat(filepath.Join(sessWT.WorktreePath, removedFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %q to be removed after rewind, stat err = %v", removedFile, err)
		}
	}

	// Host working tree must remain untouched throughout.
	hostBytes, err := os.ReadFile(filepath.Join(repoRoot, "app.txt"))
	if err != nil {
		t.Fatalf("read host app.txt: %v", err)
	}
	if string(hostBytes) != "v1\n" {
		t.Fatalf("host app.txt mutated = %q, want %q", string(hostBytes), "v1\n")
	}
}

func TestRemoveCleansWorktreeMetadata(t *testing.T) {
	ctx := context.Background()
	repoRoot, wtDir := initTestRepo(t)

	mgr, err := NewManager(repoRoot, wtDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	sessWT, err := mgr.Create(ctx, "sess_remove_1", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := mgr.Remove(ctx, sessWT.WorktreePath); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	if _, err := os.Stat(sessWT.WorktreePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected worktree dir to be removed, stat err = %v", err)
	}

	listOut, err := exec.Command("git", "-C", repoRoot, "worktree", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("git worktree list failed: %v", err)
	}
	if strings.Contains(string(listOut), "sess_remove_1") {
		t.Fatalf("stale worktree still present in git worktree list:\n%s", string(listOut))
	}
}

func TestInvariant1BlocksHostRepoMutation(t *testing.T) {
	ctx := context.Background()
	repoRoot, wtDir := initTestRepo(t)

	mgr, err := NewManager(repoRoot, wtDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if _, err := mgr.Create(ctx, "../escape", ""); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("Create(../escape) err = %v, want ErrInvalidSessionID", err)
	}

	for _, unsafePath := range []string{repoRoot, wtDir, filepath.Dir(repoRoot)} {
		if _, err := mgr.CommitStep(ctx, unsafePath, 1, "bad"); !errors.Is(err, ErrUnsafeWorktreePath) {
			t.Fatalf("CommitStep(%q) err = %v, want ErrUnsafeWorktreePath", unsafePath, err)
		}
		if err := mgr.Rewind(ctx, unsafePath, "HEAD"); !errors.Is(err, ErrUnsafeWorktreePath) {
			t.Fatalf("Rewind(%q) err = %v, want ErrUnsafeWorktreePath", unsafePath, err)
		}
		if err := mgr.Remove(ctx, unsafePath); !errors.Is(err, ErrUnsafeWorktreePath) {
			t.Fatalf("Remove(%q) err = %v, want ErrUnsafeWorktreePath", unsafePath, err)
		}
	}
}
