package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"engram/internal/control"
	"engram/internal/store"
	"engram/internal/worktree"
)

func initTempGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	runGit("init")
	runGit("config", "user.email", "engram-test@local")
	runGit("config", "user.name", "Engram Test")
	runGit("config", "core.autocrlf", "false")

	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("# test repo\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGit("add", "README.md")
	runGit("commit", "-m", "initial commit")
	return dir
}

func executeCLI(deps Dependencies, args ...string) (string, error) {
	cmd := NewRootCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestCLIInitCreatesWorkspaceAndGitIgnoresRuntime(t *testing.T) {
	repo := initTempGitRepo(t)

	out, err := executeCLI(Dependencies{}, "init", "--repo", repo)
	if err != nil {
		t.Fatalf("engram init error = %v\noutput:\n%s", err, out)
	}

	ws := control.Workspace{RepoRoot: repo}
	expectedPaths := []string{
		ws.ConfigPath(),
		ws.ManifestPath(),
		ws.HooksDir(),
		ws.ToolsDir(),
		ws.RulesDir(),
		ws.StateDBPath(),
		ws.ArtifactsDir(),
		ws.WorktreesDir(),
	}
	for _, p := range expectedPaths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %q to exist: %v", p, err)
		}
	}

	checkRuntime := exec.Command("git", "-C", repo, "check-ignore", ".engram/.runtime/state.db")
	if err := checkRuntime.Run(); err != nil {
		t.Fatalf("expected .engram/.runtime/state.db to be git-ignored: %v", err)
	}
	checkConfig := exec.Command("git", "-C", repo, "check-ignore", ".engram/config.toml")
	if err := checkConfig.Run(); err == nil {
		t.Fatalf("expected .engram/config.toml to be git-trackable, but git check-ignore matched it")
	}

	st, err := store.Open(context.Background(), ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	mode, err := st.JournalMode(context.Background())
	_ = st.Close()
	if err != nil || mode != "wal" {
		t.Fatalf("JournalMode() = %q, err = %v; want wal", mode, err)
	}

	customMarker := "# custom-marker\n"
	origCfg, err := os.ReadFile(ws.ConfigPath())
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	if err := os.WriteFile(ws.ConfigPath(), append(origCfg, []byte(customMarker)...), 0o644); err != nil {
		t.Fatalf("update config.toml: %v", err)
	}
	if _, err := executeCLI(Dependencies{}, "init", "--repo", repo); err != nil {
		t.Fatalf("second engram init error = %v", err)
	}
	afterCfg, err := os.ReadFile(ws.ConfigPath())
	if err != nil {
		t.Fatalf("read config.toml after re-init: %v", err)
	}
	if !strings.Contains(string(afterCfg), customMarker) {
		t.Fatalf("re-running init without --force overwrote config.toml")
	}
}

func TestCLIStatusDisplaysSessionsAndEngrams(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(Dependencies{}, "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	ws := control.Workspace{RepoRoot: repo}
	ctx := context.Background()
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}

	if err := st.CreateSession(ctx, store.Session{
		ID:            "sess_01J9W8K2",
		TaskPrompt:    "Add pagination tests for payments API",
		BaseCommitSHA: "a1b2c3d4e5f6",
		WorktreePath:  filepath.Join(ws.WorktreesDir(), "sess_01J9W8K2"),
		Status:        store.SessionCompleted,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := st.CreateStep(ctx, store.Step{
		ID:           "step_1",
		SessionID:    "sess_01J9W8K2",
		StepIndex:    1,
		GitCommitSHA: "deadbeef1234",
		ToolName:     "bash",
	}); err != nil {
		t.Fatalf("CreateStep() error = %v", err)
	}
	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_manual_1",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/check_db.py",
		FailureSignature: "manual_check_db",
		Status:           store.EngramStatusActive,
	}); err != nil {
		t.Fatalf("CreateEngram() error = %v", err)
	}
	_ = st.Close()

	out, err := executeCLI(Dependencies{}, "status", "--repo", repo)
	if err != nil {
		t.Fatalf("engram status error = %v\noutput:\n%s", err, out)
	}

	for _, want := range []string{
		"sess_01J9W8K2",
		"completed",
		"deadbeef",
		"1 active, 0 pending approval",
		"native",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

type fakeRewinder struct {
	called bool
	sess   store.Session
	target store.Step
}

func (f *fakeRewinder) Rewind(_ context.Context, _ control.Workspace, sess store.Session, target store.Step) error {
	f.called = true
	f.sess = sess
	f.target = target
	return nil
}

func TestCLIRewindLooksUpStepSHAAndInvokesRewinder(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(Dependencies{}, "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	ws := control.Workspace{RepoRoot: repo}
	ctx := context.Background()
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	if err := st.CreateSession(ctx, store.Session{
		ID:            "sess_rewind_1",
		TaskPrompt:    "Refactor parser",
		BaseCommitSHA: "0000aaaa",
		WorktreePath:  filepath.Join(ws.WorktreesDir(), "sess_rewind_1"),
		Status:        store.SessionRunning,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := st.CreateStep(ctx, store.Step{
		ID:           "step_1",
		SessionID:    "sess_rewind_1",
		StepIndex:    1,
		GitCommitSHA: "1111bbbb2222",
	}); err != nil {
		t.Fatalf("CreateStep() error = %v", err)
	}
	_ = st.Close()

	rewinder := &fakeRewinder{}
	out, err := executeCLI(Dependencies{Rewinder: rewinder}, "rewind", "sess_rewind_1", "--step", "1", "--repo", repo)
	if err != nil {
		t.Fatalf("engram rewind error = %v\noutput:\n%s", err, out)
	}
	if !rewinder.called {
		t.Fatalf("expected rewinder.Rewind to be called")
	}
	if rewinder.target.GitCommitSHA != "1111bbbb2222" {
		t.Fatalf("rewinder target SHA = %q, want %q", rewinder.target.GitCommitSHA, "1111bbbb2222")
	}
	if !strings.Contains(out, "1111bbbb") {
		t.Fatalf("rewind output missing short SHA:\n%s", out)
	}
}

func TestCLIRewindIntegrationWithWorktreeManager(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(Dependencies{}, "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	ws := control.Workspace{RepoRoot: repo}
	ctx := context.Background()

	mgr, err := worktree.NewManager(ws.RepoRoot, ws.WorktreesDir())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	const sessID = "sess_wt_rewind"
	sessWT, err := mgr.Create(ctx, sessID, "")
	if err != nil {
		t.Fatalf("mgr.Create() error = %v", err)
	}
	t.Cleanup(func() {
		_ = mgr.Remove(ctx, sessWT.WorktreePath)
	})

	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "README.md"), []byte("# step 1\n"), 0o644); err != nil {
		t.Fatalf("write step 1 README: %v", err)
	}
	step1Commit, err := mgr.CommitStep(ctx, sessWT.WorktreePath, 1, "step 1")
	if err != nil {
		t.Fatalf("CommitStep(1) error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(sessWT.WorktreePath, "README.md"), []byte("# step 2\n"), 0o644); err != nil {
		t.Fatalf("write step 2 README: %v", err)
	}
	step2Commit, err := mgr.CommitStep(ctx, sessWT.WorktreePath, 2, "step 2")
	if err != nil {
		t.Fatalf("CommitStep(2) error = %v", err)
	}

	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	if err := st.CreateSession(ctx, store.Session{
		ID:            sessID,
		TaskPrompt:    "Test real rewind",
		BaseCommitSHA: sessWT.BaseCommitSHA,
		WorktreePath:  sessWT.WorktreePath,
		Status:        store.SessionRunning,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := st.CreateStep(ctx, store.Step{
		ID:           "st_1",
		SessionID:    sessID,
		StepIndex:    1,
		GitCommitSHA: step1Commit.CommitSHA,
	}); err != nil {
		t.Fatalf("CreateStep(1) error = %v", err)
	}
	if err := st.CreateStep(ctx, store.Step{
		ID:           "st_2",
		SessionID:    sessID,
		StepIndex:    2,
		GitCommitSHA: step2Commit.CommitSHA,
	}); err != nil {
		t.Fatalf("CreateStep(2) error = %v", err)
	}
	_ = st.Close()

	out, err := executeCLI(defaultDependencies(), "rewind", sessID, "--step", "1", "--repo", repo)
	if err != nil {
		t.Fatalf("engram rewind error = %v\noutput:\n%s", err, out)
	}

	gotBytes, err := os.ReadFile(filepath.Join(sessWT.WorktreePath, "README.md"))
	if err != nil {
		t.Fatalf("read rewound README.md: %v", err)
	}
	if string(gotBytes) != "# step 1\n" {
		t.Fatalf("rewound README.md = %q, want %q", string(gotBytes), "# step 1\n")
	}

	hostBytes, err := os.ReadFile(filepath.Join(repo, "README.md"))
	if err != nil {
		t.Fatalf("read host README.md: %v", err)
	}
	if string(hostBytes) != "# test repo\n" {
		t.Fatalf("host README.md = %q, want %q", string(hostBytes), "# test repo\n")
	}
}

type fakeRunner struct {
	called bool
	req    RunRequest
}

func (f *fakeRunner) Run(_ context.Context, req RunRequest) error {
	f.called = true
	f.req = req
	return nil
}

func TestCLIRunLoadsWorkspaceAndInvokesRunner(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(Dependencies{}, "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	runner := &fakeRunner{}
	_, err := executeCLI(Dependencies{Runner: runner}, "run", "Fix", "API", "tests", "--repo", repo)
	if err != nil {
		t.Fatalf("engram run error = %v", err)
	}
	if !runner.called {
		t.Fatalf("expected runner.Run to be called")
	}
	if runner.req.TaskPrompt != "Fix API tests" {
		t.Fatalf("TaskPrompt = %q, want %q", runner.req.TaskPrompt, "Fix API tests")
	}
	if runner.req.Config.Context.ArtifactTokenThreshold != control.DefaultArtifactTokenThreshold {
		t.Fatalf("ArtifactTokenThreshold = %d, want %d",
			runner.req.Config.Context.ArtifactTokenThreshold, control.DefaultArtifactTokenThreshold)
	}
}

func TestCLIRunIntegrationWithAgentLoopAndStatus(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(defaultDependencies(), "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	var turns atomic.Int32
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "cli-test-key" {
			t.Fatalf("expected x-api-key=cli-test-key, got %q", r.Header.Get("x-api-key"))
		}
		w.Header().Set("Content-Type", "text/event-stream")

		switch turns.Add(1) {
		case 1:
			inputBytes, _ := json.Marshal(map[string]string{
				"path":    "README.md",
				"content": "# updated by engram run\n",
			})
			fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":30}}}\n\n")
			fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_w1\",\"name\":\"write_file\",\"input\":{}}}\n\n")
			fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":%s}}\n\n", mustQuote(string(inputBytes)))
			fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":20}}\n\n")
		case 2:
			fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":40}}}\n\n")
			fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
			fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Updated README.md.\"}}\n\n")
			fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":10}}\n\n")
		default:
			t.Fatalf("unexpected turn")
		}
	}))
	t.Cleanup(mockLLM.Close)

	t.Setenv("ENGRAM_TEST_KEY", "cli-test-key")

	ws := control.Workspace{RepoRoot: repo}
	cfg := control.DefaultConfig()
	cfg.Model.Endpoint = mockLLM.URL
	cfg.Model.APIKeyEnv = "ENGRAM_TEST_KEY"
	cfgBytes, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config.toml: %v", err)
	}
	if err := os.WriteFile(ws.ConfigPath(), cfgBytes, 0o644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	runOut, err := executeCLI(defaultDependencies(), "run", "Update", "README.md", "--repo", repo)
	if err != nil {
		t.Fatalf("engram run error = %v\noutput:\n%s", err, runOut)
	}
	if !strings.Contains(runOut, "Updated README.md.") || !strings.Contains(runOut, "Session: sess_") {
		t.Fatalf("unexpected run output:\n%s", runOut)
	}

	// Host repo README must remain untouched (Invariant #1).
	hostReadme, err := os.ReadFile(filepath.Join(repo, "README.md"))
	if err != nil {
		t.Fatalf("read host README.md: %v", err)
	}
	if string(hostReadme) != "# test repo\n" {
		t.Fatalf("host README.md mutated = %q, want %q", string(hostReadme), "# test repo\n")
	}

	// Verify SQLite state and worktree mutation, then verify `engram rewind` on step 1/2.
	ctx := context.Background()
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	sessions, err := st.ListSessions(ctx, 5)
	if err != nil {
		_ = st.Close()
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].Status != store.SessionCompleted {
		_ = st.Close()
		t.Fatalf("sessions = %+v, want 1 completed session", sessions)
	}
	wtReadme, err := os.ReadFile(filepath.Join(sessions[0].WorktreePath, "README.md"))
	_ = st.Close()
	if err != nil {
		t.Fatalf("read worktree README.md: %v", err)
	}
	if string(wtReadme) != "# updated by engram run\n" {
		t.Fatalf("worktree README.md = %q, want %q", string(wtReadme), "# updated by engram run\n")
	}

	statusOut, err := executeCLI(defaultDependencies(), "status", "--repo", repo)
	if err != nil {
		t.Fatalf("engram status error = %v", err)
	}
	if !strings.Contains(statusOut, sessions[0].ID) || !strings.Contains(statusOut, "completed") {
		t.Fatalf("status output missing completed session:\n%s", statusOut)
	}
}

func mustQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
func TestCLIRulesListShowApproveAndReject(t *testing.T) {
	repo := initTempGitRepo(t)
	if _, err := executeCLI(defaultDependencies(), "init", "--repo", repo); err != nil {
		t.Fatalf("engram init error = %v", err)
	}

	ws := control.Workspace{RepoRoot: repo}
	hookSrc := "import sys\nprint('ok')\nsys.exit(0)\n"
	if err := os.WriteFile(filepath.Join(ws.HooksDir(), "eng_cli_1.py"), []byte(hookSrc), 0o644); err != nil {
		t.Fatalf("write hook: %v", err)
	}

	ctx := context.Background()
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_cli_1",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/eng_cli_1.py",
		FailureSignature: "sig_cli_1",
		Status:           store.EngramStatusPendingApproval,
		ShadowPassRate:   1.0,
	}); err != nil {
		t.Fatalf("CreateEngram: %v", err)
	}
	_ = st.Close()

	listOut, err := executeCLI(defaultDependencies(), "rules", "list", "--status", "pending_approval", "--repo", repo)
	if err != nil || !strings.Contains(listOut, "eng_cli_1") {
		t.Fatalf("rules list = %q, err = %v", listOut, err)
	}

	showOut, err := executeCLI(defaultDependencies(), "rules", "show", "eng_cli_1", "--repo", repo)
	if err != nil || !strings.Contains(showOut, "sys.exit(0)") {
		t.Fatalf("rules show = %q, err = %v", showOut, err)
	}

	approveOut, err := executeCLI(defaultDependencies(), "rules", "approve", "eng_cli_1", "--repo", repo)
	if err != nil || !strings.Contains(approveOut, "status=active") {
		t.Fatalf("rules approve = %q, err = %v", approveOut, err)
	}

	rejectOut, err := executeCLI(defaultDependencies(), "rules", "reject", "eng_cli_1", "--repo", repo)
	if err != nil || !strings.Contains(rejectOut, "status=rejected") {
		t.Fatalf("rules reject = %q, err = %v", rejectOut, err)
	}
}
