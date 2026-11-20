package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"engram/internal/store"
)

func TestContextCompactorPassesThroughWithinBudget(t *testing.T) {
	compactor, err := NewContextCompactor(filepath.Join(t.TempDir(), "artifacts"), 2000)
	if err != nil {
		t.Fatalf("NewContextCompactor() error = %v", err)
	}

	small := "12 passed in 0.42s\n"
	res, err := compactor.Compact("sess_1", 1, "bash", small)
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if res.Spilled {
		t.Fatalf("expected Spilled=false for small output")
	}
	if res.RawArtifactPath != "" {
		t.Fatalf("expected empty RawArtifactPath, got %q", res.RawArtifactPath)
	}
	if res.Summary != small {
		t.Fatalf("Summary = %q, want %q", res.Summary, small)
	}
}

func TestContextCompactorSpillsLargeOutputToArtifact(t *testing.T) {
	artifactsDir := filepath.Join(t.TempDir(), ".engram", ".runtime", "artifacts")
	compactor, err := NewContextCompactor(artifactsDir, 2000)
	if err != nil {
		t.Fatalf("NewContextCompactor() error = %v", err)
	}

	// Build a payload > 2,000 tokens (~12,000 bytes).
	var raw strings.Builder
	raw.WriteString("HEAD_MARKER: starting pytest suite\n")
	for i := 0; i < 400; i++ {
		raw.WriteString("INFO executing integration test case line payload padding...\n")
	}
	raw.WriteString("TAIL_MARKER: ConnectionRefusedError: port 5432\n")

	res, err := compactor.Compact("sess_01J9W8K2", 4, "bash", raw.String())
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if !res.Spilled {
		t.Fatalf("expected Spilled=true for >2000 token payload (estimated=%d)", res.EstimatedTokens)
	}
	if res.RawArtifactPath == "" {
		t.Fatalf("expected non-empty RawArtifactPath")
	}

	// Verify full raw log is preserved intact on disk.
	diskBytes, err := os.ReadFile(res.RawArtifactPath)
	if err != nil {
		t.Fatalf("read artifact file: %v", err)
	}
	if string(diskBytes) != raw.String() {
		t.Fatalf("artifact content mismatch (got %d bytes, want %d bytes)", len(diskBytes), raw.Len())
	}

	// Verify summary is strictly compacted and contains head, tail, and artifact pointer.
	if EstimateTokens(res.Summary) >= 2000 {
		t.Fatalf("compacted summary still exceeded threshold: %d tokens", EstimateTokens(res.Summary))
	}
	for _, want := range []string{"HEAD_MARKER", "TAIL_MARKER", filepath.ToSlash(res.RawArtifactPath)} {
		if !strings.Contains(res.Summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, res.Summary)
		}
	}
}

func TestHookGateDeterministicAllowBlockAndTelemetry(t *testing.T) {
	pyBin, err := ResolvePythonBinary()
	if err != nil {
		t.Skipf("skipping python hook subprocess test: %v", err)
	}

	repoRoot := t.TempDir()
	ws := Workspace{RepoRoot: repoRoot}
	worktreeDir := filepath.Join(ws.WorktreesDir(), "sess_hook_1")
	if err := os.MkdirAll(ws.HooksDir(), 0o755); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.MkdirAll(worktreeDir, 0o755); err != nil {
		t.Fatalf("mkdir worktree: %v", err)
	}

	// Hook 1: blocks pytest when .db_ready marker is missing (exit 2), allows when present (exit 0).
	hookScript := `import json, os, sys
payload = json.load(sys.stdin)
marker = os.path.join(os.getcwd(), ".db_ready")
if not os.path.exists(marker):
    print("PostgreSQL test container is not running on port 5432. Run: docker compose -f docker-compose.test.yml up -d")
    sys.exit(2)
sys.exit(0)
`
	hookRel := "hooks/eng_01J9X4M9_verify_test_db.py"
	if err := os.WriteFile(filepath.Join(ws.EngramDir(), hookRel), []byte(hookScript), 0o644); err != nil {
		t.Fatalf("write hook script: %v", err)
	}

	ctx := context.Background()
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.CreateEngram(ctx, store.Engram{
		ID:               "eng_01J9X4M9",
		Kind:             store.EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         hookRel,
		FailureSignature: "manual_pg_5432",
		Status:           store.EngramStatusActive,
	}); err != nil {
		t.Fatalf("CreateEngram() error = %v", err)
	}

	specs, err := LoadActiveHookSpecs(ctx, st, Manifest{
		Version: "1.0",
		Hooks: []ManifestEntry{
			{
				ID:             "eng_01J9X4M9",
				Kind:           store.EngramKindHook,
				TargetTool:     "bash",
				TriggerPattern: `^pytest\b`,
				FilePath:       hookRel,
				Status:         store.EngramStatusActive,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadActiveHookSpecs() error = %v", err)
	}

	gate, err := NewHookGate(HookGateConfig{
		Workspace: ws,
		Store:     st,
		PythonBin: pyBin,
		Timeout:   10 * time.Second,
	}, specs)
	if err != nil {
		t.Fatalf("NewHookGate() error = %v", err)
	}

	// Non-matching command must pass without triggering the hook.
	dec, err := gate.Evaluate(ctx, HookInvocation{
		Phase:        HookPhasePre,
		SessionID:    "sess_hook_1",
		StepIndex:    1,
		WorktreePath: worktreeDir,
		ToolName:     "bash",
		ToolInput:    json.RawMessage(`{"command":"ls -la"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate(ls) error = %v", err)
	}
	if !dec.Allowed || len(dec.TriggeredHooks) != 0 {
		t.Fatalf("Evaluate(ls) = %+v, want Allowed=true and 0 triggered hooks", dec)
	}

	// Matching pytest command without .db_ready must be blocked with exit code 2 guidance.
	dec, err = gate.Evaluate(ctx, HookInvocation{
		Phase:        HookPhasePre,
		SessionID:    "sess_hook_1",
		StepIndex:    2,
		WorktreePath: worktreeDir,
		ToolName:     "bash",
		ToolInput:    json.RawMessage(`{"command":"pytest tests/api"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate(pytest blocked) error = %v", err)
	}
	if dec.Allowed || dec.BlockedBy != "eng_01J9X4M9" {
		t.Fatalf("Evaluate(pytest blocked) = %+v, want Allowed=false, BlockedBy=eng_01J9X4M9", dec)
	}
	if !strings.Contains(dec.Guidance, "docker-compose.test.yml") {
		t.Fatalf("unexpected guidance: %q", dec.Guidance)
	}

	// Create .db_ready inside the isolated worktree -> hook must now exit 0 and allow.
	if err := os.WriteFile(filepath.Join(worktreeDir, ".db_ready"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write .db_ready: %v", err)
	}
	dec, err = gate.Evaluate(ctx, HookInvocation{
		Phase:        HookPhasePre,
		SessionID:    "sess_hook_1",
		StepIndex:    3,
		WorktreePath: worktreeDir,
		ToolName:     "bash",
		ToolInput:    json.RawMessage(`{"command":"pytest tests/api"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate(pytest allowed) error = %v", err)
	}
	if !dec.Allowed || len(dec.TriggeredHooks) != 1 {
		t.Fatalf("Evaluate(pytest allowed) = %+v, want Allowed=true, 1 triggered hook", dec)
	}

	// Verify SQLite engram telemetry incremented (2 triggers, 1 error prevented).
	eng, err := st.GetEngram(ctx, "eng_01J9X4M9")
	if err != nil {
		t.Fatalf("GetEngram() error = %v", err)
	}
	if eng.TimesTriggered != 2 || eng.TimesPreventedError != 1 {
		t.Fatalf("engram metrics = triggered:%d prevented:%d, want 2 and 1",
			eng.TimesTriggered, eng.TimesPreventedError)
	}
}

func TestHookGateRejectsPathTraversal(t *testing.T) {
	repoRoot := t.TempDir()
	ws := Workspace{RepoRoot: repoRoot}
	if err := os.MkdirAll(ws.HooksDir(), 0o755); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}

	_, err := NewHookGate(HookGateConfig{
		Workspace: ws,
		PythonBin: "python",
	}, []HookSpec{
		{
			ID:             "eng_escape",
			TriggerPattern: ".*",
			FilePath:       "../evil.py",
		},
	})
	if !errors.Is(err, ErrUnsafeHookPath) {
		t.Fatalf("NewHookGate(path traversal) err = %v, want ErrUnsafeHookPath", err)
	}
}
