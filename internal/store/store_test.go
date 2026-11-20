package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), ".engram", ".runtime", "state.db")
	st, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", dbPath, err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return st
}

func intPtr(v int) *int          { return &v }
func floatPtr(v float64) *float64 { return &v }

func TestOpenInitializesWALAndForeignKeys(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), ".engram", ".runtime", "state.db")

	st, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	mode, err := st.JournalMode(ctx)
	if err != nil {
		t.Fatalf("JournalMode() error = %v", err)
	}
	if mode != "wal" {
		t.Fatalf("JournalMode() = %q, want %q", mode, "wal")
	}

	fkEnabled, err := st.ForeignKeysEnabled(ctx)
	if err != nil {
		t.Fatalf("ForeignKeysEnabled() error = %v", err)
	}
	if !fkEnabled {
		t.Fatalf("ForeignKeysEnabled() = false, want true")
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Re-opening must be idempotent.
	st2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if err := st2.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestSessionCRUDAndCascadeDelete(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	sess := Session{
		ID:            "sess_01J9W8K2",
		TaskPrompt:    "Fix failing API pagination tests",
		BaseCommitSHA: "a1b2c3d4e5f6",
		WorktreePath:  ".engram/.runtime/worktrees/sess_01J9W8K2",
		Status:        SessionRunning,
	}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := st.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got.TaskPrompt != sess.TaskPrompt || got.BaseCommitSHA != sess.BaseCommitSHA || got.Status != SessionRunning {
		t.Fatalf("GetSession() = %+v, want %+v", got, sess)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("GetSession().CreatedAt is zero")
	}

	if err := st.UpdateSessionStatus(ctx, sess.ID, SessionCompleted); err != nil {
		t.Fatalf("UpdateSessionStatus() error = %v", err)
	}
	got, err = st.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() after update error = %v", err)
	}
	if got.Status != SessionCompleted {
		t.Fatalf("status = %q, want %q", got.Status, SessionCompleted)
	}

	if err := st.CreateStep(ctx, Step{
		ID:           "step_001",
		SessionID:    sess.ID,
		StepIndex:    1,
		GitCommitSHA: "1111111",
		ToolName:     "bash",
		ExitCode:     intPtr(0),
	}); err != nil {
		t.Fatalf("CreateStep() error = %v", err)
	}

	sessions, err := st.ListSessions(ctx, 10)
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != sess.ID {
		t.Fatalf("ListSessions() = %+v, want 1 session %q", sessions, sess.ID)
	}

	// Deleting session must cascade delete steps via ON DELETE CASCADE.
	if err := st.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	if _, err := st.GetSession(ctx, sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession() after delete err = %v, want ErrNotFound", err)
	}
	if _, err := st.GetStep(ctx, "step_001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetStep() after session cascade delete err = %v, want ErrNotFound", err)
	}
}

func TestStepRecordingUniqueIndexAndRewindLookup(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	const sessID = "sess_01J9W8K9"
	if err := st.CreateSession(ctx, Session{
		ID:            sessID,
		TaskPrompt:    "Refactor auth middleware",
		BaseCommitSHA: "base000",
		WorktreePath:  ".engram/.runtime/worktrees/" + sessID,
		Status:        SessionRunning,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	steps := []Step{
		{
			ID:           "step_1",
			SessionID:    sessID,
			StepIndex:    1,
			GitCommitSHA: "sha_1",
			Thought:      "Inspect repository layout",
			ExitCode:     nil, // Thought-only step
			DurationMS:   120,
			TokensIn:     500,
			TokensOut:    80,
		},
		{
			ID:                "step_2",
			SessionID:         sessID,
			StepIndex:         2,
			GitCommitSHA:      "sha_2",
			ToolName:          "bash",
			ToolInputJSON:     `{"cmd":"pytest tests/api"}`,
			ToolOutputSummary: "Failed with ConnectionRefusedError (full log spilled to artifact)",
			RawArtifactPath:   ".engram/.runtime/artifacts/step_2.log",
			ExitCode:          intPtr(1),
			DurationMS:        2450,
			TokensIn:          920,
			TokensOut:         140,
		},
		{
			ID:                "step_3",
			SessionID:         sessID,
			StepIndex:         3,
			GitCommitSHA:      "sha_3",
			ToolName:          "bash",
			ToolInputJSON:     `{"cmd":"pytest tests/api"}`,
			ToolOutputSummary: "12 passed in 0.8s",
			ExitCode:          intPtr(0),
			DurationMS:        810,
			TokensIn:          1100,
			TokensOut:         95,
		},
	}

	for _, step := range steps {
		if err := st.CreateStep(ctx, step); err != nil {
			t.Fatalf("CreateStep(%q) error = %v", step.ID, err)
		}
	}

	// Duplicate (session_id, step_index) must fail due to UNIQUE constraint.
	if err := st.CreateStep(ctx, Step{
		ID:           "step_2_dup",
		SessionID:    sessID,
		StepIndex:    2,
		GitCommitSHA: "sha_dup",
	}); err == nil {
		t.Fatalf("CreateStep() with duplicate step_index succeeded, want error")
	}

	// Rewind lookup by step_index.
	step2, err := st.GetStepByIndex(ctx, sessID, 2)
	if err != nil {
		t.Fatalf("GetStepByIndex(2) error = %v", err)
	}
	if step2.GitCommitSHA != "sha_2" || step2.ExitCode == nil || *step2.ExitCode != 1 {
		t.Fatalf("GetStepByIndex(2) = %+v", step2)
	}
	if step2.RawArtifactPath != ".engram/.runtime/artifacts/step_2.log" {
		t.Fatalf("RawArtifactPath = %q, want artifact path", step2.RawArtifactPath)
	}

	// Verify NULL exit code stays nil and 0 stays non-nil 0.
	step1, err := st.GetStepByIndex(ctx, sessID, 1)
	if err != nil {
		t.Fatalf("GetStepByIndex(1) error = %v", err)
	}
	if step1.ExitCode != nil {
		t.Fatalf("step1.ExitCode = %v, want nil", *step1.ExitCode)
	}

	latest, err := st.LatestStep(ctx, sessID)
	if err != nil {
		t.Fatalf("LatestStep() error = %v", err)
	}
	if latest.StepIndex != 3 || latest.ExitCode == nil || *latest.ExitCode != 0 {
		t.Fatalf("LatestStep() = %+v, want step 3 with exit_code 0", latest)
	}

	// Simulate rewind truncation after step 1.
	deleted, err := st.DeleteStepsAfter(ctx, sessID, 1)
	if err != nil {
		t.Fatalf("DeleteStepsAfter() error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("DeleteStepsAfter() deleted %d rows, want 2", deleted)
	}

	remaining, err := st.ListStepsBySession(ctx, sessID)
	if err != nil {
		t.Fatalf("ListStepsBySession() error = %v", err)
	}
	if len(remaining) != 1 || remaining[0].StepIndex != 1 {
		t.Fatalf("ListStepsBySession() = %+v, want only step 1", remaining)
	}
}

func TestEngramLifecycleAndInvariant4Guard(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	const sessID = "sess_01J9W8K2"
	if err := st.CreateSession(ctx, Session{
		ID:            sessID,
		TaskPrompt:    "Run pytest suite",
		BaseCommitSHA: "a1b2c3d4",
		WorktreePath:  ".engram/.runtime/worktrees/" + sessID,
		Status:        SessionFailed,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Invariant #4: self-generated hook cannot be created directly as active without shadow verification.
	err := st.CreateEngram(ctx, Engram{
		ID:               "eng_unverified",
		Kind:             EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/eng_unverified.py",
		SourceSessionID:  sessID,
		FailureSignature: "sig_pg_5432",
		Status:           EngramStatusActive,
		ShadowPassRate:   0.0,
	})
	if !errors.Is(err, ErrShadowVerificationRequired) {
		t.Fatalf("CreateEngram(unverified active hook) err = %v, want ErrShadowVerificationRequired", err)
	}

	// Valid lifecycle: shadow_testing -> pending_approval -> active after shadow replay passes.
	eng := Engram{
		ID:               "eng_01J9X4M9",
		Kind:             EngramKindHook,
		TriggerPattern:   `^pytest\b`,
		FilePath:         "hooks/eng_01J9X4M9_verify_test_db.py",
		SourceSessionID:  sessID,
		FailureSignature: "sig_pg_5432",
		Status:           EngramStatusShadowTesting,
	}
	if err := st.CreateEngram(ctx, eng); err != nil {
		t.Fatalf("CreateEngram() error = %v", err)
	}

	// Attempting direct promotion without shadow_pass_rate > 0 must fail.
	if err := st.UpdateEngramStatus(ctx, eng.ID, EngramStatusActive, nil); !errors.Is(err, ErrShadowVerificationRequired) {
		t.Fatalf("UpdateEngramStatus(active without pass rate) err = %v, want ErrShadowVerificationRequired", err)
	}

	// Shadow replay succeeds -> pending_approval.
	if err := st.UpdateEngramStatus(ctx, eng.ID, EngramStatusPendingApproval, floatPtr(1.0)); err != nil {
		t.Fatalf("UpdateEngramStatus(pending_approval) error = %v", err)
	}

	// Approval promotes to active while retaining shadow_pass_rate = 1.0.
	if err := st.UpdateEngramStatus(ctx, eng.ID, EngramStatusActive, nil); err != nil {
		t.Fatalf("UpdateEngramStatus(active) error = %v", err)
	}

	// Manually authored hook (empty SourceSessionID) may be active directly.
	manual := Engram{
		ID:               "eng_manual_01",
		Kind:             EngramKindHook,
		TriggerPattern:   `^git push\b`,
		FilePath:         "hooks/block_force_push.py",
		FailureSignature: "manual_guard",
		Status:           EngramStatusActive,
	}
	if err := st.CreateEngram(ctx, manual); err != nil {
		t.Fatalf("CreateEngram(manual hook) error = %v", err)
	}

	// Increment telemetry metrics.
	if err := st.IncrementEngramMetrics(ctx, eng.ID, 3, 2); err != nil {
		t.Fatalf("IncrementEngramMetrics() error = %v", err)
	}

	got, err := st.GetEngram(ctx, eng.ID)
	if err != nil {
		t.Fatalf("GetEngram() error = %v", err)
	}
	if got.Status != EngramStatusActive || got.ShadowPassRate != 1.0 || got.TimesTriggered != 3 || got.TimesPreventedError != 2 {
		t.Fatalf("GetEngram() = %+v", got)
	}

	bySig, err := st.FindEngramBySignature(ctx, "sig_pg_5432")
	if err != nil {
		t.Fatalf("FindEngramBySignature() error = %v", err)
	}
	if bySig.ID != eng.ID {
		t.Fatalf("FindEngramBySignature().ID = %q, want %q", bySig.ID, eng.ID)
	}

	activeHooks, err := st.ListEngrams(ctx, EngramFilter{
		Status: EngramStatusActive,
		Kind:   EngramKindHook,
	})
	if err != nil {
		t.Fatalf("ListEngrams() error = %v", err)
	}
	if len(activeHooks) != 2 {
		t.Fatalf("ListEngrams(active hooks) len = %d, want 2", len(activeHooks))
	}
}

func TestSchemaCheckConstraints(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	if err := st.CreateSession(ctx, Session{
		ID:            "sess_bad",
		TaskPrompt:    "test",
		BaseCommitSHA: "abc",
		WorktreePath:  "/tmp/wt",
		Status:        SessionStatus("invalid_status"),
	}); err == nil {
		t.Fatalf("CreateSession() with invalid status succeeded, want CHECK constraint error")
	}

	if err := st.CreateEngram(ctx, Engram{
		ID:               "eng_bad_kind",
		Kind:             EngramKind("macro"),
		TriggerPattern:   ".*",
		FilePath:         "hooks/x.py",
		FailureSignature: "sig",
		Status:           EngramStatusPendingApproval,
	}); err == nil {
		t.Fatalf("CreateEngram() with invalid kind succeeded, want CHECK constraint error")
	}
}