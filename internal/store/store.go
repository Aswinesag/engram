package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("store: record not found")

	// ErrShadowVerificationRequired enforces Invariant #4: no self-generated
	// hook or tool may enter active status before passing shadow replay.
	ErrShadowVerificationRequired = errors.New("store: self-generated hook or tool requires shadow verification before activation")
)

// SessionStatus mirrors the CHECK constraint on sessions.status.
type SessionStatus string

const (
	SessionRunning   SessionStatus = "running"
	SessionCompleted SessionStatus = "completed"
	SessionFailed    SessionStatus = "failed"
	SessionAborted   SessionStatus = "aborted"
)

// EngramKind mirrors the CHECK constraint on engrams.kind.
type EngramKind string

const (
	EngramKindHook EngramKind = "hook"
	EngramKindTool EngramKind = "tool"
	EngramKindRule EngramKind = "rule"
)

// EngramStatus mirrors the CHECK constraint on engrams.status.
type EngramStatus string

const (
	EngramStatusShadowTesting   EngramStatus = "shadow_testing"
	EngramStatusPendingApproval EngramStatus = "pending_approval"
	EngramStatusActive          EngramStatus = "active"
	EngramStatusRejected        EngramStatus = "rejected"
)

// Session represents a single isolated agent execution session.
type Session struct {
	ID            string
	TaskPrompt    string
	BaseCommitSHA string
	WorktreePath  string
	Status        SessionStatus
	CreatedAt     time.Time
}

// Step represents a single atomic agent step and its Git snapshot SHA.
type Step struct {
	ID                string
	SessionID         string
	StepIndex         int
	GitCommitSHA      string
	Thought           string
	ToolName          string
	ToolInputJSON     string
	ToolOutputSummary string
	RawArtifactPath   string
	ExitCode          *int
	DurationMS        int64
	TokensIn          int64
	TokensOut         int64
	CreatedAt         time.Time
}

// Engram represents a compiled hook, composite tool, or glob-scoped rule.
type Engram struct {
	ID                  string
	Kind                EngramKind
	TriggerPattern      string
	FilePath            string
	SourceSessionID     string
	FailureSignature    string
	Status              EngramStatus
	ShadowPassRate      float64
	TimesTriggered      int64
	TimesPreventedError int64
	CreatedAt           time.Time
}

// EngramFilter constrains ListEngrams queries. Empty fields are ignored.
type EngramFilter struct {
	Status EngramStatus
	Kind   EngramKind
}

// Store wraps the SQLite WAL-mode telemetry and replay database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at dbPath, enforces WAL mode and
// foreign keys on every connection, and runs the embedded schema DDL.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("store: dbPath must not be empty")
	}

	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			return nil, fmt.Errorf("store: create parent directory: %w", err)
		}
	}

	dsn, err := buildDSN(dbPath)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// Single writer connection avoids SQLITE_BUSY write contention inside the
	// Go daemon while WAL mode permits concurrent external readers.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping sqlite: %w", err)
	}

	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying SQLite connection pool.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// JournalMode returns the active SQLite journal_mode pragma value.
func (s *Store) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode;`).Scan(&mode); err != nil {
		return "", fmt.Errorf("store: query journal_mode: %w", err)
	}
	return strings.ToLower(mode), nil
}

// ForeignKeysEnabled returns true when SQLite foreign key enforcement is active.
func (s *Store) ForeignKeysEnabled(ctx context.Context) (bool, error) {
	var enabled int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys;`).Scan(&enabled); err != nil {
		return false, fmt.Errorf("store: query foreign_keys: %w", err)
	}
	return enabled == 1, nil
}

// CreateSession inserts a new session row.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	if sess.ID == "" {
		return errors.New("store: session id is required")
	}
	if sess.Status == "" {
		sess.Status = SessionRunning
	}

	const q = `
		INSERT INTO sessions (id, task_prompt, base_commit_sha, worktree_path, status)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, q,
		sess.ID,
		sess.TaskPrompt,
		sess.BaseCommitSHA,
		sess.WorktreePath,
		string(sess.Status),
	)
	if err != nil {
		return fmt.Errorf("store: create session %q: %w", sess.ID, err)
	}
	return nil
}

// GetSession retrieves a session by its ID.
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	const q = `
		SELECT id, task_prompt, base_commit_sha, worktree_path, status, created_at
		FROM sessions
		WHERE id = ?
	`
	var sess Session
	var status string
	var createdAt sqliteTime

	err := s.db.QueryRowContext(ctx, q, id).Scan(
		&sess.ID,
		&sess.TaskPrompt,
		&sess.BaseCommitSHA,
		&sess.WorktreePath,
		&status,
		&createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: get session %q: %w", id, err)
	}

	sess.Status = SessionStatus(status)
	sess.CreatedAt = createdAt.Time
	return sess, nil
}

// ListSessions returns the most recent sessions. If limit <= 0, all sessions are returned.
func (s *Store) ListSessions(ctx context.Context, limit int) ([]Session, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if limit > 0 {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, task_prompt, base_commit_sha, worktree_path, status, created_at
			FROM sessions
			ORDER BY created_at DESC, rowid DESC
			LIMIT ?
		`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, task_prompt, base_commit_sha, worktree_path, status, created_at
			FROM sessions
			ORDER BY created_at DESC, rowid DESC
		`)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var sess Session
		var status string
		var createdAt sqliteTime
		if err := rows.Scan(
			&sess.ID,
			&sess.TaskPrompt,
			&sess.BaseCommitSHA,
			&sess.WorktreePath,
			&status,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("store: scan session: %w", err)
		}
		sess.Status = SessionStatus(status)
		sess.CreatedAt = createdAt.Time
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate sessions: %w", err)
	}
	return out, nil
}

// UpdateSessionStatus updates the status column of an existing session.
func (s *Store) UpdateSessionStatus(ctx context.Context, id string, status SessionStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET status = ? WHERE id = ?`, string(status), id)
	if err != nil {
		return fmt.Errorf("store: update session %q status: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected for session %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSession removes a session and cascades deletion to its steps.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete session %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected deleting session %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateStep records an executed agent step along with its atomic Git commit SHA.
func (s *Store) CreateStep(ctx context.Context, st Step) error {
	if st.ID == "" {
		return errors.New("store: step id is required")
	}
	if st.SessionID == "" {
		return errors.New("store: step session_id is required")
	}

	var exitCode sql.NullInt64
	if st.ExitCode != nil {
		exitCode = sql.NullInt64{Int64: int64(*st.ExitCode), Valid: true}
	}

	const q = `
		INSERT INTO steps (
			id, session_id, step_index, git_commit_sha,
			thought, tool_name, tool_input_json, tool_output_summary,
			raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, q,
		st.ID,
		st.SessionID,
		st.StepIndex,
		st.GitCommitSHA,
		nullableString(st.Thought),
		nullableString(st.ToolName),
		nullableString(st.ToolInputJSON),
		nullableString(st.ToolOutputSummary),
		nullableString(st.RawArtifactPath),
		exitCode,
		st.DurationMS,
		st.TokensIn,
		st.TokensOut,
	)
	if err != nil {
		return fmt.Errorf("store: create step %q (session %q, index %d): %w", st.ID, st.SessionID, st.StepIndex, err)
	}
	return nil
}

// GetStep retrieves a single step by ID.
func (s *Store) GetStep(ctx context.Context, id string) (Step, error) {
	const q = `
		SELECT id, session_id, step_index, git_commit_sha,
		       thought, tool_name, tool_input_json, tool_output_summary,
		       raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out, created_at
		FROM steps
		WHERE id = ?
	`
	st, err := scanStep(s.db.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Step{}, ErrNotFound
	}
	if err != nil {
		return Step{}, fmt.Errorf("store: get step %q: %w", id, err)
	}
	return st, nil
}

// GetStepByIndex retrieves a step by (session_id, step_index), primarily for
// time-travel rewind lookup of git_commit_sha.
func (s *Store) GetStepByIndex(ctx context.Context, sessionID string, stepIndex int) (Step, error) {
	const q = `
		SELECT id, session_id, step_index, git_commit_sha,
		       thought, tool_name, tool_input_json, tool_output_summary,
		       raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out, created_at
		FROM steps
		WHERE session_id = ? AND step_index = ?
	`
	st, err := scanStep(s.db.QueryRowContext(ctx, q, sessionID, stepIndex))
	if errors.Is(err, sql.ErrNoRows) {
		return Step{}, ErrNotFound
	}
	if err != nil {
		return Step{}, fmt.Errorf("store: get step (session %q, index %d): %w", sessionID, stepIndex, err)
	}
	return st, nil
}

// LatestStep returns the highest-indexed step recorded for a session.
func (s *Store) LatestStep(ctx context.Context, sessionID string) (Step, error) {
	const q = `
		SELECT id, session_id, step_index, git_commit_sha,
		       thought, tool_name, tool_input_json, tool_output_summary,
		       raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out, created_at
		FROM steps
		WHERE session_id = ?
		ORDER BY step_index DESC
		LIMIT 1
	`
	st, err := scanStep(s.db.QueryRowContext(ctx, q, sessionID))
	if errors.Is(err, sql.ErrNoRows) {
		return Step{}, ErrNotFound
	}
	if err != nil {
		return Step{}, fmt.Errorf("store: latest step for session %q: %w", sessionID, err)
	}
	return st, nil
}

// ListStepsBySession returns all steps for a session ordered ascending by step_index.
func (s *Store) ListStepsBySession(ctx context.Context, sessionID string) ([]Step, error) {
	const q = `
		SELECT id, session_id, step_index, git_commit_sha,
		       thought, tool_name, tool_input_json, tool_output_summary,
		       raw_artifact_path, exit_code, duration_ms, tokens_in, tokens_out, created_at
		FROM steps
		WHERE session_id = ?
		ORDER BY step_index ASC
	`
	rows, err := s.db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: list steps for session %q: %w", sessionID, err)
	}
	defer rows.Close()

	var out []Step
	for rows.Next() {
		st, err := scanStep(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan step: %w", err)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate steps: %w", err)
	}
	return out, nil
}

// DeleteStepsAfter deletes all steps for a session with step_index > stepIndex.
func (s *Store) DeleteStepsAfter(ctx context.Context, sessionID string, stepIndex int) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM steps WHERE session_id = ? AND step_index > ?`,
		sessionID, stepIndex,
	)
	if err != nil {
		return 0, fmt.Errorf("store: delete steps after %d for session %q: %w", stepIndex, sessionID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: rows affected deleting steps: %w", err)
	}
	return n, nil
}

// CreateEngram inserts a compiled or manually authored engram record.
// Self-generated hooks and tools (SourceSessionID != "") cannot be inserted
// directly in active status unless ShadowPassRate > 0 (Invariant #4).
func (s *Store) CreateEngram(ctx context.Context, e Engram) error {
	if e.ID == "" {
		return errors.New("store: engram id is required")
	}
	if requiresShadowVerification(e.Kind, e.SourceSessionID, e.Status, e.ShadowPassRate) {
		return ErrShadowVerificationRequired
	}

	const q = `
		INSERT INTO engrams (
			id, kind, trigger_pattern, file_path, source_session_id,
			failure_signature, status, shadow_pass_rate,
			times_triggered, times_prevented_error
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, q,
		e.ID,
		string(e.Kind),
		e.TriggerPattern,
		e.FilePath,
		nullableString(e.SourceSessionID),
		e.FailureSignature,
		string(e.Status),
		e.ShadowPassRate,
		e.TimesTriggered,
		e.TimesPreventedError,
	)
	if err != nil {
		return fmt.Errorf("store: create engram %q: %w", e.ID, err)
	}
	return nil
}

// GetEngram retrieves an engram by ID.
func (s *Store) GetEngram(ctx context.Context, id string) (Engram, error) {
	const q = `
		SELECT id, kind, trigger_pattern, file_path, source_session_id,
		       failure_signature, status, shadow_pass_rate,
		       times_triggered, times_prevented_error, created_at
		FROM engrams
		WHERE id = ?
	`
	e, err := scanEngram(s.db.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Engram{}, ErrNotFound
	}
	if err != nil {
		return Engram{}, fmt.Errorf("store: get engram %q: %w", id, err)
	}
	return e, nil
}

// FindEngramBySignature returns the newest engram matching failureSignature.
func (s *Store) FindEngramBySignature(ctx context.Context, failureSignature string) (Engram, error) {
	const q = `
		SELECT id, kind, trigger_pattern, file_path, source_session_id,
		       failure_signature, status, shadow_pass_rate,
		       times_triggered, times_prevented_error, created_at
		FROM engrams
		WHERE failure_signature = ?
		ORDER BY created_at DESC, rowid DESC
		LIMIT 1
	`
	e, err := scanEngram(s.db.QueryRowContext(ctx, q, failureSignature))
	if errors.Is(err, sql.ErrNoRows) {
		return Engram{}, ErrNotFound
	}
	if err != nil {
		return Engram{}, fmt.Errorf("store: find engram by signature: %w", err)
	}
	return e, nil
}

// ListEngrams returns engrams matching optional status and kind filters.
func (s *Store) ListEngrams(ctx context.Context, filter EngramFilter) ([]Engram, error) {
	var (
		clauses []string
		args    []any
	)
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, string(filter.Status))
	}
	if filter.Kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, string(filter.Kind))
	}

	query := `
		SELECT id, kind, trigger_pattern, file_path, source_session_id,
		       failure_signature, status, shadow_pass_rate,
		       times_triggered, times_prevented_error, created_at
		FROM engrams
	`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC, rowid DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list engrams: %w", err)
	}
	defer rows.Close()

	var out []Engram
	for rows.Next() {
		e, err := scanEngram(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan engram: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate engrams: %w", err)
	}
	return out, nil
}

// UpdateEngramStatus transitions an engram's status and optionally updates its
// shadow_pass_rate. Enforces Invariant #4 inside a transaction.
func (s *Store) UpdateEngramStatus(ctx context.Context, id string, status EngramStatus, shadowPassRate *float64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx for engram %q: %w", id, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var (
		kindStr         string
		sourceSessionID sql.NullString
		currentPassRate float64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT kind, source_session_id, shadow_pass_rate
		FROM engrams
		WHERE id = ?
	`, id).Scan(&kindStr, &sourceSessionID, &currentPassRate)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: load engram %q for update: %w", id, err)
	}

	effectivePassRate := currentPassRate
	if shadowPassRate != nil {
		effectivePassRate = *shadowPassRate
	}

	if requiresShadowVerification(EngramKind(kindStr), sourceSessionID.String, status, effectivePassRate) {
		return ErrShadowVerificationRequired
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE engrams SET status = ?, shadow_pass_rate = ? WHERE id = ?`,
		string(status), effectivePassRate, id,
	); err != nil {
		return fmt.Errorf("store: update engram %q status: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit engram %q status update: %w", id, err)
	}
	return nil
}

// IncrementEngramMetrics atomically increments times_triggered and
// times_prevented_error counters on an engram.
func (s *Store) IncrementEngramMetrics(ctx context.Context, id string, triggeredDelta, preventedDelta int64) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE engrams
		SET times_triggered = times_triggered + ?,
		    times_prevented_error = times_prevented_error + ?
		WHERE id = ?
	`, triggeredDelta, preventedDelta, id)
	if err != nil {
		return fmt.Errorf("store: increment metrics for engram %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected incrementing metrics for engram %q: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func requiresShadowVerification(kind EngramKind, sourceSessionID string, status EngramStatus, shadowPassRate float64) bool {
	if status != EngramStatusActive {
		return false
	}
	if sourceSessionID == "" {
		// Manually authored hooks/tools/rules are explicitly user-owned.
		return false
	}
	if kind != EngramKindHook && kind != EngramKindTool {
		return false
	}
	return shadowPassRate <= 0
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanStep(row rowScanner) (Step, error) {
	var (
		st            Step
		thought       sql.NullString
		toolName      sql.NullString
		toolInputJSON sql.NullString
		toolSummary   sql.NullString
		rawArtifact   sql.NullString
		exitCode      sql.NullInt64
		durationMS    sql.NullInt64
		tokensIn      sql.NullInt64
		tokensOut     sql.NullInt64
		createdAt     sqliteTime
	)

	err := row.Scan(
		&st.ID,
		&st.SessionID,
		&st.StepIndex,
		&st.GitCommitSHA,
		&thought,
		&toolName,
		&toolInputJSON,
		&toolSummary,
		&rawArtifact,
		&exitCode,
		&durationMS,
		&tokensIn,
		&tokensOut,
		&createdAt,
	)
	if err != nil {
		return Step{}, err
	}

	st.Thought = thought.String
	st.ToolName = toolName.String
	st.ToolInputJSON = toolInputJSON.String
	st.ToolOutputSummary = toolSummary.String
	st.RawArtifactPath = rawArtifact.String
	if exitCode.Valid {
		code := int(exitCode.Int64)
		st.ExitCode = &code
	}
	st.DurationMS = durationMS.Int64
	st.TokensIn = tokensIn.Int64
	st.TokensOut = tokensOut.Int64
	st.CreatedAt = createdAt.Time
	return st, nil
}

func scanEngram(row rowScanner) (Engram, error) {
	var (
		e               Engram
		kindStr         string
		statusStr       string
		sourceSessionID sql.NullString
		createdAt       sqliteTime
	)

	err := row.Scan(
		&e.ID,
		&kindStr,
		&e.TriggerPattern,
		&e.FilePath,
		&sourceSessionID,
		&e.FailureSignature,
		&statusStr,
		&e.ShadowPassRate,
		&e.TimesTriggered,
		&e.TimesPreventedError,
		&createdAt,
	)
	if err != nil {
		return Engram{}, err
	}

	e.Kind = EngramKind(kindStr)
	e.Status = EngramStatus(statusStr)
	e.SourceSessionID = sourceSessionID.String
	e.CreatedAt = createdAt.Time
	return e, nil
}

func nullableString(v string) sql.NullString {
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func buildDSN(dbPath string) (string, error) {
	if dbPath == ":memory:" {
		return "file::memory:?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", nil
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return "", fmt.Errorf("store: resolve absolute path %q: %w", dbPath, err)
	}

	slashed := filepath.ToSlash(absPath)
	if !strings.HasPrefix(slashed, "/") {
		// Windows drive paths (e.g. C:/...) need a leading slash so url.URL
		// emits file:///C:/... instead of file://C:/... (invalid URI authority).
		slashed = "/" + slashed
	}

	u := url.URL{
		Scheme: "file",
		Path:   slashed,
	}
	q := u.Query()
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type sqliteTime struct {
	time.Time
}

func (t *sqliteTime) Scan(src any) error {
	if src == nil {
		t.Time = time.Time{}
		return nil
	}

	switch v := src.(type) {
	case time.Time:
		t.Time = v.UTC()
		return nil
	case string:
		parsed, err := parseSQLiteTimestamp(v)
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	case []byte:
		parsed, err := parseSQLiteTimestamp(string(v))
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	default:
		return fmt.Errorf("store: unsupported timestamp type %T", src)
	}
}

func parseSQLiteTimestamp(raw string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("store: parse timestamp %q", raw)
}
