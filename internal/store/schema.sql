PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    task_prompt TEXT NOT NULL,
    base_commit_sha TEXT NOT NULL,
    worktree_path TEXT NOT NULL,
    status TEXT CHECK(status IN ('running', 'completed', 'failed', 'aborted')) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS steps (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    git_commit_sha TEXT NOT NULL, -- Atomic Git snapshot after this step
    thought TEXT,
    tool_name TEXT,
    tool_input_json TEXT,
    tool_output_summary TEXT, -- Compacted summary injected into LLM context
    raw_artifact_path TEXT, -- Full log path on disk if truncated
    exit_code INTEGER,
    duration_ms INTEGER,
    tokens_in INTEGER,
    tokens_out INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, step_index)
);

CREATE TABLE IF NOT EXISTS engrams (
    id TEXT PRIMARY KEY, -- e.g., eng_01J9X4M9
    kind TEXT CHECK(kind IN ('hook', 'tool', 'rule')) NOT NULL,
    trigger_pattern TEXT NOT NULL, -- Tool regex or file path glob
    file_path TEXT NOT NULL, -- Relative path inside .engram/
    source_session_id TEXT REFERENCES sessions(id),
    failure_signature TEXT NOT NULL, -- Normalized hash/description of the loop resolved
    status TEXT CHECK(status IN ('shadow_testing', 'pending_approval', 'active', 'rejected')) NOT NULL,
    shadow_pass_rate REAL DEFAULT 0.0,
    times_triggered INTEGER DEFAULT 0,
    times_prevented_error INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_steps_session_step ON steps(session_id, step_index);
CREATE INDEX IF NOT EXISTS idx_engrams_status_kind ON engrams(status, kind);
CREATE INDEX IF NOT EXISTS idx_engrams_failure_sig ON engrams(failure_signature);