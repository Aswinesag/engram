import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  EngramItem,
  EngramRPCClient,
  ForkResult,
  RewindResult,
  SessionSummary,
  SessionTrace,
  StepArtifact,
  StepDiff,
  StepNode,
  WorkspaceInfo,
} from "./rpc";

type ActiveTab = "traces" | "inbox";
type InspectorTab = "diff" | "io";
type StatusFilter = "all" | "pending_approval" | "active" | "shadow_testing" | "rejected";

function shortSHA(sha: string): string {
  return sha.length > 8 ? sha.slice(0, 8) : sha;
}

function stepClass(step: StepNode): string {
  if (!step.tool_name) return "node-thought";
  if (step.exit_code === 2) return "node-blocked";
  if (step.exit_code !== null && step.exit_code !== 0) return "node-error";
  return "node-ok";
}

function formatJSON(raw: string): string {
  if (!raw.trim()) return "{}";
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

export function App() {
  const rpcRef = useRef<EngramRPCClient | null>(null);
  if (rpcRef.current === null) {
    rpcRef.current = new EngramRPCClient();
  }
  const rpc = rpcRef.current;

  const [wsConnected, setWsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<ActiveTab>("traces");
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("diff");

  const [workspace, setWorkspace] = useState<WorkspaceInfo | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("");
  const [trace, setTrace] = useState<SessionTrace | null>(null);
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(0);

  const [stepDiff, setStepDiff] = useState<StepDiff | null>(null);
  const [artifact, setArtifact] = useState<StepArtifact | null>(null);
  const [forkPrompt, setForkPrompt] = useState<string>("");

  const [engrams, setEngrams] = useState<EngramItem[]>([]);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  const [errorMsg, setErrorMsg] = useState<string>("");
  const [infoMsg, setInfoMsg] = useState<string>("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const unsub = rpc.onStatusChange(setWsConnected);
    return () => {
      unsub();
      rpc.dispose();
    };
  }, [rpc]);

  const loadOverview = useCallback(async () => {
    try {
      const [info, sessRes, engRes] = await Promise.all([
        rpc.call<WorkspaceInfo>("workspace.info"),
        rpc.call<{ sessions: SessionSummary[] }>("sessions.list", { limit: 50 }),
        rpc.call<{ engrams: EngramItem[] }>("engrams.list"),
      ]);
      setWorkspace(info);
      setSessions(sessRes.sessions ?? []);
      setEngrams(engRes.engrams ?? []);
      setSelectedSessionId((prev) => {
        if (prev && (sessRes.sessions ?? []).some((s) => s.id === prev)) {
          return prev;
        }
        return sessRes.sessions?.[0]?.id ?? "";
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    }
  }, [rpc]);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    if (!selectedSessionId) {
      setTrace(null);
      setSelectedStepIndex(0);
      return;
    }
    let cancelled = false;
    rpc
      .call<SessionTrace>("sessions.trace", { session_id: selectedSessionId })
      .then((res) => {
        if (cancelled) return;
        setTrace(res);
        const lastStep = res.steps[res.steps.length - 1];
        setSelectedStepIndex(lastStep ? lastStep.step_index : 0);
        setArtifact(null);
      })
      .catch((err) => {
        if (!cancelled) {
          setErrorMsg(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [rpc, selectedSessionId]);

  useEffect(() => {
    if (!selectedSessionId || selectedStepIndex <= 0) {
      setStepDiff(null);
      return;
    }
    let cancelled = false;
    setArtifact(null);
    rpc
      .call<StepDiff>("steps.diff", {
        session_id: selectedSessionId,
        step_index: selectedStepIndex,
      })
      .then((res) => {
        if (!cancelled) setStepDiff(res);
      })
      .catch((err) => {
        if (!cancelled) {
          setErrorMsg(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [rpc, selectedSessionId, selectedStepIndex]);

  const selectedStep = useMemo<StepNode | null>(() => {
    if (!trace) return null;
    return trace.steps.find((s) => s.step_index === selectedStepIndex) ?? null;
  }, [trace, selectedStepIndex]);

  const filteredEngrams = useMemo(() => {
    if (statusFilter === "all") return engrams;
    return engrams.filter((e) => e.status === statusFilter);
  }, [engrams, statusFilter]);

  const pendingCount = useMemo(
    () => engrams.filter((e) => e.status === "pending_approval").length,
    [engrams]
  );

  const handleLoadArtifact = async () => {
    if (!selectedStep) return;
    setBusy(true);
    setErrorMsg("");
    try {
      const res = await rpc.call<StepArtifact>("steps.artifact", {
        session_id: selectedStep.session_id,
        step_index: selectedStep.step_index,
      });
      setArtifact(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleRewind = async () => {
    if (!selectedStep) return;
    setBusy(true);
    setErrorMsg("");
    setInfoMsg("");
    try {
      const res = await rpc.call<RewindResult>("sessions.rewind", {
        session_id: selectedStep.session_id,
        step_index: selectedStep.step_index,
      });
      setInfoMsg(
        `Rewound worktree for ${res.session_id} to step ${res.step_index} (${shortSHA(res.git_commit_sha)}).`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleFork = async () => {
    if (!selectedStep) return;
    setBusy(true);
    setErrorMsg("");
    setInfoMsg("");
    try {
      const res = await rpc.call<ForkResult>("sessions.fork", {
        session_id: selectedStep.session_id,
        step_index: selectedStep.step_index,
        task_prompt: forkPrompt.trim(),
      });
      setForkPrompt("");
      setInfoMsg(
        `Forked detached worktree ${res.forked_session_id} at ${shortSHA(res.base_commit_sha)}.`
      );
      await loadOverview();
      setSelectedSessionId(res.forked_session_id);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleApproveEngram = async (id: string) => {
    setBusy(true);
    setErrorMsg("");
    setInfoMsg("");
    try {
      await rpc.call("engrams.approve", { engram_id: id });
      setInfoMsg(`Approved and activated engram ${id}.`);
      await loadOverview();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleRejectEngram = async (id: string) => {
    setBusy(true);
    setErrorMsg("");
    setInfoMsg("");
    try {
      await rpc.call("engrams.reject", { engram_id: id });
      setInfoMsg(`Rejected engram ${id}.`);
      await loadOverview();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <h1>ENGRAM</h1>
          <div className="meta-pills">
            <span className={`pill ${wsConnected ? "ok" : "warn"}`}>
              {wsConnected ? "WS CONNECTED" : "HTTP FALLBACK"}
            </span>
            {workspace && (
              <>
                <span className="pill">{workspace.model_provider}:{workspace.model_name}</span>
                <span className="pill">sandbox:{workspace.sandbox_mode}</span>
                <span className="pill">active:{workspace.active_engram_count}</span>
              </>
            )}
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`tab-btn ${activeTab === "traces" ? "active" : ""}`}
            onClick={() => setActiveTab("traces")}
          >
            Execution DAG &amp; Diffs
          </button>
          <button
            className={`tab-btn ${activeTab === "inbox" ? "active" : ""}`}
            onClick={() => setActiveTab("inbox")}
          >
            Rule Approval Inbox
            {pendingCount > 0 && <span className="badge">{pendingCount}</span>}
          </button>
          <button className="btn" onClick={() => void loadOverview()} disabled={busy}>
            Refresh
          </button>
        </nav>
      </header>

      {errorMsg && (
        <div className="banner error">
          <span>{errorMsg}</span>
          <button className="btn" onClick={() => setErrorMsg("")}>
            Dismiss
          </button>
        </div>
      )}

      {infoMsg && (
        <div className="banner info">
          <span>{infoMsg}</span>
          <button className="btn" onClick={() => setInfoMsg("")}>
            Dismiss
          </button>
        </div>
      )}

      {activeTab === "traces" ? (
        <div className="workspace-grid">
          <aside className="sidebar">
            <div className="panel-header">
              <span>Sessions ({sessions.length})</span>
            </div>
            <div className="scroll-area">
              {sessions.length === 0 ? (
                <div className="empty-state">
                  No sessions recorded yet. Run <code>engram run &quot;...&quot;</code> to start.
                </div>
              ) : (
                sessions.map((s) => (
                  <button
                    key={s.id}
                    className={`session-card ${s.id === selectedSessionId ? "selected" : ""}`}
                    onClick={() => setSelectedSessionId(s.id)}
                  >
                    <div className="session-card-top">
                      <span>{s.id}</span>
                      <span className={`status-dot status-${s.status}`}>{s.status}</span>
                    </div>
                    <div className="session-prompt">{s.task_prompt}</div>
                    <div className="session-meta">
                      <span>steps:{s.step_count}</span>
                      <span>err:{s.error_count}</span>
                      <span>{shortSHA(s.head_commit_sha)}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </aside>

          <main className="main-pane">
            {!trace ? (
              <div className="empty-state">Select a session to inspect its execution DAG and diffs.</div>
            ) : (
              <>
                <section className="dag-strip">
                  <div className="dag-nodes">
                    <div className="dag-node node-thought">
                      <div className="dag-node-title">
                        <span>BASE</span>
                        <span>{shortSHA(trace.session.base_commit_sha)}</span>
                      </div>
                      <div className="dag-node-sub">detached worktree</div>
                    </div>
                    {trace.steps.map((st) => (
                      <div key={st.id} style={{ display: "flex", alignItems: "center" }}>
                        <div className="dag-arrow" />
                        <button
                          className={`dag-node ${stepClass(st)} ${
                            st.step_index === selectedStepIndex ? "selected" : ""
                          }`}
                          onClick={() => setSelectedStepIndex(st.step_index)}
                        >
                          <div className="dag-node-title">
                            <span>#{st.step_index} {st.tool_name || "final"}</span>
                            <span>{shortSHA(st.git_commit_sha)}</span>
                          </div>
                          <div className="dag-node-sub">
                            {st.exit_code !== null ? `exit:${st.exit_code}` : "reasoning"} · {st.duration_ms}ms
                            {st.raw_artifact_path ? " · spilled" : ""}
                          </div>
                        </button>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="inspector-body">
                  {!selectedStep ? (
                    <div className="empty-state">No steps recorded in this session yet.</div>
                  ) : (
                    <>
                      <div className="inspector-toolbar">
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          <button
                            className={`tab-btn ${inspectorTab === "diff" ? "active" : ""}`}
                            onClick={() => setInspectorTab("diff")}
                          >
                            Git Diff Inspector
                          </button>
                          <button
                            className={`tab-btn ${inspectorTab === "io" ? "active" : ""}`}
                            onClick={() => setInspectorTab("io")}
                          >
                            Tool I/O &amp; Telemetry
                          </button>
                          <span className="pill">
                            {shortSHA(selectedStep.parent_commit_sha)} → {shortSHA(selectedStep.git_commit_sha)}
                          </span>
                          <span className="pill">
                            in:{selectedStep.tokens_in} / out:{selectedStep.tokens_out}
                          </span>
                        </div>

                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          <input
                            className="fork-input"
                            placeholder="Optional fork task prompt..."
                            value={forkPrompt}
                            onChange={(e) => setForkPrompt(e.target.value)}
                          />
                          <button className="btn primary" onClick={() => void handleFork()} disabled={busy}>
                            Fork Here
                          </button>
                          <button className="btn danger" onClick={() => void handleRewind()} disabled={busy}>
                            Rewind to Step #{selectedStep.step_index}
                          </button>
                        </div>
                      </div>

                      <div className="inspector-content">
                        {inspectorTab === "diff" ? (
                          stepDiff && stepDiff.diff.trim() ? (
                            <div className="code-block">
                              {stepDiff.diff.split("\n").map((line, idx) => {
                                let cls = "diff-line";
                                if (line.startsWith("+") && !line.startsWith("+++")) cls += " diff-add";
                                else if (line.startsWith("-") && !line.startsWith("---")) cls += " diff-del";
                                else if (line.startsWith("@@")) cls += " diff-hunk";
                                return (
                                  <span key={idx} className={cls}>
                                    {line}
                                  </span>
                                );
                              })}
                            </div>
                          ) : (
                            <div className="empty-state">
                              No file mutations in step #{selectedStep.step_index} (commit unchanged).
                            </div>
                          )
                        ) : (
                          <div>
                            {selectedStep.thought && (
                              <>
                                <strong>Assistant Thought</strong>
                                <div className="code-block">{selectedStep.thought}</div>
                              </>
                            )}
                            {selectedStep.tool_name && (
                              <>
                                <strong>Tool Input ({selectedStep.tool_name})</strong>
                                <div className="code-block">{formatJSON(selectedStep.tool_input_json)}</div>
                              </>
                            )}
                            <strong>Compacted Output Summary</strong>
                            <div className="code-block">
                              {selectedStep.tool_output_summary || "(empty output)"}
                            </div>
                            {selectedStep.raw_artifact_path && (
                              <div style={{ marginTop: 12 }}>
                                <button
                                  className="btn primary"
                                  onClick={() => void handleLoadArtifact()}
                                  disabled={busy}
                                >
                                  Load Full Spilled Artifact ({selectedStep.raw_artifact_path})
                                </button>
                                {artifact && (
                                  <div className="code-block" style={{ marginTop: 10 }}>
                                    {artifact.content}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </section>
              </>
            )}
          </main>
        </div>
      ) : (
        <div className="inbox-container">
          <div className="inbox-filters">
            {(["all", "pending_approval", "active", "shadow_testing", "rejected"] as StatusFilter[]).map(
              (status) => (
                <button
                  key={status}
                  className={`tab-btn ${statusFilter === status ? "active" : ""}`}
                  onClick={() => setStatusFilter(status)}
                >
                  {status.replace("_", " ")}
                </button>
              )
            )}
          </div>

          <div className="inbox-list">
            {filteredEngrams.length === 0 ? (
              <div className="empty-state">No compiled engrams match this filter.</div>
            ) : (
              filteredEngrams.map((eng) => {
                const blockedByInvariant4 =
                  eng.source_session_id !== "" &&
                  (eng.kind === "hook" || eng.kind === "tool") &&
                  eng.shadow_pass_rate <= 0;

                return (
                  <article key={eng.id} className="engram-card">
                    <div className="engram-card-head">
                      <div className="engram-title">
                        <span>{eng.id}</span>
                        <span className="pill">{eng.kind}</span>
                        <span className={`status-dot status-${eng.status}`}>{eng.status}</span>
                        <span className="pill">shadow:{Math.round(eng.shadow_pass_rate * 100)}%</span>
                        <span className="pill">
                          prevented:{eng.times_prevented_error}/{eng.times_triggered}
                        </span>
                      </div>

                      <div className="engram-actions">
                        {eng.status !== "active" && (
                          <button
                            className="btn approve"
                            disabled={busy || blockedByInvariant4}
                            title={
                              blockedByInvariant4
                                ? "Invariant #4: Shadow replay verification required before activation"
                                : "Approve and activate this engram"
                            }
                            onClick={() => void handleApproveEngram(eng.id)}
                          >
                            Approve &amp; Activate
                          </button>
                        )}
                        {eng.status !== "rejected" && (
                          <button
                            className="btn danger"
                            disabled={busy}
                            onClick={() => void handleRejectEngram(eng.id)}
                          >
                            Reject
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="session-meta" style={{ marginBottom: 8 }}>
                      <span>trigger: {eng.trigger_pattern}</span>
                      <span>file: {eng.file_path}</span>
                      <span>signature: {eng.failure_signature}</span>
                    </div>

                    <div className="code-block">
                      {eng.source_code || "(source file not materialized on disk)"}
                    </div>
                  </article>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}