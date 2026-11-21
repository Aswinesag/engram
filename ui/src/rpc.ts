export interface WorkspaceInfo {
  repo_root: string;
  model_provider: string;
  model_name: string;
  sandbox_mode: string;
  redact_secrets: boolean;
  allowed_domains: string[];
  active_engram_count: number;
  pending_engram_count: number;
  session_count: number;
  artifact_token_budget: number;
}

export interface SessionSummary {
  id: string;
  task_prompt: string;
  base_commit_sha: string;
  head_commit_sha: string;
  worktree_path: string;
  status: "running" | "completed" | "failed" | "aborted";
  step_count: number;
  error_count: number;
  tokens_in: number;
  tokens_out: number;
  duration_ms: number;
  created_at: string;
}

export interface StepNode {
  id: string;
  session_id: string;
  step_index: number;
  git_commit_sha: string;
  parent_commit_sha: string;
  thought: string;
  tool_name: string;
  tool_input_json: string;
  tool_output_summary: string;
  raw_artifact_path: string;
  exit_code: number | null;
  duration_ms: number;
  tokens_in: number;
  tokens_out: number;
  created_at: string;
}

export interface DagEdge {
  from: string;
  to: string;
}

export interface SessionTrace {
  session: {
    id: string;
    task_prompt: string;
    base_commit_sha: string;
    worktree_path: string;
    status: string;
    created_at: string;
  };
  steps: StepNode[];
  edges: DagEdge[];
}

export interface StepDiff {
  session_id: string;
  step_index: number;
  from_sha: string;
  to_sha: string;
  diff: string;
}

export interface StepArtifact {
  path: string;
  content: string;
}

export interface RewindResult {
  session_id: string;
  step_index: number;
  git_commit_sha: string;
  worktree_path: string;
}

export interface ForkResult {
  forked_session_id: string;
  source_session_id: string;
  source_step_index: number;
  base_commit_sha: string;
  worktree_path: string;
  task_prompt: string;
}

export interface EngramItem {
  id: string;
  kind: "hook" | "tool" | "rule";
  trigger_pattern: string;
  file_path: string;
  source_session_id: string;
  failure_signature: string;
  status: "shadow_testing" | "pending_approval" | "active" | "rejected";
  shadow_pass_rate: number;
  times_triggered: number;
  times_prevented_error: number;
  source_code: string;
  created_at: string;
}

interface RPCResponse<T> {
  jsonrpc: "2.0";
  id?: number | string;
  result?: T;
  error?: { code: number; message: string };
}

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

/**
 * EngramRPCClient communicates over WebSocket (/ws) JSON-RPC 2.0 with automatic
 * HTTP POST (/api/rpc) fallback so the dashboard remains resilient across reconnects.
 */
export class EngramRPCClient {
  private ws: WebSocket | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingCall>();
  private statusListeners = new Set<(connected: boolean) => void>();
  private reconnectTimer: number | null = null;
  private connected = false;

  constructor() {
    this.connect();
  }

  onStatusChange(listener: (connected: boolean) => void): () => void {
    this.statusListeners.add(listener);
    listener(this.connected);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  private setConnected(state: boolean): void {
    if (this.connected === state) return;
    this.connected = state;
    for (const fn of this.statusListeners) {
      fn(state);
    }
  }

  private connect(): void {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws`;
    try {
      const sock = new WebSocket(wsUrl);
      this.ws = sock;

      sock.onopen = () => {
        this.setConnected(true);
      };

      sock.onmessage = (event) => {
        try {
          const msg = JSON.parse(String(event.data)) as RPCResponse<unknown>;
          const id = typeof msg.id === "number" ? msg.id : Number(msg.id);
          const entry = this.pending.get(id);
          if (!entry) return;
          this.pending.delete(id);
          if (msg.error) {
            entry.reject(new Error(`${msg.error.message} (code ${msg.error.code})`));
          } else {
            entry.resolve(msg.result);
          }
        } catch {
          // Ignore malformed non-RPC frames.
        }
      };

      sock.onclose = () => {
        this.setConnected(false);
        this.ws = null;
        for (const [, entry] of this.pending) {
          entry.reject(new Error("WebSocket closed before response"));
        }
        this.pending.clear();
        this.scheduleReconnect();
      };

      sock.onerror = () => {
        sock.close();
      };
    } catch {
      this.setConnected(false);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 2500);
  }

  async call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params });

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return new Promise<T>((resolve, reject) => {
        this.pending.set(id, {
          resolve: (val) => resolve(val as T),
          reject,
        });
        this.ws!.send(payload);
      });
    }

    const resp = await fetch("/api/rpc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    }
    const data = (await resp.json()) as RPCResponse<T>;
    if (data.error) {
      throw new Error(`${data.error.message} (code ${data.error.code})`);
    }
    return data.result as T;
  }

  dispose(): void {
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}