/**
 * Thin typed client over the IR-SAM API.
 *
 * All requests go through the Next.js rewrite at /api/* so the browser
 * stays same-origin and the API's HttpOnly cookie just works.
 */

export class ApiError extends Error {
  constructor(public status: number, public payload: unknown) {
    super(`API ${status}`);
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  init?: RequestInit,
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: payload,
    credentials: "include",
    cache: "no-store",
    ...init,
  });
  const text = await res.text();
  const json = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiError(res.status, json ?? text);
  return json as T;
}

function safeJson(s: string): unknown {
  try { return JSON.parse(s); } catch { return s; }
}

export const api = {
  get:   <T>(p: string)                 => request<T>("GET", p),
  post:  <T>(p: string, body?: unknown) => request<T>("POST", p, body),
  patch: <T>(p: string, body?: unknown) => request<T>("PATCH", p, body),
  del:   <T>(p: string)                 => request<T>("DELETE", p),
};

// --- Types (kept close to backend Pydantic schemas) ----------------------

export type User = { id: string; email: string; role: string; created_at: string };

export type Project = {
  id: string; owner_id: string; name: string; source_type: "upload" | "git" | "sarif";
  git_url: string | null; default_branch: string | null;
  settings: Record<string, unknown>; created_at: string;
};

export type Scan = {
  id: string; project_id: string; status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  trigger: string; commit_sha: string | null;
  started_at: string | null; finished_at: string | null;
  stats: Record<string, unknown>; created_at: string;
};

export type Finding = {
  id: string; scan_id: string; rule_id: string; cwe: string;
  file_path: string; line: number; sink_api: string; severity: string;
  state: "open" | "dismissed" | "wont_fix"; created_at: string;
};

export type PatchProposal = {
  id: string; finding_id: string; stage_reached: string;
  unified_diff: string | null; status: string;
  decided_at: string | null; created_at: string;
  plan?: {
    prepared_template?: string | null;
    binders_used?: string[];
    proof_status?: string;
    safety_claim?: string;
    abstention_reason?: string | null;
    all_gates_passed?: boolean;
  } | null;
  gate_report?: { gates: Array<{ name: string; passed: boolean; detail?: string }> } | null;
};

export type Gate = { name: string; passed: boolean; detail: string };

export type QuickfixResult = {
  request_id: string; language: string; elapsed_ms: number;
  result: {
    file: string; stage_reached: string; patched: boolean;
    all_gates_passed: boolean; abstention_reason: string | null;
    unified_diff: string | null; patched_source: string | null;
    prepared_template: string | null; binders_used: string[];
    gates: Gate[];
  };
};
