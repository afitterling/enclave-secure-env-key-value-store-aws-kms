/** Thin fetch wrapper for the enclave-envoy API. Mirrors cli/enclave/client.py. */

const API_URL = ((import.meta.env.VITE_API_URL as string) ?? "").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let token: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setToken(t: string | null) {
  token = t;
}

export function setOnUnauthorized(fn: (() => void) | null) {
  onUnauthorized = fn;
}

async function request<T>(path: string, init: { method?: string; body?: unknown; auth?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (init.body !== undefined) headers["content-type"] = "application/json";
  if (init.auth !== false && token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${API_URL}${path}`, {
    method: init.method ?? (init.body !== undefined ? "POST" : "GET"),
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  if (res.status === 401 && init.auth !== false) onUnauthorized?.();
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error ?? msg;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg);
  }
  return (res.status === 204 ? {} : await res.json()) as T;
}

// ---- auth ------------------------------------------------------------------

export const authRequest = (email: string, signup = false) =>
  request<{ message: string }>("/auth/request", { body: { email, signup }, auth: false });

export const authVerify = (email: string, code: string) =>
  request<{ token: string; email: string; access: Record<string, string[]> }>("/auth/verify", {
    body: { email, code },
    auth: false,
  });

export const whoami = () => request<{ email: string; access: Record<string, string[]> }>("/access/whoami");

// ---- crypto ----------------------------------------------------------------

export const datakeyGenerate = (project: string, stage: string) =>
  request<{ plaintext: string; ciphertext: string }>("/crypto/datakey", {
    body: { op: "generate", project, stage },
  });

export const datakeyDecrypt = (project: string, stage: string, ciphertextB64: string) =>
  request<{ plaintext: string }>("/crypto/datakey", {
    body: { op: "decrypt", project, stage, ciphertext: ciphertextB64 },
  });

// ---- s3 --------------------------------------------------------------------

export interface Presigned {
  url: string;
  method: string;
  key: string;
  expiresIn: number;
}

export const presign = (op: "upload" | "download" | "delete", project: string, stage: string, file: string) =>
  request<Presigned>("/s3/presign", { body: { op, project, stage, file } });

export const listFiles = (project: string, stage: string) =>
  request<{ prefix: string; files: string[] }>("/s3/presign", { body: { op: "list", project, stage } });

// ---- admin: projects -------------------------------------------------------

export interface ProjectSummary {
  project: string;
  role: "owner" | "member";
  stages: string[];
  owner: string | null;
}

export interface MachineBinding {
  id: string;
  kind: "oidc" | "aws";
  issuer?: string;
  audience?: string;
  claims?: Record<string, string>;
  account?: string;
  role?: string;
  stages: string[];
  access: "read" | "write";
  description?: string;
  createdBy?: string;
  createdAt?: string;
  grantExpiresAt?: string;
}

export interface ProjectDetail {
  project: string;
  owner: string;
  members: { email: string; role: string; stages: string[]; grantExpiresAt?: string }[];
  teams: { team: string; stages: string[] }[];
  machines?: MachineBinding[];
}

export const listProjects = () => request<{ projects: ProjectSummary[] }>("/admin/projects");
export const createProject = (project: string) =>
  request<{ project: string; role: string }>("/admin/projects", { body: { project } });
export const projectDetail = (project: string) => request<ProjectDetail>(`/admin/projects/${project}`);
export const addProjectMember = (project: string, email: string, stages: string[], expiresInHours?: number) =>
  request<{ ok: true }>(`/admin/projects/${project}/members`, {
    body: { email, stages, ...(expiresInHours ? { expiresInHours } : {}) },
  });
export const removeProjectMember = (project: string, email: string) =>
  request<{ ok: true }>(`/admin/projects/${project}/members/remove`, { body: { email } });
export const grantTeam = (project: string, team: string, stages: string[]) =>
  request<{ ok: true }>(`/admin/projects/${project}/teams`, { body: { team, stages } });
export const revokeTeam = (project: string, team: string) =>
  request<{ ok: true }>(`/admin/projects/${project}/teams/remove`, { body: { team } });

// ---- admin: teams ----------------------------------------------------------

export interface TeamSummary {
  team: string;
  role: "owner" | "member";
  owner: string | null;
}

export interface TeamDetail {
  team: string;
  owner: string;
  members: { email: string; role: string }[];
  grants: { project: string; stages: string[] }[];
}

export const listTeams = () => request<{ teams: TeamSummary[] }>("/admin/teams");
export const createTeam = (team: string) => request<{ team: string }>("/admin/teams", { body: { team } });
export const teamDetail = (team: string) => request<TeamDetail>(`/admin/teams/${team}`);
export const addTeamMember = (team: string, email: string) =>
  request<{ ok: true }>(`/admin/teams/${team}/members`, { body: { email } });
export const removeTeamMember = (team: string, email: string) =>
  request<{ ok: true }>(`/admin/teams/${team}/members/remove`, { body: { email } });

// ---- admin: machine identities ---------------------------------------------

export const workloadInfo = () =>
  request<{ audience: string; serverIdHeader: string }>("/auth/workload", { auth: false });
export const upsertMachine = (
  project: string,
  binding: Omit<MachineBinding, "createdBy" | "createdAt" | "grantExpiresAt">,
  expiresInHours?: number,
) =>
  request<{ ok: true; id: string }>(`/admin/projects/${project}/machines`, {
    body: { ...binding, ...(expiresInHours ? { expiresInHours } : {}) },
  });
export const removeMachine = (project: string, id: string) =>
  request<{ ok: true }>(`/admin/projects/${project}/machines/remove`, { body: { id } });

// ---- admin: CIEM (enterprise) ----------------------------------------------

export interface StageUsage {
  lastRead?: string;
  lastWrite?: string;
  reads: number;
  writes: number;
}

export interface Entitlement {
  principal: string;
  kind: "human" | "machine";
  via: string;
  stages: string[];
  access: "read" | "write";
  grantedAt?: string;
  grantExpiresAt?: string;
  expired: boolean;
  usage: Record<string, StageUsage>;
  lastUsed?: string;
}

export type Fix =
  | { kind: "removeStage"; principal: string; via: string; stage: string }
  | { kind: "removePrincipal"; principal: string; via: string }
  | { kind: "downgrade"; principal: string; via: string }
  | { kind: "timebox"; principal: string; via: string };

export interface Finding {
  id: string;
  rule: string;
  severity: "high" | "medium" | "low";
  principal: string;
  via: string;
  stage?: string;
  title: string;
  detail: string;
  fix?: Fix;
}

export interface EntitlementReport {
  project: string;
  windowDays: number;
  utilization: { granted: number; used: number; ratio: number };
  entitlements: Entitlement[];
  findings: Finding[];
}

export interface AuditEvent {
  at: string;
  principal: string;
  kind: "human" | "machine" | "runner";
  actor?: string;
  stage: string;
  action: string;
  file?: string;
  ip?: string;
  src?: string;
  detail?: Record<string, string>;
}

export const entitlements = (project: string) =>
  request<EntitlementReport>(`/admin/projects/${project}/entitlements`);
export const auditLog = (project: string, cursor?: string | null) =>
  request<{ events: AuditEvent[]; cursor: string | null }>(
    `/admin/projects/${project}/audit?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
  );
