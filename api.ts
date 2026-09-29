import {
  DashboardStats, EnrolledClient, PhishingRule, ReportData, ThreatAlert,
  UrlEvent, UrlEventsPage, WhitelistRule
} from "./types";

/**
 * Dashboard API client. Every call either returns real server data or THROWS an
 * ApiError carrying the server's message — nothing here ever converts a failed
 * request into an empty list, so views can't mistake "request failed" for
 * "there is no data".
 */
export class ApiError extends Error {
  constructor(public status: number, message: string, public code?: string) {
    super(message);
  }
}

const TIMEOUT_MS = 20_000;

function anySignal(a: AbortSignal, b: AbortSignal): AbortSignal {
  const c = new AbortController();
  const abort = () => c.abort();
  if (a.aborted || b.aborted) c.abort();
  a.addEventListener("abort", abort, { once: true });
  b.addEventListener("abort", abort, { once: true });
  return c.signal;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      signal: init?.signal ? anySignal(init.signal, ctrl.signal) : ctrl.signal,
      cache: "no-store",
      credentials: "same-origin",
      headers: { ...(init?.body ? { "Content-Type": "application/json" } : {}), ...(init?.headers || {}) }
    });
  } catch (e: any) {
    if (e?.name === "AbortError") {
      if (init?.signal?.aborted) throw e; // caller cancelled (superseded request) — not an error
      throw new ApiError(0, "The server took too long to respond", "timeout");
    }
    throw new ApiError(0, "Could not reach the server — check your connection", "network");
  } finally {
    clearTimeout(timer);
  }
  let body: any = null;
  try { body = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    throw new ApiError(res.status, body?.error || `Request failed (HTTP ${res.status})`, body?.code);
  }
  return body as T;
}

export const isAbort = (e: unknown) => e instanceof DOMException && e.name === "AbortError";
export const errMsg = (e: unknown, fallback = "Something went wrong") =>
  e instanceof ApiError || e instanceof Error ? e.message : fallback;

const scope = (clientId?: string) =>
  clientId && clientId !== "ALL" ? `?clientId=${encodeURIComponent(clientId)}` : "";

export const fetchStats = (clientId?: string, signal?: AbortSignal) =>
  request<DashboardStats>(`/api/stats${scope(clientId)}`, { signal });

export async function fetchClients(signal?: AbortSignal): Promise<EnrolledClient[]> {
  return (await request<{ clients: EnrolledClient[] }>("/api/clients", { signal })).clients;
}

export const fetchClientDetails = (id: string) =>
  request<{ client: EnrolledClient; events: UrlEvent[]; alerts: ThreatAlert[]; eventsTotal: number; eventsHasMore: boolean }>(
    `/api/clients/${encodeURIComponent(id)}`
  );

export async function deleteClient(id: string): Promise<void> {
  await request(`/api/clients/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function fetchEvents(params?: {
  clientId?: string; classification?: string; search?: string; limit?: number; offset?: number;
}, signal?: AbortSignal): Promise<UrlEventsPage> {
  const q = new URLSearchParams();
  if (params?.clientId && params.clientId !== "ALL") q.set("clientId", params.clientId);
  if (params?.classification && params.classification !== "ALL") q.set("classification", params.classification);
  if (params?.search) q.set("search", params.search);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  return request<UrlEventsPage>(`/api/events?${q.toString()}`, { signal });
}

export async function fetchThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
  return (await request<{ alerts: ThreatAlert[] }>(`/api/threats${scope(clientId)}`)).alerts;
}

export async function updateAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED" | "ACTIVE"): Promise<void> {
  await request(`/api/threats/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) });
}

export const fetchRules = () =>
  request<{ whitelist: WhitelistRule[]; phishing: PhishingRule[]; version: number }>("/api/rules");

export async function addWhitelistRule(pattern: string, description: string): Promise<WhitelistRule> {
  return (await request<{ rule: WhitelistRule }>("/api/rules/whitelist", { method: "POST", body: JSON.stringify({ pattern, description }) })).rule;
}
export async function addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string): Promise<PhishingRule> {
  return (await request<{ rule: PhishingRule }>("/api/rules/phishing", { method: "POST", body: JSON.stringify({ pattern, severity, reason }) })).rule;
}
export async function updateWhitelistRule(id: string, patch: Partial<Pick<WhitelistRule, "pattern" | "description" | "enabled">>): Promise<WhitelistRule> {
  return (await request<{ rule: WhitelistRule }>(`/api/rules/whitelist/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) })).rule;
}
export async function updatePhishingRule(id: string, patch: Partial<Pick<PhishingRule, "pattern" | "reason" | "severity" | "enabled">>): Promise<PhishingRule> {
  return (await request<{ rule: PhishingRule }>(`/api/rules/phishing/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) })).rule;
}
export async function deleteWhitelistRule(id: string): Promise<void> {
  await request(`/api/rules/whitelist/${encodeURIComponent(id)}`, { method: "DELETE" });
}
export async function deletePhishingRule(id: string): Promise<void> {
  await request(`/api/rules/phishing/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export const fetchServerInfo = () =>
  request<{ serverUrl: string; version: string; status: string; dashboardProtected?: boolean; enrollmentKeyRequired?: boolean }>("/api/info");

export const fetchHealth = () =>
  request<{ status: string; database: string; schemaVersion: string }>("/api/health");

export const fetchReportData = (clientId?: string) => request<ReportData>(`/api/reports${scope(clientId)}`);

export function getDownloadExtensionUrl(): string {
  return "/api/download-extension";
}
