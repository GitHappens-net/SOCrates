/* ── SOCrates backend API client ────────────────────────────────── */

import type {
  ApiAlert,
  ApiChatResponse,
  ApiDevice,
  ApiLog,
  ApiStats,
} from "../types";

const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

async function del<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

/* ── Alerts ───────────────────────────────────────────────────────── */

export function fetchAlerts(params?: {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<ApiAlert[]> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return get(`/alerts${qs ? `?${qs}` : ""}`);
}

export function fetchAlert(id: number): Promise<ApiAlert> {
  return get(`/alerts/${id}`);
}

export function patchAlertStatus(
  id: number,
  status: string,
): Promise<ApiAlert> {
  return patch(`/alerts/${id}`, { status });
}

export function clearAlerts(): Promise<{ cleared: number }> {
  return del("/alerts");
}

/* ── Devices ──────────────────────────────────────────────────────── */

export function fetchDevices(): Promise<ApiDevice[]> {
  return get("/devices");
}

/* ── Logs ─────────────────────────────────────────────────────────── */

export function fetchLogs(params?: {
  limit?: number;
  offset?: number;
}): Promise<ApiLog[]> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return get(`/logs${qs ? `?${qs}` : ""}`);
}

export function fetchDeviceLogs(
  ip: string,
  params?: { limit?: number; offset?: number },
): Promise<ApiLog[]> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return get(`/devices/${ip}/logs${qs ? `?${qs}` : ""}`);
}

/* ── Stats ────────────────────────────────────────────────────────── */

export function fetchStats(): Promise<ApiStats> {
  return get("/stats");
}

/* ── Chat ─────────────────────────────────────────────────────────── */

export function sendChat(
  message: string,
  sessionId = "default",
): Promise<ApiChatResponse> {
  return post("/chat", { message, session_id: sessionId });
}

export function clearChat(
  sessionId = "default",
): Promise<{ cleared: boolean }> {
  return del("/chat", { session_id: sessionId });
}
