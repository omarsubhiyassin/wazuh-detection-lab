import type { Alert, Filters, Stats } from "./types";

/** Fetch error carrying the HTTP status so callers can react to 401s. */
export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function qs(f: Filters): string {
  const p = new URLSearchParams();
  p.set("range", f.range);
  if (f.technique) p.set("technique", f.technique);
  if (f.minLevel) p.set("minLevel", String(f.minLevel));
  if (f.host) p.set("host", f.host);
  if (f.search) p.set("search", f.search);
  return p.toString();
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new HttpError(res.status, `${url} -> HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const getStats = (f: Filters) => getJSON<Stats>(`/api/stats?${qs(f)}`);

export const getAlerts = (f: Filters, size = 100) =>
  getJSON<{ total: number; alerts: Alert[] }>(`/api/alerts?${qs(f)}&size=${size}`);

export const getHealth = () =>
  getJSON<{ ok: boolean; alerts?: number; index?: string }>(`/api/health`);

// --- Auth ----------------------------------------------------------------

export const getSession = () => getJSON<{ user: string }>(`/api/auth/session`);

export async function login(username: string, password: string): Promise<{ user: string }> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new HttpError(res.status, json?.error ?? `HTTP ${res.status}`);
  return json as { user: string };
}

export const logout = () =>
  fetch("/api/auth/logout", { method: "POST" }).then(() => undefined);
