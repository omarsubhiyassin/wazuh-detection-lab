import type { Alert, Filters, Stats } from "./types";

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
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const getStats = (f: Filters) => getJSON<Stats>(`/api/stats?${qs(f)}`);

export const getAlerts = (f: Filters, size = 100) =>
  getJSON<{ total: number; alerts: Alert[] }>(`/api/alerts?${qs(f)}&size=${size}`);

export const getHealth = () =>
  getJSON<{ ok: boolean; alerts?: number; index?: string }>(`/api/health`);
