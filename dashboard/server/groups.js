// Wazuh agent groups, for team-scoped filtering in the dashboard.
//
// WHY THIS TALKS TO THE MANAGER API, NOT THE INDEXER
//   Agent group membership is not in the alert documents — an alert's `agent`
//   object is only {id, name, ip}. The group lives on the manager. So to offer
//   "show me the Network team's alerts" we ask the manager API which agents are
//   in that group, then filter the alert query by those agent NAMES. The
//   indexer stays read-only and unaware of groups.
//
// WHAT THIS IS (AND IS NOT)
//   This backs a convenience FILTER, not access control. It answers "which
//   hosts are in this group" so the UI can scope the view. It does NOT decide
//   who is allowed to see what — any authenticated user can pick any group.
//   Real per-team isolation would be RBAC on top of this, deliberately not
//   built here.
//
// FAILURE POSTURE
//   The manager API is a soft dependency. If creds are unset or the API is
//   unreachable, group listing returns empty (the UI shows only "All") and a
//   group filter resolves to null so the caller can answer 503 rather than
//   silently showing everything or nothing. Down is not the same as "no hosts".
import https from "node:https";

const API_URL = (process.env.WAZUH_API_URL || "https://wazuh.manager:55000").replace(/\/$/, "");
const API_USER = process.env.WAZUH_API_USER || "";
const API_PASSWORD = process.env.WAZUH_API_PASSWORD || "";
const ENABLED = Boolean(API_USER && API_PASSWORD);

// The manager uses a self-signed cert, same as the indexer; trust it only here.
const agent = new https.Agent({ rejectUnauthorized: false });

// Caches. The token is a JWT the API issues on authenticate (~15 min default);
// we refresh well inside that. Membership changes rarely, so a short TTL keeps
// the dashboard responsive without hammering the manager.
const TOKEN_TTL_MS = 10 * 60_000;
const DATA_TTL_MS = Number(process.env.WAZUH_GROUPS_TTL_MS || 60_000);
let token = { value: null, at: 0 };
let cache = { data: null, at: 0 };

if (!ENABLED) {
  console.warn("[dashboard] WAZUH_API_USER/PASSWORD unset — group filtering disabled (All only)");
}

/** Low-level request. Returns { status, json }. Rejects only on transport error. */
function request(path, { method = "GET", auth, bearer } = {}) {
  const url = new URL(API_URL + path);
  const headers = {};
  if (auth) headers.Authorization = "Basic " + Buffer.from(auth).toString("base64");
  if (bearer) headers.Authorization = "Bearer " + bearer;
  return new Promise((resolve, reject) => {
    const r = https.request(url, { method, agent, headers }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch { /* leave null */ }
        resolve({ status: res.statusCode ?? 0, json, text: buf });
      });
    });
    r.on("error", reject);
    r.end();
  });
}

/** Get a bearer token, cached. Returns null on failure. */
async function authenticate() {
  if (token.value && Date.now() - token.at < TOKEN_TTL_MS) return token.value;
  try {
    const r = await request("/security/user/authenticate?raw=true",
      { method: "POST", auth: `${API_USER}:${API_PASSWORD}` });
    // raw=true returns the bare JWT as text, not JSON.
    const t = (r.text || "").trim();
    if (r.status === 200 && t.length > 20) {
      token = { value: t, at: Date.now() };
      return t;
    }
    console.error(`[dashboard] Wazuh API auth failed (HTTP ${r.status})`);
  } catch (e) {
    console.error("[dashboard] Wazuh API auth error:", String(e));
  }
  token = { value: null, at: 0 };
  return null;
}

/** One authenticated GET, re-authing once on a 401 (expired token). */
async function apiGet(path) {
  let t = await authenticate();
  if (!t) return null;
  let r = await request(path, { bearer: t });
  if (r.status === 401) {
    token = { value: null, at: 0 };
    t = await authenticate();
    if (!t) return null;
    r = await request(path, { bearer: t });
  }
  return r.status === 200 ? r.json : null;
}

/**
 * Refresh { groups: [{name, count}], members: { group: [agentName,...] } }.
 * Returns null (leaving any prior cache in place) if the API can't be reached,
 * so the caller can tell "unavailable" from "genuinely empty".
 */
async function refresh() {
  if (!ENABLED) return null;
  if (cache.data && Date.now() - cache.at < DATA_TTL_MS) return cache.data;

  // /groups is the authoritative list incl. empty groups; /agents gives the
  // membership (each agent carries its group array).
  const g = await apiGet("/groups?limit=500");
  const a = await apiGet("/agents?select=name,group&limit=100000");
  if (!g || !a) return null;

  const groups = (g.data?.affected_items || [])
    .map((it) => ({ name: it.name, count: Number(it.count ?? 0) }))
    .filter((x) => x.name);

  const members = {};
  for (const it of a.data?.affected_items || []) {
    const name = it.name;
    for (const grp of it.group || []) {
      (members[grp] ??= []).push(name);
    }
  }

  cache = { data: { groups, members }, at: Date.now() };
  return cache.data;
}

/** Group list with agent counts, for the switcher. Empty if unavailable. */
export async function list() {
  const d = await refresh();
  return d ? d.groups : [];
}

/**
 * Agent NAMES in a group. Returns:
 *   string[]  — the members (possibly empty: a real, empty group)
 *   null      — the mapping is unavailable (disabled or API down); the caller
 *               should surface that rather than guess.
 */
export async function agentsIn(name) {
  const d = await refresh();
  if (!d) return null;
  return d.members[name] || [];
}

export const enabled = () => ENABLED;
