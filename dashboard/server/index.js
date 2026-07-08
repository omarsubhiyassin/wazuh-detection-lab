// Backend-for-frontend for the detection-lab dashboard.
//
// Holds the read-only indexer credentials server-side (the browser only ever
// talks to same-origin /api) and exposes a small, purpose-built API over the
// Wazuh alerts index. In production it also serves the built SPA from dist/.
import express from "express";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installAuth } from "./auth.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const INDEXER_URL = process.env.INDEXER_URL || "https://localhost:9200";
const RO_USER = process.env.INDEXER_RO_USER || "detectionlab_ro";
const RO_PASSWORD = process.env.INDEXER_RO_PASSWORD || "";
const ALERTS_INDEX = process.env.ALERTS_INDEX || "wazuh-alerts-*";
const PORT = Number(process.env.PORT || 8787);

if (!RO_PASSWORD) {
  console.warn("[dashboard] INDEXER_RO_PASSWORD is empty — set it in dashboard/.env");
}

const AUTH = "Basic " + Buffer.from(`${RO_USER}:${RO_PASSWORD}`).toString("base64");
// The lab indexer uses a self-signed cert; trust it only for this known host.
const agent = new https.Agent({ rejectUnauthorized: false });

/** Query the indexer. Returns { status, json }. */
function indexer(reqPath, method = "GET", body = null) {
  const url = new URL(INDEXER_URL.replace(/\/$/, "") + reqPath);
  const data = body ? JSON.stringify(body) : null;
  const options = {
    method,
    agent,
    headers: {
      "Content-Type": "application/json",
      Authorization: AUTH,
      ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
    },
  };
  return new Promise((resolve, reject) => {
    const r = https.request(url, options, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch { /* leave null */ }
        resolve({ status: res.statusCode ?? 0, json });
      });
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

/** Build a timestamp range filter from a shorthand like "24h", "7d", or "all". */
function rangeFilter(range) {
  if (!range || range === "all") return [];
  if (!/^\d+[smhdwMy]$/.test(range)) return [];
  return [{ range: { timestamp: { gte: `now-${range}` } } }];
}

/** Assemble the bool query used by the alerts + stats endpoints. */
function buildQuery(q) {
  const must = [];
  const filter = [...rangeFilter(q.range)];
  if (q.technique) filter.push({ term: { "rule.mitre.id": q.technique } });
  if (q.host) filter.push({ term: { "agent.name": q.host } });
  if (q.minLevel) filter.push({ range: { "rule.level": { gte: Number(q.minLevel) } } });
  if (q.search) {
    must.push({
      simple_query_string: {
        query: q.search,
        fields: ["rule.description", "full_log", "data.srcip", "agent.name"],
        default_operator: "and",
      },
    });
  }
  return { bool: { must: must.length ? must : [{ match_all: {} }], filter } };
}

const app = express();
app.use(express.json());

// --- Auth ----------------------------------------------------------------------
// Registers /api/auth/login|logout|session and a session guard on everything
// else under /api. See server/auth.js.
installAuth(app);

// --- API ---------------------------------------------------------------------

app.get("/api/health", async (_req, res) => {
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_count`, "GET");
    if (r.status >= 400) return res.status(502).json({ ok: false, status: r.status });
    res.json({ ok: true, alerts: r.json?.count ?? 0, index: ALERTS_INDEX });
  } catch (e) {
    res.status(502).json({ ok: false, error: String(e) });
  }
});

app.get("/api/stats", async (req, res) => {
  const query = buildQuery(req.query);
  const body = {
    size: 0,
    query,
    aggs: {
      by_level: { terms: { field: "rule.level", size: 16 } },
      by_technique: {
        terms: { field: "rule.mitre.id", size: 50 },
        aggs: {
          max_level: { max: { field: "rule.level" } },
          tactic: { terms: { field: "rule.mitre.tactic", size: 1 } },
        },
      },
      over_time: { auto_date_histogram: { field: "timestamp", buckets: 48 } },
    },
  };
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_search`, "POST", body);
    if (r.status >= 400) return res.status(502).json({ error: "indexer", status: r.status, detail: r.json });
    const a = r.json.aggregations;
    res.json({
      total: r.json.hits?.total?.value ?? 0,
      byLevel: (a.by_level.buckets || []).map((b) => ({ level: b.key, count: b.doc_count })),
      byTechnique: (a.by_technique.buckets || []).map((b) => ({
        id: b.key,
        count: b.doc_count,
        maxLevel: Math.round(b.max_level.value ?? 0),
        tactic: b.tactic.buckets?.[0]?.key ?? null,
      })),
      overTime: (a.over_time.buckets || []).map((b) => ({ t: b.key, count: b.doc_count })),
    });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

app.get("/api/alerts", async (req, res) => {
  const size = Math.min(Number(req.query.size || 100), 500);
  const body = {
    size,
    query: buildQuery(req.query),
    sort: [{ timestamp: "desc" }],
    _source: ["timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
      "rule.mitre", "agent.name", "agent.ip", "location", "full_log", "data", "decoder.name"],
  };
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_search`, "POST", body);
    if (r.status >= 400) return res.status(502).json({ error: "indexer", status: r.status, detail: r.json });
    res.json({
      total: r.json.hits?.total?.value ?? 0,
      alerts: (r.json.hits?.hits || []).map((h) => ({ id: h._id, source: h._source })),
    });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// --- Static SPA (production) --------------------------------------------------
const distDir = path.join(__dirname, "..", "dist");
app.use(express.static(distDir));
app.get("*", (_req, res) => res.sendFile(path.join(distDir, "index.html")));

app.listen(PORT, () => {
  console.log(`[dashboard] BFF on http://localhost:${PORT}  ->  ${INDEXER_URL} (${ALERTS_INDEX})`);
});
