// Backend-for-frontend for the detection-lab dashboard.
//
// Holds the read-only indexer credentials server-side (the browser only ever
// talks to same-origin /api) and exposes a small, purpose-built API over the
// Wazuh alerts index. In production it also serves the built SPA from dist/.
import express from "express";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installAuth, requireRole } from "./auth.js";
import * as audit from "./audit.js";
import * as triage from "./triage.js";
import * as analysis from "./analysis.js";
import * as metrics from "./metrics.js";
import * as coverage from "./coverage.js";

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
// else under /api. Login/logout are recorded to the audit log. See server/auth.js.
installAuth(app, { onAuthEvent: (e) => audit.record(e) });

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
      // Which hosts are producing alerts, how severe, and how recently. NOTE:
      // this is alert activity, not agent connectivity — the read-only account
      // only sees the alerts index, so a quiet host looks the same as an
      // offline one. The UI labels it as "last alert", never "online".
      by_agent: {
        terms: { field: "agent.name", size: 12 },
        aggs: {
          max_level: { max: { field: "rule.level" } },
          last_seen: { max: { field: "timestamp" } },
        },
      },
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
      byAgent: (a.by_agent?.buckets || []).map((b) => ({
        name: b.key,
        count: b.doc_count,
        maxLevel: Math.round(b.max_level.value ?? 0),
        lastSeen: b.last_seen.value_as_string ?? null,
      })),
      // Global triage queue (from the BFF store, not the indexer). These are
      // whole-store counts and are deliberately NOT narrowed by the current
      // filters — the queue is "everything outstanding", not "outstanding on
      // this page".
      triageCounts: triage.counts(),
      aiAwaiting: resolveIdFilter({ ai: "awaiting" })?.length ?? 0,
    });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// Triage state and AI findings live on the BFF, not in the indexer, so they
// cannot be expressed as a query clause. Resolve them to alert ids here and
// push those into the indexer query instead — otherwise the filter only ever
// applies to whichever page the browser already loaded, and "closed alerts"
// silently means "closed alerts among the most recent 500".
//
// Returns null when no such filter is requested, or an array (possibly EMPTY —
// which must yield zero results, not every result).
const ID_FILTER_CAP = 1024;

function resolveIdFilter(q) {
  const sets = [];

  if (q.triage && triage.STATUSES.includes(q.triage)) {
    sets.push(triage.idsByStatus(q.triage));
  }

  if (q.ai === "flagged" || q.ai === "awaiting") {
    const flagged = analysis.flaggedIds();
    if (q.ai === "flagged") sets.push(flagged);
    else {
      // "Awaiting human review" = the AI flagged it and no human has moved it
      // past `new`. Mirrors reviewOf() in the SPA; kept here so the queue is a
      // real queue rather than a view of one page.
      const byId = triage.getMany(flagged);
      sets.push(flagged.filter((id) => !byId[id] || byId[id].status === "new"));
    }
  }

  if (!sets.length) return null;
  const ids = sets.reduce((acc, s) => acc.filter((id) => s.includes(id)));
  return ids.slice(0, ID_FILTER_CAP);
}

app.get("/api/alerts", async (req, res) => {
  const size = Math.min(Number(req.query.size || 100), 500);
  const idFilter = resolveIdFilter(req.query);
  // An empty id set means "nothing matches" — never fall through to unfiltered.
  if (idFilter && idFilter.length === 0) {
    return res.json({ total: 0, alerts: [] });
  }
  const query = buildQuery(req.query);
  if (idFilter) query.bool.filter.push({ ids: { values: idFilter } });
  const body = {
    size,
    query,
    sort: [{ timestamp: "desc" }],
    _source: ["timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
      "rule.mitre", "agent.name", "agent.ip", "location", "full_log", "data", "decoder.name"],
  };
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_search`, "POST", body);
    if (r.status >= 400) return res.status(502).json({ error: "indexer", status: r.status, detail: r.json });
    const hits = r.json.hits?.hits || [];
    const ids = hits.map((h) => h._id);
    const triageById = triage.getMany(ids);
    const aiById = analysis.getMany(ids);
    res.json({
      total: r.json.hits?.total?.value ?? 0,
      alerts: hits.map((h) => ({
        id: h._id,
        source: h._source,
        triage: triageById[h._id] ?? null,
        ai: aiById[h._id] ?? null,
      })),
    });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// --- Triage (analyst+): set/read an alert's workflow state -------------------
// The ONLY path that advances or closes an investigation. requireRole gates it
// to an authenticated analyst+, and the acting username is taken from the
// session — never from the request body — so a caller cannot act as someone
// else. The AI layer has no route here by design.
app.post("/api/alerts/:id/triage", requireRole("analyst"), async (req, res) => {
  const { status, assignee, note, aiVerdict, disposition } = req.body || {};
  // Stamp the alert's identity onto the record from the INDEXER, not from the
  // request body — the client could claim any rule, and these facts are what
  // the efficacy metrics are grouped by. Looked up once, then reused.
  let context;
  if (!triage.get(req.params.id)?.context) {
    context = await alertContext(req.params.id);
  }
  const result = triage.set(req.params.id,
    { status, assignee, note, aiVerdict, disposition, context }, req.session.user);
  if (!result.ok) return res.status(400).json({ error: result.error });
  audit.record({ action: "triage", user: req.session.user, alertId: req.params.id,
    status: result.record.status, assignee: result.record.assignee,
    aiVerdict: result.record.aiVerdict, disposition: result.record.disposition,
    ruleId: result.record.context?.ruleId ?? null });
  res.json({ id: req.params.id, triage: result.record });
});

/**
 * Look up the durable facts about one alert. Denormalized into the triage
 * record so metrics still work after ISM deletes the alert's index. Returns
 * undefined if the alert can't be read — triage must not fail because the
 * lookup did.
 */
async function alertContext(id) {
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_search`, "POST", {
      size: 1,
      query: { ids: { values: [id] } },
      _source: ["timestamp", "rule.id", "rule.level", "rule.description", "agent.name"],
    });
    const s = r.json?.hits?.hits?.[0]?._source;
    if (!s) return undefined;
    return {
      ruleId: s.rule?.id ?? null,
      ruleLevel: s.rule?.level ?? null,
      description: s.rule?.description ?? null,
      host: s.agent?.name ?? null,
      alertTs: s.timestamp ?? null,
    };
  } catch {
    return undefined;
  }
}

// --- Detection efficacy metrics ----------------------------------------------
// Closes the loop: which of our own rules are noisy, how fast alerts get
// handled, and how often analysts agreed with the scorer. Read-only aggregate,
// so any signed-in role may see it.
app.get("/api/metrics", (_req, res) => {
  res.json(metrics.compute());
});

// --- ATT&CK coverage ----------------------------------------------------------
// Which techniques our own ruleset actually covers. Cross-referenced in the UI
// against observed alerts so "no rule" and "rule fired nothing" stop looking
// alike. Read from detections/rules/local_rules.xml (DASH_RULES_FILE).
app.get("/api/coverage", (_req, res) => {
  res.json(coverage.read());
});

// --- AI analysis (advisory only) ---------------------------------------------
// Runs the scoring pass over the current filter window and stores advisory
// findings. It cannot mark anything reviewed, resolved, or closed — those live
// in the triage store above and require a human.
app.post("/api/analysis/run", requireRole("analyst"), async (req, res) => {
  const size = Math.min(Number(req.body?.size || 200), 500);
  const body = {
    size,
    query: buildQuery(req.body?.filters || {}),
    sort: [{ timestamp: "desc" }],
    _source: ["timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
      "rule.mitre", "agent.name", "agent.ip", "location", "full_log", "data", "decoder.name"],
  };
  try {
    const r = await indexer(`/${encodeURIComponent(ALERTS_INDEX)}/_search`, "POST", body);
    if (r.status >= 400) return res.status(502).json({ error: "indexer", status: r.status });
    const alerts = (r.json.hits?.hits || []).map((h) => ({ id: h._id, source: h._source }));
    const summary = await analysis.run(alerts, req.session.user);
    audit.record({ action: "analysis_run", user: req.session.user,
      considered: summary.considered, flagged: summary.flagged, llm: summary.llm });
    res.json(summary);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// Current advisory findings + the scoring configuration (so the ranking is
// inspectable rather than a black box).
app.get("/api/analysis", (_req, res) => {
  res.json({ findings: analysis.all(), config: analysis.config() });
});

// --- Audit log (admin only) ---------------------------------------------------
app.get("/api/audit", requireRole("admin"), (req, res) => {
  res.json({ events: audit.readRecent(Math.min(Number(req.query.limit || 200), 1000)) });
});

// --- Triage housekeeping ------------------------------------------------------
// Open records whose alert has aged out of the indexer can never be actioned,
// and until removed they inflate the queue counts — the sidebar would report
// work that no longer exists. Closed records are kept (they are the efficacy
// history) unless DASH_CLOSED_RETENTION_DAYS is set. Run at start and daily;
// the result is audited because it deletes workflow records.
function pruneTriage(reason) {
  const summary = triage.prune();
  if (summary.orphaned || summary.expired) {
    console.log(`[dashboard] triage prune (${reason}):`, JSON.stringify(summary));
    audit.record({ action: "triage_prune", user: "system", reason, ...summary });
  }
  return summary;
}
pruneTriage("startup");
setInterval(() => pruneTriage("scheduled"), 24 * 3600_000).unref();

// --- Static SPA (production) --------------------------------------------------
const distDir = path.join(__dirname, "..", "dist");
app.use(express.static(distDir));
app.get("*", (_req, res) => res.sendFile(path.join(distDir, "index.html")));

// Serve HTTPS when a cert/key pair is configured (bootstrap generates one and
// sets DASH_TLS_CERT/DASH_TLS_KEY in .env); plain HTTP otherwise (dev).
const TLS_CERT = process.env.DASH_TLS_CERT || "";
const TLS_KEY = process.env.DASH_TLS_KEY || "";
if (TLS_CERT && TLS_KEY) {
  https
    .createServer({ cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) }, app)
    .listen(PORT, () => {
      console.log(`[dashboard] BFF on https://localhost:${PORT}  ->  ${INDEXER_URL} (${ALERTS_INDEX})`);
    });
} else {
  app.listen(PORT, () => {
    console.log(`[dashboard] BFF on http://localhost:${PORT}  ->  ${INDEXER_URL} (${ALERTS_INDEX})`);
  });
}
