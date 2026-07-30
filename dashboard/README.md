# Custom ATT&CK dashboard

A React (Vite + TypeScript) SPA over a thin Express **backend-for-frontend (BFF)**.
The BFF holds the indexer's **read-only** service account and proxies a small,
purpose-built API over `wazuh-alerts-*`; the browser only ever talks to same-origin
`/api` and never sees the credentials.

## Views
- **ATT&CK matrix** — techniques placed in their tactic columns, heat-colored by alert
  count. Click a cell to filter the alert feed to that technique.
- **Stat tiles** — total / critical / high alerts, techniques seen, activity sparkline.
- **Alert feed** — time, level, MITRE technique tags, rule, description, host. Click a row
  for a **detail drawer** with the MITRE mapping, raw log, and full `_source`.
- **Filters** — time range, minimum level, host, free-text search.
- **Sidebar** — saved views, the triage queue, and the **AI review queue**
  (see [AI-assisted triage](#ai-assisted-triage-advisory-only)).
- **Fleet rail** — hosts ranked by alert volume, and the top techniques seen.

## Prerequisites
- **Node.js 18+** (for global `fetch`/`https.Agent` and `node --watch`).
- The lab stack up, and the read-only account created on the indexer
  (`detectionlab_ro`). See the "read-only service account" note in
  [../infra/README.md](../infra/README.md).

## Run

```bash
cd dashboard
cp .env.example .env         # set INDEXER_RO_PASSWORD to the account's password
npm install
npm run hash-password        # prompts for the dashboard login password;
                             # paste the DASH_PASSWORD_HASH line into .env

# dev: Vite (5173) + BFF (8787), with /api proxied to the BFF
npm run dev
# open http://localhost:5173

# production: build the SPA and serve everything from the BFF
npm run build && npm start   # open http://localhost:8787
```

## Detection efficacy metrics

Closes the loop the rest of the app opens: rules produce alerts → analysts triage them →
the aggregate says **which of our own detections are noisy**. Open it from *efficacy* in
the header (`GET /api/metrics`, any signed-in role).

Closing an alert requires stating an **outcome**, enforced server-side:

| Disposition | Meaning | Counts against the rule? |
|---|---|---|
| `true-positive` | real malicious or unauthorized activity | no — the rule worked |
| `false-positive` | the rule fired on something it does not describe | **yes — a detection defect** |
| `benign` | the rule was right, the activity was authorized | no |

That middle distinction is the whole point. Collapsing "false positive" into "benign true
positive" would blame the ruleset for normal admin work and hide the detections that
genuinely need tuning. Without a *required* disposition the numbers silently degrade into
"of the closures somebody happened to label", which is not a measurement — so
`triage.set()` rejects a close without one.

Reported per rule: triaged/closed volume, false-positive rate, benign rate, precision,
median time to close, and the **sample size**, because 100% over 2 closures is not the
same claim as 40% over 200. Fleet-wide: median time to first touch and to close (medians,
not means — one stale alert should not move the number), outcome mix, closures per
analyst, and how often analysts **agreed with the AI scorer** — which is how the weights
in `analysis.js` get validated or indicted.

Rule attribution is looked up from the **indexer** at triage time and denormalized onto
the record, not taken from the request body: the client could claim any rule, and a record
holding only an index `_id` becomes unattributable the moment ISM deletes that index.

**Honest limits, stated in the UI too:** these are *analyst-reported outcomes, not ground
truth*, they only cover alerts someone actually triaged, and a rate stays `null` (shown
`—`) until there is something to divide by rather than displaying a confident `0%`.

## Tests

```bash
npm test        # node:test, no test framework dependency
```

61 tests over `tests/`, run in CI on every dashboard change
([dashboard-ci.yml](../.github/workflows/dashboard-ci.yml)). They exist to protect
**security invariants that are otherwise only claims in comments**:

- an analysis pass produces advisory findings only — never `status`, `assignee`, or
  `updatedBy` — and never writes to the triage store;
- a re-run cannot reopen or overwrite an alert a human already closed;
- `triage.set()` refuses to act without a named actor (`undefined`, `""`, `"  "`,
  non-strings all rejected);
- RBAC gates each route by role, and the acting username comes from the session, not
  from anything the caller can set;
- a forged or logged-out cookie grants nothing, and an unknown username is rejected
  identically to a wrong password.

Each of those was **mutation-tested**: removing the human-actor guard, letting findings
carry workflow state, dropping the duplicate grouping, and disabling the role comparison
each make the suite fail. A test that cannot fail protects nothing.

## Configuration (`.env`)
| Var | Default | Meaning |
|-----|---------|---------|
| `INDEXER_URL` | `https://localhost:9200` | indexer endpoint |
| `INDEXER_RO_USER` | `detectionlab_ro` | read-only account |
| `INDEXER_RO_PASSWORD` | — | its password |
| `ALERTS_INDEX` | `wazuh-alerts-*` | alerts index pattern |
| `PORT` | `8787` | BFF port |
| `DASH_USER` | `admin` | dashboard login username |
| `DASH_PASSWORD_HASH` | — | scrypt hash from `npm run hash-password`; logins **fail closed** until set |
| `DASH_SESSION_TTL_HOURS` | `12` | session lifetime |
| `DASH_COOKIE_SECURE` | `false` | set `true` behind HTTPS (adds `Secure` to the session cookie) |
| `DASH_AUTH_DISABLED` | `false` | `true` disables auth entirely (local dev only) |

## API (BFF)
| Endpoint | Purpose |
|----------|---------|
| `POST /api/auth/login` | `{username, password}` → session cookie; rate-limited |
| `POST /api/auth/logout` | end the session |
| `GET /api/auth/session` | current user, or 401 |
| `GET /api/health` | indexer reachable + alert count |
| `GET /api/stats?range&technique&minLevel&host&search` | totals, by-level, by-technique (+maxLevel/tactic), activity histogram |
| `GET /api/alerts?…&size` | recent alerts (id + `_source` + triage + AI finding) for the feed/drawer |
| `POST /api/alerts/:id/triage` | set status/assignee/note/AI verdict — **analyst+** |
| `POST /api/analysis/run` | score the current filter window, store advisory findings — **analyst+** |
| `GET /api/analysis` | current findings + the scoring configuration |
| `GET /api/metrics` | detection efficacy: per-rule FP rate, timings, scorer agreement |
| `GET /api/audit` | recent audit events — **admin only** |

All endpoints except `/api/auth/*` require a signed-in session (401 otherwise).

## AI-assisted triage (advisory only)

The **detection** is not AI — Wazuh rules do that. This layer only *triages* what the
rules already found: it scores each alert, flags the ones worth a look, and suggests an
investigation order (`P1`, `P2`, …).

**The ranking is deterministic**, not a model output. `server/analysis.js` applies a
weighted score over signals already present in the alert:

| Signal | Weight | Why |
|--------|--------|-----|
| rule level 13+ / 12 / 8+ | 45 / 40 / 20 | the ruleset's own severity |
| multi-stage correlation rule fired | +30 | several related events already line up |
| high-impact ATT&CK tactic | +5…+15 | credential access & lateral movement outrank execution |
| on a real enrolled endpoint | +10 | outranks lab infrastructure and the synthetic generator |
| same rule+host ≥3× in the window | +10 | repetition is signal |

Same input, same output; every contribution is shown to the analyst as a plain sentence
in the drawer. No API key, no cost, no data leaving the host.

Flagged alerts are then **grouped by rule + host**, so a rule that fires 16 times is one
queue item (`P1 ×16`) rather than 16 copies of the same decision filling the top of the
list. The representative is the highest-scoring, most recent instance.

**Optional LLM rationale.** With `AI_LLM_ENABLED=true`, Claude drafts a 1–2 sentence
rationale on top of the score. It is **off by default**, it never changes the score, the
ranking, or any workflow state, and it degrades to "no prose" on failure or refusal.
It needs `npm i @anthropic-ai/sdk` and `ANTHROPIC_API_KEY` — deliberately *not* a
package.json dependency, so the default build stays free of a dependency it never calls.
Log text is attacker-controllable, so it is fenced as untrusted data in the prompt, the
model output is never parsed for actions, and the UI labels it unverified.

**A human closes the investigation — enforced server-side, not by UI convention.**
`server/analysis.js` writes only to its own advisory store and has no path to triage
state. `triage.set()` rejects any call without an authenticated actor, and the acting
username comes from the session, never the request body. The UI keeps the two states
visually distinct — amber **"AI-flagged · awaiting human review"** vs green
**"human-confirmed · closed by X"** — and closing requires the analyst to write a note.
Their agree/disagree verdict on each flag is recorded, which is also the raw material for
measuring the scorer's false-positive rate later.

| Var | Default | Meaning |
|-----|---------|---------|
| `AI_MIN_LEVEL` | `8` | ignore alerts below this rule level |
| `AI_FLAG_THRESHOLD` | `45` | score at which an alert is flagged |
| `AI_LLM_ENABLED` | `false` | enable the Claude rationale |
| `AI_LLM_MODEL` | `claude-opus-5` | model for the rationale |
| `AI_LLM_MAX_SUMMARIES` | `5` | cap per pass (bounds cost/latency) |

## Design notes
- **Why a BFF:** the browser can't hold indexer creds, and direct browser→indexer calls
  hit CORS + the self-signed cert + basic-auth. The BFF solves all three and keeps the
  attack surface to a few read-only endpoints.
- **Auth** (`server/auth.js`) is zero-dependency by design: the single account's password
  is scrypt-hashed (`node:crypto`), sessions are random 256-bit tokens in an in-memory
  store, and the cookie is `HttpOnly; SameSite=Strict` (CSRF mitigation). Failed logins
  are throttled per source IP (10 per 15 min), and a wrong username still runs one scrypt
  verification so timing doesn't leak which usernames exist. A BFF restart logs everyone
  out — fine single-tenant. The SPA shell itself is public; every byte of alert data sits
  behind the session guard.
- **ATT&CK mapping** for the matrix layout is a static table (`src/attack.ts`) — techniques
  belong to tactics per the framework, matching how ATT&CK Navigator renders coverage.
  Counts come live from `rule.mitre.id` aggregations.
