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

# dev: Vite (5173) + BFF (8787), with /api proxied to the BFF
npm run dev
# open http://localhost:5173

# production: build the SPA and serve everything from the BFF
npm run build && npm start   # open http://localhost:8787
```

## Configuration (`.env`)
| Var | Default | Meaning |
|-----|---------|---------|
| `INDEXER_URL` | `https://localhost:9200` | indexer endpoint |
| `INDEXER_RO_USER` | `detectionlab_ro` | read-only account |
| `INDEXER_RO_PASSWORD` | — | its password |
| `ALERTS_INDEX` | `wazuh-alerts-*` | alerts index pattern |
| `PORT` | `8787` | BFF port |

## API (BFF)
| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | indexer reachable + alert count |
| `GET /api/stats?range&technique&minLevel&host&search` | totals, by-level, by-technique (+maxLevel/tactic), activity histogram |
| `GET /api/alerts?…&size` | recent alerts (id + `_source`) for the feed/drawer |

## Design notes
- **Why a BFF:** the browser can't hold indexer creds, and direct browser→indexer calls
  hit CORS + the self-signed cert + basic-auth. The BFF solves all three and keeps the
  attack surface to a few read-only endpoints.
- **ATT&CK mapping** for the matrix layout is a static table (`src/attack.ts`) — techniques
  belong to tactics per the framework, matching how ATT&CK Navigator renders coverage.
  Counts come live from `rule.mitre.id` aggregations.
