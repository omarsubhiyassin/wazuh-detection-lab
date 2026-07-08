# Dashboard walkthrough

Every control and view in the custom ATT&CK dashboard ([../dashboard/](../dashboard/)),
what it does, and the API call behind it. Diagrams: [use-case-diagram.md](use-case-diagram.md)
· [architecture-diagram.md](architecture-diagram.md).

The page has five regions, top to bottom: **header + controls**, **stat tiles**,
**ATT&CK coverage matrix**, **alert feed**, and (on demand) the **alert detail drawer**.
Any control change re-queries `/api/stats` and `/api/alerts` together and re-renders
everything below.

---

## 1. Header & controls

`Detection Lab — ATT&CK Dashboard` with a green status dot, and four filter controls. All
four feed one `filters` object; changing any of them refetches stats + alerts.

| Control | Type | Options / behavior | Effect on the query |
|---------|------|--------------------|---------------------|
| **Range** | dropdown | `1h`, `24h`, `7d` (default), `30d`, `all` | Time window: `timestamp >= now-<range>`; `all` drops the time filter |
| **Min level** | dropdown | `any` (default), `4+`, `8+`, `12+` | `rule.level >= N` — hide low-severity noise |
| **host…** | text input | free text (e.g. `agent-linux-01`) | `agent.name` term filter |
| **search…** | text input | free text | `simple_query_string` over `rule.description`, `full_log`, `data.srcip`, `agent.name` |

> Wazuh severity scale is 0–15. The lab's custom detections fire at level 10–13; benign
> baseline events stay at level 0–5. So `Min level: 8+` is a quick way to see "just the
> interesting stuff."

If the BFF or indexer is unreachable, a red banner appears here:
*"Cannot reach the API… Is the BFF running and the indexer up?"*

---

## 2. Stat tiles

Five summary tiles, computed from `/api/stats` for the current filters.

| Tile | Shows | Source |
|------|-------|--------|
| **alerts** | total matching alerts | `stats.total` |
| **critical (12+)** | count of level 12–15 alerts (red) | sum of `byLevel` where level ≥ 12 |
| **high (8–11)** | count of level 8–11 alerts (orange) | sum of `byLevel` in 8–11 |
| **techniques seen** | `hit / total` of the lab's known techniques that have ≥1 alert | `byTechnique` vs. `TECHNIQUES` map |
| **activity** | sparkline of alerts over time (each bar = a time bucket; hover for exact time + count) | `stats.overTime` (`auto_date_histogram`, 48 buckets) |

"Techniques seen" reflects the **static** ATT&CK map in `src/attack.ts` (the techniques the
lab can detect), so `9/9` means every catalogued technique has produced at least one alert
in the current window.

---

## 3. ATT&CK coverage matrix

The centerpiece. Columns are **tactics** (only tactics that contain a known technique, in
ATT&CK order); each cell is a **technique** placed in its tactic per the framework.

**Cell contents:** technique ID (e.g. `T1059.001`), short name, and the alert **count** in
the current window. Hover shows `Txxxx Name — N alerts, max level M`.

**Heat colors** (by count relative to the busiest technique on screen):

| Class | Meaning |
|-------|---------|
| dim / grey | 0 alerts — technique is covered by a rule but hasn't fired in this window |
| amber | low volume (≤ ⅓ of the max) |
| orange | medium volume (⅓–⅔) |
| red | high volume (> ⅔) |

**Click a cell** to filter the whole alert feed to that technique. The clicked cell gets a
blue outline and a **`filtered: Txxxx ×`** chip appears next to the panel title — click the
chip (or the cell again) to clear. This is UC3 (drill into a technique); it sets
`technique` in the filters and issues `/api/alerts?technique=Txxxx`.

Placement uses the framework mapping (`attack.ts`), not the data — matching how ATT&CK
Navigator renders coverage. Counts come live from `rule.mitre.id` aggregations.

---

## 4. Alert feed

A table of the most recent matching alerts (newest first, up to the query size). The header
shows **`showing N of <total>`** (or `loading…` while fetching).

| Column | Content |
|--------|---------|
| **Time** | alert timestamp (localized) |
| **Lvl** | Wazuh rule level as a colored badge |
| **Technique** | `rule.mitre.id` tags (one chip each), or `—` if untagged |
| **Rule** | `rule.id` (custom rules are `100xxx`; built-ins are `5xxx`/`86xxx`) |
| **Description** | `rule.description` |
| **Host** | `agent.name` |

**Severity badge colors:** level ≥ 12 = critical (red), ≥ 8 = high (orange), ≥ 4 = medium
(amber), otherwise low (grey).

**Click any row** to open the detail drawer (UC5). If nothing matches, the table shows
*"No alerts match the current filters."*

---

## 5. Alert detail drawer

Slides in from the right when a row is clicked. Click the **×** or the dimmed backdrop to
close. It renders entirely from the alert's `_source` already fetched with the feed (no
extra request).

| Section | Content |
|---------|---------|
| **Title** | `Rule <id> — level <level>` |
| **Description** | `rule.description` |
| **Key/value** | Time · Host (name + IP) · Location · Decoder · Groups |
| **MITRE box** | one row per technique: ID chip · technique name · tactic |
| **Raw log** | the original `full_log` line (the exact event that triggered the rule) |
| **Event (_source)** | the full alert document, pretty-printed JSON |

The MITRE box is populated from `rule.mitre.{id,technique,tactic}` — the tags the custom
rules attach — which is what makes correlation alerts (e.g. `100430` tagged both
`T1059.001` and `T1105`) legible at a glance.

---

## API reference (what the UI calls)

The React app only ever talks to same-origin `/api/*`; the BFF adds the read-only
credentials and queries the indexer.

| Endpoint | Purpose | Key response fields |
|----------|---------|---------------------|
| `GET /api/health` | is the indexer reachable + how many alerts | `{ ok, alerts, index }` |
| `GET /api/stats?range&technique&minLevel&host&search` | tiles + matrix + sparkline | `{ total, byLevel[], byTechnique[]{id,count,maxLevel,tactic}, overTime[]{t,count} }` |
| `GET /api/alerts?…&size` | the feed + drawer data | `{ total, alerts[]{ id, source } }` |

All three accept the same filter params, so the tiles, matrix, and feed always agree with
the controls.

---

## Typical flow

1. Set **Range** to the window you care about (e.g. `24h`).
2. Bump **Min level** to `8+` to drop benign noise.
3. Read the **matrix** to see which tactics/techniques are active; a red cell = high volume.
4. **Click** the hottest cell to scope the **feed** to that technique.
5. **Click a row** to open the **drawer** and read the raw log + MITRE mapping.
6. Clear the technique **chip** to go back to the full picture.
