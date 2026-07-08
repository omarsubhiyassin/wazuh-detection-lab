# How it works — a build-it-yourself walkthrough

A guided tour of the whole project for someone who knows security basics but hasn't
built a detection pipeline before. For each phase you get: **the problem it solves**,
**how it works under the hood**, **the actual code with the important parts explained**,
and **the concepts you'd need to build it yourself**.

Read it top to bottom the first time — each phase builds on the last.

---

## The one big idea: the detection-engineering loop

Most "SIEM projects" stop at *"I installed a SIEM and wrote some rules."* The thing that
makes this a real **detection-engineering** project is a closed feedback loop:

```
        ┌─────────────────────────────────────────────────────┐
        │                                                     │
   inject KNOWN attacks  ──►  detect them  ──►  MEASURE how   │
   (generator + ground     (Wazuh rules)      many you caught │
    truth = the answer key)                   (validation) ───┘
```

You inject attacks *whose answers you already know*, let your detections run, then
**measure** what fraction you caught and how many false alarms you raised. That
measurement is the difference between "I think my rules work" and "my rules detect
100% of the injected techniques with 0 false positives, and here's the report."

Everything below serves that loop.

### Mental models you need first

- **A SIEM is a log pipeline, not a magic box.** Logs are *collected* from machines,
  *parsed* into fields, *matched* against rules to produce *alerts*, and *stored* so you
  can search them. Wazuh is one implementation; Splunk, Elastic, and Sentinel are the
  same shape.
- **A detection is a hypothesis about attacker behavior**, expressed as a rule. "If a
  process named `lsass.exe` is opened for memory-read by something that isn't antivirus,
  someone is probably stealing credentials."
- **MITRE ATT&CK** is a shared vocabulary for attacker behavior. Each technique has an ID
  (e.g. `T1003.001` = "OS Credential Dumping: LSASS Memory"). Tagging detections with
  ATT&CK IDs lets you talk about *coverage* — which behaviors you can and can't see.
- **Detection-as-code** means your rules, tests, and docs live in git like software:
  reviewed, versioned, and tested. That's why every rule here ships with a test case.

---

## Phase 1 — Infrastructure: building the log pipeline

### The problem
Before you can detect anything, you need somewhere for logs to *land*, get *parsed*, get
*matched* against rules, and get *stored* for searching. That's four jobs, and Wazuh
splits them across four programs.

### How it works — the assembly line
Think of it as a **factory assembly line** for logs:

| Component | Job | Assembly-line analogy |
|-----------|-----|-----------------------|
| **Wazuh Agent** | runs on the monitored machine; reads log files and ships new lines | the person who picks raw material off the truck |
| **Wazuh Manager** | *decodes* each log into fields, then runs the *rule engine*; emits alerts | the station that inspects each part and stamps "DEFECT" |
| **Filebeat** | ships the alerts from the manager to storage | the conveyor to the warehouse |
| **Wazuh Indexer** (OpenSearch) | stores alerts in the `wazuh-alerts-*` index; makes them searchable | the warehouse with a searchable catalog |
| **Wazuh Dashboard** | the built-in web UI | the warehouse's front desk |

The data flow for a single log line:

```
generator writes a line ─► Agent's "logcollector" sees the new line
   ─► sends it to the Manager over TCP 1514 (TLS)
   ─► Manager DECODES it (raw text → named fields)
   ─► Manager runs the RULE ENGINE (does any rule match?)
   ─► if a rule matches → an ALERT (with a level and MITRE tags)
   ─► Filebeat ships the alert → Indexer stores it in wazuh-alerts-*
   ─► you can now query it
```

### The code: infrastructure as code
We never click through installers — the whole stack is declared in files so it's
reproducible. We use the official `wazuh-docker` Compose stack, pinned to a version, and
layer **our** customization on top with a Compose *override* file (so the vendored files
stay untouched and upgradable):

```yaml
# infra/docker-compose.override.yml  (excerpt)
services:
  wazuh.manager:
    volumes:
      # mount OUR rules into the manager, read-only
      - ${DETECTION_LAB_ROOT}/detections/rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
  wazuh.agent.linux:
    image: wazuh/wazuh-agent:${WAZUH_IMAGE_TAG}
    environment:
      - WAZUH_MANAGER=wazuh.manager
      - WAZUH_AGENT_GROUP=detection-lab
    volumes:
      # the agent tails the generator's output files
      - ${DETECTION_LAB_ROOT}/generator/output:/var/log/detection-lab:ro
```

The agent needs to be told *which files to read*. That's a `<localfile>` block — the
agent's equivalent of `tail -f`:

```xml
<!-- infra/config/agent-ossec.conf -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/detection-lab/auth.log</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/log/detection-lab/windows_events.json</location>
</localfile>
```

### Concepts you'd need to build it yourself
- **Agent enrollment.** An agent must *register* with the manager before it can send data
  (it exchanges a key over port 1515). Agents can only auto-enroll into a **group** that
  already exists — a real gotcha we hit: the manager rejected the agent until we created
  the `detection-lab` group first. *Lesson: enrollment is authentication; the server has
  to know the client.*
- **Log formats & decoders.** The manager can only rule on *fields*, and it only gets
  fields if a **decoder** knows how to parse the format. We emit **real** formats
  (sshd's `auth.log`, Windows Event JSON, Suricata `eve.json`) precisely so Wazuh's
  *built-in* decoders parse them for free.
- **The indexer is OpenSearch.** Alerts are JSON documents in an index; you query them
  with the OpenSearch/Elasticsearch API. Learn that API — it's the same skill across
  Elastic and OpenSearch.
- **Two war stories that teach the pipeline:**
  1. *An empty `<group>` with no `<rule>` crashed the whole manager* — `analysisd` (the
     rule engine) aborts on a malformed ruleset, and if it aborts, **no** daemon starts,
     so the agent can't even connect. Lesson: the rule engine is load-bearing; a bad rule
     is an outage, not just a missing alert.
  2. *The dashboard password isn't set by an env var* — OpenSearch authenticates against a
     bcrypt hash in `internal_users.yml`, not a plaintext env var. Env vars only tell
     *clients* what to present. Lesson: understand where the source of truth for a
     credential actually lives.

---

## Phase 2 — The synthetic log generator

### The problem
To *measure* detections you need attacks whose answers you already know — an **answer
key**. Real attack data is scarce, messy, and unlabeled. So we generate synthetic logs
that (a) look real enough for the decoders, (b) embed specific ATT&CK techniques, and
(c) write down exactly what was injected and when.

Analogy: it's a **flight simulator**. Not real flying, but realistic enough to train and
*grade* the pilot, and you control the weather.

### How it works
Three layers of output, written as real-format log files the agent tails:
1. **Benign baseline** — normal SSH logins, DNS lookups, web traffic, process spawns.
   Without believable noise, every detection is trivially true.
2. **Attack scenarios** — scripted kill-chains (brute force, PowerShell cradle, LSASS
   dump, …) mapped to ATT&CK.
3. **Ground truth** — a `ground_truth.jsonl` file: one labeled record per injected attack
   event. *This is the answer key.*

The design separates three concerns cleanly:

- **`world.py`** — the deterministic "environment": hosts, users, IPs, all driven by one
  seeded random generator so a given `--seed` reproduces identical logs.
- **`emitters/`** — *pure functions* that format one log line. No I/O, no state — just
  "given these fields, return the exact bytes of an sshd line / a Sysmon JSON event."
- **`scenarios/`** — YAML playbooks + a Python *builder* per scenario that emits correlated
  events.
- **`timeline.py`** — schedules events in time and writes them out.

### The code: a pure emitter
An emitter knows *one format* and nothing else. Here's the sshd one:

```python
# generator/emitters/sshd.py
def _header(ts, host, pid, proc="sshd"):
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    stamp = f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"
    return f"{stamp} {host} {proc}[{pid}]:"

def failed_invalid_user(ts, *, host, user, src_ip, port, pid):
    return (f"{_header(ts, host, pid)} Failed password for invalid user "
            f"{user} from {src_ip} port {port} ssh2")
```

That output is byte-for-byte a real `auth.log` line, which is why Wazuh's built-in sshd
decoder parses it and its built-in rules (5710, 5712…) fire with no work from us.

### The code: deferred events (the clever bit)
The **timeline** is the trick that lets the *same* schedule play out two ways. Builders
don't write bytes directly; they register a `(offset, sink, render)` where `render(ts)`
produces the line for an absolute timestamp:

```python
# generator/timeline.py  (the core idea)
def emit(self, offset, sink, render):
    # offset = seconds into the run; render(ts) -> the log line
    self.events.append(_Event(offset, sink, render))
```

Now the same events can be materialized as:
- **backfill** — resolve `ts = start + offset` for every event, sort, and write them all
  at once (instant historical data), or
- **stream** — replay in real time (scaled by a compression factor), stamping each line
  with the wall-clock time it actually fires.

Why two modes? Because of a subtlety you'll hit: the agent's logcollector forwards
*newly appended* lines. Backfill is great for filling the indexer fast; **stream** is what
you use for validation, because it appends events live *and* writes the ground-truth
timestamp at the same instant, so the injected time and the detected time line up.

### The code: a scenario builder + the answer key
A builder turns parameters into correlated events and **labels** them:

```python
# generator/scenarios/builders.py  (brute-force -> success)
def brute_force_success(cfg, world, tl, start):
    ...
    for _ in range(n):                       # N failed logins from one IP
        tl.emit(off, "auth.log", partial(sshd.failed_invalid_user,
                host=host, user=..., src_ip=src_ip, ...))
        off += interval + jitter
    # the answer key entry for the brute force:
    tl.label(start, technique_id="T1110", tactic="Credential Access",
             scenario=name, host=host, src_ip=src_ip, source="sshd",
             expected_rules=[5710, 5712, 5720])
    # then ONE success from the same IP:
    tl.emit(off, "auth.log", partial(sshd.accepted_password, ..., src_ip=src_ip))
    tl.label(off, technique_id="T1078", ..., src_ip=src_ip)
```

Each `label(...)` becomes a line in `ground_truth.jsonl`:
`{technique_id, timestamp, host, src_ip, expected_rules, scenario, ...}`.

### Concepts you'd need to build it yourself
- **Determinism via seeding.** One `random.Random(seed)` threaded everywhere ⇒
  reproducible datasets ⇒ reproducible test results. Non-negotiable for a measurement tool.
- **Emit real formats.** If your fake logs match real ones byte-for-byte, existing
  decoders parse them and your effort goes into *detection logic*, not plumbing.
- **Ground truth is the whole point.** The moment you write "I injected T1110 at 14:02 on
  web-01," you can later ask "did anything detect it?" — that's the loop.
- **Model correlation on purpose.** Events in a scenario share host / user / source IP and
  realistic timing so that *correlation* rules (Phase 4) have something to stitch together.

---

## Phase 3 — Signature detection rules

### The problem
The manager now receives decoded events. A **signature rule** turns a single suspicious
event into an alert: "*this one event, by itself, is bad.*"

### How Wazuh rules work
Two steps happen for every event: **decode** (raw → fields), then **match** (do fields
satisfy a rule?). A Wazuh rule is XML with:
- a numeric **id** (custom rules use 100000+) and a **level** 0–15 (severity; 0 = log-only,
  12+ = high);
- **conditions** — `<field name="...">regex</field>` matches a decoded field; `<if_sid>`
  makes a rule a *child* of another (only evaluated if the parent matched);
- optional **`<mitre><id>`** tags;
- **groups** for organization.

Analogy: rules form a **decision tree**, like an airport security funnel. A cheap parent
rule ("is this a process-creation event at all?") gates expensive child rules ("…and is it
PowerShell with an encoded blob?"). You don't run the expensive check on every event.

### The code: base rule + child rule, line by line
```xml
<!-- PARENT: fires on ANY Sysmon process-creation event; level 0 = never alerts -->
<rule id="100100" level="0">
  <decoded_as>json</decoded_as>                                   <!-- event came through the json decoder -->
  <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
  <field name="win.system.eventID" type="pcre2">^1$</field>       <!-- Event ID exactly 1 -->
  <description>Sysmon: process creation (Event ID 1).</description>
</rule>

<!-- CHILD: only checked when 100100 matched -->
<rule id="100101" level="12">
  <if_sid>100100</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{30,}</field>
  <description>Encoded PowerShell command line executed (possible obfuscated payload).</description>
  <mitre><id>T1059.001</id></mitre>
</rule>
```

Reading `100101` like an analyst:
- `image` ends in `powershell.exe`/`pwsh.exe` — the process is PowerShell;
- `commandLine` matches ` -e<anything> <30+ base64 chars>` — the `-e`/`-enc`/
  `-EncodedCommand` switch followed by a long base64 blob. Attackers base64-encode payloads
  to hide them; a long encoded blob on a PowerShell command line is the tell.
- `(?i)` = case-insensitive; `\\` = a literal backslash (Windows paths); `$` = end of
  string. **These are just regexes on decoded fields** — the core skill of signature
  writing.

### The code: the false-positive problem (LSASS)
The hardest part of signatures isn't catching the attack — it's *not* catching benign
look-alikes. LSASS is the perfect example: antivirus reads `lsass.exe` memory constantly,
with the *same* access masks a credential dumper uses. Matching "someone read lsass" would
be a false-positive firehose. The fix is an **allowlist on the source process**:

```xml
<rule id="100700" level="13">
  <decoded_as>json</decoded_as>
  <field name="win.system.eventID" type="pcre2">^10$</field>                     <!-- Sysmon 10 = ProcessAccess -->
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field> <!-- opening LSASS... -->
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)^0x(1010|1410|1418|1438|143a|1fffff)$</field>  <!-- ...with read rights -->
  <!-- ...but NOT from a known-good process (negate = "field must NOT match") -->
  <field name="win.eventdata.sourceImage" negate="yes"
         type="pcre2">(?i)\\(wininit|csrss|services|lsass|MsMpEng|...|svchost)\.exe$</field>
  <mitre><id>T1003.001</id></mitre>
</rule>
```

`negate="yes"` is the key: fire only when the source process is *not* on the allowlist.
We proved this works at scale — 1 alert on the attack, 0 on ~27 benign LSASS accesses
carrying the identical mask.

### Concepts you'd need to build it yourself
- **Decode-then-match.** You can only rule on fields a decoder produced. Always confirm the
  exact field path first (we used `wazuh-logtest`, which shows the decoded fields and which
  rule fired — you paste a log line, it tells you everything).
- **Parent/child trees & levels.** Cheap gate rules → expensive specific rules; level tunes
  severity and is how you triage.
- **Regex on fields is 80% of signatures.** `(?i)`, anchors (`^ $`), character classes,
  quantifiers (`{30,}`). Practice these.
- **Signatures are a precision/recall tradeoff.** Broad rules catch more but false-positive;
  narrow rules are quiet but evadable. The LSASS allowlist is the canonical technique:
  *characterize the benign, then exclude it.*
- **Detect the action AND the effect.** For log clearing we wrote *two* rules — one for the
  `wevtutil cl` command (Sysmon 1) and one for the Windows `1102` "log cleared" event.
  Defense in depth: if the attacker disables one telemetry source, the other still fires.

---

## Phase 4 — Correlation rules

### The problem
Many real attacks are invisible in any *single* event but obvious as a *sequence*. One
failed SSH login is nothing; 25 failures then a success from the same IP is a compromise.
One weird DNS query is nothing; 30 on a fixed interval is a C2 beacon. **Correlation** =
detecting patterns *across* events over time.

Analogy: a signature rule is a **smoke detector** (one reading). A correlation rule is a
**detective** who remembers earlier events and notices the pattern.

### How stateful correlation works
Wazuh's engine keeps recent events in memory so a rule can say "fire only if I've *also*
seen X recently." The knobs:
- `frequency="N"` + `timeframe="S"` — needs N matching events within S seconds;
- `<if_matched_sid>RULE</if_matched_sid>` — "a specific earlier rule also fired recently";
- `<same_source_ip/>`, `<same_field>NAME</same_field>` — the correlated events must **share
  a field value** (this is the crucial part — *what ties the events together?*).

### The code: four correlations, and why each "join key" differs
The interesting lesson is that **choosing the field that links the events is the whole
design.** Look at how each rule answers "what makes these the *same* incident?":

```xml
<!-- 1) Brute force -> success: linked by the ATTACKER'S IP -->
<rule id="100400" level="12" timeframe="300">
  <if_sid>5715</if_sid>               <!-- an SSH success just happened -->
  <if_matched_sid>5712</if_matched_sid> <!-- AND a brute-force fired recently -->
  <same_source_ip/>                   <!-- ...from the SAME IP -->
  <mitre><id>T1078</id><id>T1110</id></mitre>
</rule>

<!-- 2) DNS beacon: linked by the SOURCE HOST, counted by frequency -->
<rule id="100410" level="12" frequency="8" timeframe="600">
  <if_matched_sid>100300</if_matched_sid> <!-- 8 "suspicious DNS" events... -->
  <same_field>src_ip</same_field>         <!-- ...from one host in 600s -->
</rule>

<!-- 3) Execution -> persistence: linked by the HOST NAME -->
<rule id="100420" level="13" timeframe="600">
  <if_sid>100121</if_sid>                 <!-- a suspicious scheduled task registered -->
  <if_matched_sid>100101</if_matched_sid> <!-- AND encoded PowerShell ran... -->
  <same_field>win.system.computer</same_field> <!-- ...on the SAME machine -->
</rule>

<!-- 4) Download <-> execution: linked by the PROCESS GUID -->
<rule id="100430" level="13" timeframe="300">
  <if_sid>100200</if_sid>                  <!-- a network connection... -->
  <if_matched_sid>100101</if_matched_sid>  <!-- ...by the SAME process that was encoded PowerShell -->
  <same_field>win.eventdata.processGuid</same_field>
</rule>
```

The join key gets *more precise* as you go: attacker IP → host IP → host name → **exact
process**. Rule 100430 is the payoff of a real problem: the download shows up as a
Suricata network event (identified by `src_ip`) while the execution is a Sysmon endpoint
event (identified by `win.system.computer`) — **they share no field**, so you can't
correlate them. The fix was to add the *endpoint's* view of the download (Sysmon Event ID
3, a network connection) which carries the same `processGuid` as the PowerShell process —
now they share a key, and you get process-level precision.

### Concepts you'd need to build it yourself
- **Statefulness.** Correlation needs memory of recent events. `timeframe` bounds that
  memory; too long is noisy and expensive, too short misses slow attacks.
- **The join key is the design.** Ask "what single value proves these events belong to the
  same incident?" Same IP? Same host? Same user? Same process? Pick the *most specific one
  available* to minimize false correlations.
- **Network↔endpoint identity is genuinely hard.** A packet knows an IP; an EDR knows a
  process. Bridging them (via an IP→host asset map, or by capturing an endpoint view like
  Sysmon 3) is a real SOC problem you just met in miniature.
- **A war story: `frequency="1"` crashed the rule engine.** Wazuh requires frequency > 1.
  For "one prior match," you *omit* frequency and rely on `if_matched_sid` + `timeframe`.
  Lesson: correlation semantics have sharp edges — test on the running engine.
- **Composites raise fidelity, not coverage.** 100430 doesn't detect a *new* technique; it
  detects the same ones with far higher confidence. That's often what you want: fewer,
  better alerts.

---

## Phase 5 — The dashboard

### The problem
Analysts need to *see* and *triage* alerts — an ATT&CK heatmap, a filterable feed, a way
to drill in — **without** handing the browser direct access to the datastore (that would
mean shipping database credentials to every browser tab, plus CORS and TLS headaches).

### How it works — the backend-for-frontend (BFF)
The architecture is deliberately two pieces:

```
Browser ──(same-origin /api/*)──► Express BFF ──(OpenSearch, read-only creds)──► Indexer
```

The **BFF** is a thin server that holds the read-only indexer credentials, exposes a
handful of purpose-built endpoints, and serves the React app. The browser only ever talks
to same-origin `/api/*` and **never sees a credential**. Analogy: the BFF is a **bank
teller** — you don't get to walk into the vault; you make specific requests and the teller
(who has the keys) fetches exactly what you asked for.

Two security ideas ride along:
- **Least privilege** — the account (`detectionlab_ro`) can *read* `wazuh-alerts-*` and
  nothing else. We verified it gets HTTP 403 on writes and on other indices.
- **The security boundary is the BFF**, and it's the only thing with credentials.

### The code: the BFF talking to the datastore
```js
// dashboard/server/index.js  (the essentials)
const AUTH = "Basic " + Buffer.from(`${RO_USER}:${RO_PASSWORD}`).toString("base64");
const agent = new https.Agent({ rejectUnauthorized: false }); // trust the lab's self-signed cert

function indexer(path, method, body) {                 // one helper: talk to OpenSearch
  // ...https.request to the indexer with Basic auth, returns {status, json}
}

function buildQuery(q) {                                // turn UI filters into an OpenSearch query
  const filter = [];
  if (q.range && q.range !== "all")
    filter.push({ range: { timestamp: { gte: `now-${q.range}` } } });
  if (q.technique) filter.push({ term: { "rule.mitre.id": q.technique } });
  if (q.minLevel)  filter.push({ range: { "rule.level": { gte: Number(q.minLevel) } } });
  return { bool: { must: [{ match_all: {} }], filter } };
}

app.get("/api/stats", async (req, res) => {            // aggregations for the tiles + matrix
  const body = { size: 0, query: buildQuery(req.query), aggs: {
    by_level:     { terms: { field: "rule.level" } },
    by_technique: { terms: { field: "rule.mitre.id" },
                    aggs: { max_level: { max: { field: "rule.level" } } } },
    over_time:    { auto_date_histogram: { field: "timestamp", buckets: 48 } },
  }};
  const r = await indexer(`/${ALERTS_INDEX}/_search`, "POST", body);
  res.json({ /* total, byLevel, byTechnique, overTime */ });
});
```

`size: 0` means "don't return documents, just the **aggregations**" — that's how you turn
millions of alerts into "12 alerts for T1071.004, max level 12" without shipping the raw
docs. Learning OpenSearch aggregations is a high-leverage skill.

### The code: the React side and the ATT&CK matrix
The frontend keeps a `filters` object in state; whenever it changes, it refetches:

```tsx
// dashboard/src/App.tsx
useEffect(() => {
  Promise.all([getStats(filters), getAlerts(filters)])
    .then(([s, a]) => { setStats(s); setData(a); });
}, [filters]);   // <-- re-runs every time a control changes
```

The matrix places each technique in its tactic column using a **static ATT&CK map** (so
placement follows the framework, like ATT&CK Navigator), and colors cells by alert count:

```ts
// dashboard/src/attack.ts
export const TECHNIQUES = {
  "T1059.001": { name: "PowerShell", tactics: ["Execution"] },
  "T1003.001": { name: "LSASS Memory", tactics: ["Credential Access"] },
  // ...
};
```

```tsx
// heat class from count relative to the busiest technique on screen
function heat(count, max) {
  if (count <= 0) return "cell heat-0";     // covered but quiet
  const r = count / max;
  return r > 0.66 ? "cell heat-3" : r > 0.33 ? "cell heat-2" : "cell heat-1";
}
```

### Concepts you'd need to build it yourself
- **Backend-for-frontend.** Never put datastore creds in a browser. A thin server with a
  small, purpose-built API is the pattern — it also solves CORS and cert trust.
- **Least-privilege service accounts.** Create a role that can do *exactly* what the app
  needs and prove it can't do more.
- **Aggregations vs. documents.** Dashboards are mostly aggregations (`terms`, `max`,
  `date_histogram`). Fetch documents only for the detail view.
- **Client state → declarative refetch.** UI is a function of state; when filters change,
  refetch and re-render. (Here, React's `useEffect` keyed on `filters`.)

---

## Phase 6 — The validation harness

### The problem
"I wrote rules" is not "detection works." You need to **measure**: of the attacks I
injected, how many did I catch (**recall**), how many did I miss (**false negatives**), and
how many false alarms did I raise (**false positives**)? Without this, you're guessing.

### How it works
The harness joins two lists by time and technique:
- the **answer key** (`ground_truth.jsonl`) — what was injected;
- the **alerts** in the indexer — what was detected.

For each injected event, it asks "did a matching alert fire within a time window?"

```python
# validation/validate.py
def matches(gt, alert, window):
    if abs(alert["epoch"] - gt["epoch"]) > window:           # close in time?
        return False
    if gt["technique_id"] in alert["mitre_ids"]:             # same ATT&CK technique?
        return True
    if alert["rule_id"] in set(gt.get("expected_rules", [])): # or an expected rule id?
        return True
    return False
```

Then it tallies per technique and overall:

```python
def score(gts, alerts, window):
    for gt in gts:
        t = per_tech[gt["technique_id"]]
        t["injected"] += 1
        hit_rules = sorted({a["rule_id"] for a in alerts if matches(gt, a, window)})
        if hit_rules:               # at least one alert matched → DETECTED (true positive)
            t["detected"] += 1
    # recall = detected / injected ; false_negatives = injected - detected
```

It emits three artifacts: a human `coverage.md`, a machine `coverage.json`, and an
**ATT&CK Navigator layer** you can load onto the real ATT&CK matrix to visualize coverage.

### The subtle part: defining a false positive correctly
This is the most instructive bug in the project. A naive FP definition is "a custom-rule
alert that matches no injected event." But the indexer *accumulates* alerts across runs, so
a previous run's perfectly valid attack alerts would be counted as false positives (we saw
FP jump to 34 — all our own rules). The fix is to make FP **run-order-independent**:

```python
# a false positive = a custom-rule alert tagged with a technique we NEVER injected this run
injected_techs = {gt["technique_id"] for gt in gts}
fps = [a for a in alerts
       if a["rule_id"] >= 100000 and a["level"] > 0
       and not (set(a["mitre_ids"]) & injected_techs)]
```

Because we *separately* verified (in Phase 3) that the custom rules don't fire on the
benign baseline, a custom alert whose technique was injected is a detection, not a false
alarm — only a *non-injected* technique is a genuine FP. **Lesson: a metric is only as
good as its definition; think hard about what you're actually counting.**

There was a second teaching bug: the generator initially credited **T1105** (the download)
to the PowerShell-execution rule, inflating recall to a fake 100%. Fixing the answer key so
T1105 had no detector correctly dropped recall to 83% and exposed a real gap — which we
then closed with the network-download rule. *The measurement caught our own mistake. That's
the point of measuring.*

### Concepts you'd need to build it yourself
- **Recall / precision / false negatives / false positives.** The vocabulary of detection
  quality. Recall = "of the bad things, how many did I catch?" FP rate = "how much did I
  cry wolf?"
- **Matching is fuzzy.** Injected time ≠ alert time exactly; you match within a *window*
  and by *technique*, not by exact equality.
- **Coverage as a first-class metric.** Per-technique detection rate, rendered on the ATT&CK
  matrix, is how mature teams talk about what they can and can't see.
- **Guard your metric against artifacts.** Shared state, prior runs, clock skew — a
  measurement you don't scrutinize will lie to you.

---

## How to build this yourself, from scratch

If you wanted to reproduce it, here's the order that keeps you always-working:

1. **Stand up the pipeline.** One Wazuh single-node stack (Docker). Enroll one agent. Feed
   *one* known sshd failed-login line and confirm a built-in rule fires and the alert lands
   in `wazuh-alerts-*`. Don't write a single custom rule until this end-to-end path works.
2. **Generate one attack + its ground truth.** A tiny Python script that appends real-format
   log lines and writes a `ground_truth.jsonl` label. Start with SSH brute force (built-in
   rules already detect it — instant feedback).
3. **Write one signature rule** for something *not* covered by built-ins (e.g. encoded
   PowerShell via Sysmon 1). Develop it with `wazuh-logtest` (paste a line, see the fields
   and which rule fires). Ship it with a test case.
4. **Write one correlation rule** (brute-force→success). Learn `if_matched_sid` +
   `same_source_ip` + `timeframe`.
5. **Write the validation harness** — even 40 lines that join ground truth to alerts and
   print recall. Now you have the loop; everything after is *adding scenarios and rules and
   watching the number move.*
6. **Add a read-only dashboard** last — it's presentation, not detection.

### What to learn next
- **Sigma** — a vendor-neutral detection rule language; translates to Wazuh, Splunk,
  Elastic, Sentinel. Learn to think in Sigma and you're portable.
- **Real Sysmon** with a good config (SwiftOnSecurity / Olaf's), and Windows event logging
  (4624/4625/4688/4698/1102…). We *simulated* these; run them for real.
- **The ATT&CK framework in depth**, and **atomic-red-team** (real, safe technique tests) as
  a step up from synthetic logs.
- **Query languages**: OpenSearch/Elastic DSL (here), plus KQL (Sentinel) and SPL (Splunk).
- **Detection engineering as a discipline** — the ideas of detection-as-code, coverage,
  and testing generalize far beyond Wazuh.

---

## Quick glossary

| Term | Plain meaning |
|------|---------------|
| SIEM | the log pipeline: collect → parse → match → store → search |
| Decoder | parses a raw log line into named fields |
| Rule / signature | a condition on fields that produces an alert |
| Correlation rule | a rule that fires on a *pattern across* events over time |
| Level | Wazuh severity 0–15 (0 = log only, 12+ = high) |
| MITRE ATT&CK | shared IDs for attacker behaviors (e.g. T1003.001) |
| Ground truth | the answer key: what attacks were injected, and when |
| Recall / detection rate | fraction of injected attacks that were detected |
| False positive | an alert that doesn't correspond to a real injected attack |
| BFF | backend-for-frontend: thin server holding creds + a small API |
| Least privilege | give an account exactly the access it needs, no more |
| Coverage | which ATT&CK techniques you can (and can't) detect |

Every claim here is backed by code in this repo — start at
[architecture.md](architecture.md) for the map, then open the files each section quotes.
