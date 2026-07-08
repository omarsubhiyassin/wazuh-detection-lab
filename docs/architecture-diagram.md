# Architecture diagram

How the components connect, end to end: the synthetic generator produces logs → Wazuh
ingests, decodes, and detects → the read-only BFF queries the indexer → the React SPA
renders. (Prose version with design rationale is in [architecture.md](architecture.md).)

## System architecture (component diagram)

```mermaid
flowchart TB
    Browser(["Analyst's browser"])

    subgraph GEN["Synthetic Log Generator — Python"]
        SCN["8 scenarios + benign baseline<br/>(MITRE ATT&CK-mapped)"]
        GT["ground_truth.jsonl<br/>(what was injected)"]
    end

    subgraph WZ["Wazuh single-node — Docker / WSL2"]
        AG["Wazuh Agent<br/>logcollector (tails output files)"]
        MG["Wazuh Manager<br/>decoders → rule engine → MITRE tags"]
        FB["Filebeat"]
        IX[("Wazuh Indexer<br/>index: wazuh-alerts-*")]
        RO{{"read-only role<br/>detectionlab_ro"}}
    end

    subgraph APP["Custom Dashboard — dashboard/"]
        BFF["Express BFF (server/index.js)<br/>holds RO creds · exposes /api/*"]
        UI["React SPA (Vite + TS)<br/>matrix · stat tiles · feed · drawer"]
    end

    VAL["validation/validate.py<br/>coverage.md · coverage.json · Navigator layer"]

    SCN -->|"real-format logs:<br/>auth.log, Windows/Sysmon JSON, eve.json"| AG
    AG -->|"1514 / TLS (enrolled agent)"| MG
    MG --> FB
    FB -->|"ships alerts"| IX
    RO -. "authorizes read-only" .-> IX

    BFF -->|"OpenSearch _search / _count (RO creds)"| IX
    UI -->|"same-origin /api/* (no creds in browser)"| BFF
    Browser --> UI

    GT --> VAL
    VAL -->|"read-only query of alerts"| IX
```

Legend: `[( )]` = data store, `{{ }}` = access-control role, `([ ])` = external actor.

## Runtime data flow (analyst filters by technique)

```mermaid
sequenceDiagram
    actor Analyst
    participant UI as React SPA
    participant BFF as Express BFF
    participant IX as Wazuh Indexer

    Analyst->>UI: click matrix cell (e.g. T1071.004)
    UI->>UI: set filters.technique
    UI->>BFF: GET /api/stats?range=7d&technique=T1071.004
    UI->>BFF: GET /api/alerts?range=7d&technique=T1071.004
    BFF->>IX: POST wazuh-alerts-*/_search (Basic auth, RO)
    IX-->>BFF: aggregations + hits
    BFF-->>UI: {byTechnique, byLevel, overTime} / {total, alerts[]}
    UI-->>Analyst: heatmap + filtered feed + active "filtered: T1071.004" chip
```

## Ingestion path (how an injected attack becomes an alert)

```mermaid
flowchart LR
    A["Generator appends<br/>a log line"] --> B["Agent logcollector<br/>forwards new line"]
    B --> C["Manager decoder<br/>parses fields"]
    C --> D["Rule engine matches<br/>(+ correlation state)"]
    D --> E["Alert with<br/>rule.mitre.id / level"]
    E --> F["Filebeat → Indexer<br/>wazuh-alerts-*"]
    F --> G["BFF /api → dashboard"]
```

## Dashboard internal structure (frontend + BFF)

```mermaid
classDiagram
    class App {
        +Filters filters
        +Stats stats
        +Alert selected
        +reloadOnFilterChange()
    }
    class AttackMatrix {
        +onSelect(technique)
        +heat(count, max)
    }
    class AlertTable {
        +onSelect(alert)
        +levelClass(level)
    }
    class AlertDrawer {
        +onClose()
    }
    class api {
        +getStats(filters)
        +getAlerts(filters)
        +getHealth()
    }
    class attack {
        +coveredTactics()
        +techniquesForTactic(tactic)
    }
    class BFF {
        +health()
        +stats()
        +alerts()
        +indexer(path, method, body)
    }
    class Indexer

    App --> AttackMatrix
    App --> AlertTable
    App --> AlertDrawer
    App --> api
    AttackMatrix --> attack
    api --> BFF : fetch /api
    BFF --> Indexer : OpenSearch RO
```

## Why this shape

| Decision | Reason |
|----------|--------|
| Real log formats out of the generator | Wazuh's built-in decoders parse them; custom work stays at the detection layer |
| BFF between browser and indexer | Browser can't hold indexer creds; also solves CORS + the self-signed cert |
| Read-only account (`detectionlab_ro`) | Least privilege — dashboard can read `wazuh-alerts-*`, nothing else (verified 403 on writes) |
| `ground_truth.jsonl` + `validate.py` | Closes the loop: measured detection coverage, not just "rules exist" |
