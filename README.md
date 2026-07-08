# Detection Engineering Lab

A blue-team detection-engineering portfolio project built on **Wazuh** (open-source
SIEM/XDR). A scenario-driven synthetic log generator injects realistic attacks mapped
to **MITRE ATT&CK**; custom Wazuh rules detect them; a custom dashboard visualizes
alerts on an ATT&CK matrix; and a validation harness scores detection coverage against
ground truth.

The whole project is organized as **detection-as-code**: every detection ships with a
test case, an ATT&CK mapping, and a documented hypothesis, and coverage is *measured*
against the attacks the generator knows it injected.

## Architecture

```
Synthetic Log Generator ──► Wazuh Agent ──► Wazuh Manager (decoders + rules + MITRE)
   (MITRE-labeled,                                  │
    + ground_truth.jsonl)                           ▼
                                          Wazuh Indexer (wazuh-alerts-*)
                                                     │
                                    ┌────────────────┴───────────────┐
                                    ▼                                ▼
                           Wazuh Dashboard                  Custom Dashboard
                           (ops / debugging)                (ATT&CK heatmap, React)
```

Full component breakdown in [docs/architecture.md](docs/architecture.md).

## Repository layout

| Path | Purpose |
|------|---------|
| `infra/` | Wazuh single-node stack as code: bootstrap, compose override, configs, runbook |
| `generator/` | Python synthetic log generator; `scenarios/` = YAML attack playbooks, `ground_truth/` = labels |
| `detections/` | Custom Wazuh rules + decoders (XML); `tests/` = `wazuh-logtest` cases |
| `dashboard/` | Custom React (Vite + TS) dashboard querying the Wazuh Indexer |
| `validation/` | Coverage-scoring harness + generated reports |
| `docs/` | Architecture, ATT&CK coverage map, per-detection docs, runbook |

## Status

Building in phases (see [docs/roadmap.md](docs/roadmap.md)):

- [x] **Phase 0** — Lab infra + repo scaffolding
- [x] **Phase 1** — Wazuh up, ingestion smoke test
- [x] **Phase 2** — Synthetic log generator (baseline + 4 v1 scenarios)
- [x] **Phase 3** — Decoders + signature detections
- [x] **Phase 4** — Correlation / composite detections
- [x] **Phase 5** — Custom dashboard
- [x] **Phase 6** — Validation harness + docs

**Measured coverage** (live stream run): recall **100%** (11/11 injected events across 9
techniques / 7 tactics), false positives **0** — see the committed
[coverage report](docs/coverage-report.md). Includes three correlation
detections: execution→persistence kill-chain (100420), download↔execution via process
GUID (100430), and network-based ingress-tool-transfer (100310, closing T1105). See
[validation/](validation/) and [docs/detections.md](docs/detections.md).

**v1 attack scenarios:** brute-force→success (T1110→T1078), encoded PowerShell cradle
(T1059.001), scheduled-task persistence (T1053.005), DNS-tunnel C2 beacon (T1071.004).

## Documentation

| Doc | What's in it |
|-----|--------------|
| [docs/how-it-works.md](docs/how-it-works.md) | **Learning walkthrough** — every phase explained (problem, internals, code, concepts) for someone building it from scratch |
| [docs/architecture.md](docs/architecture.md) | Component breakdown + design rationale (prose) |
| [docs/architecture-diagram.md](docs/architecture-diagram.md) | Mermaid component / sequence / class diagrams |
| [docs/use-case-diagram.md](docs/use-case-diagram.md) | Actors and dashboard use cases (Mermaid) |
| [docs/dashboard-walkthrough.md](docs/dashboard-walkthrough.md) | Every control and view in the dashboard |
| [docs/detections.md](docs/detections.md) | Per-detection catalog (hypothesis, logic, ATT&CK, limits) |
| [docs/attack-coverage.md](docs/attack-coverage.md) · [docs/coverage-report.md](docs/coverage-report.md) | ATT&CK coverage map + measured results |
| [docs/roadmap.md](docs/roadmap.md) | Phased build log + next iterations |

## Quick start

Requires Docker Desktop (WSL2 backend) with ~8 GB RAM allocated. See the full runbook in
[infra/README.md](infra/README.md).

```bash
cd infra
cp .env.example .env      # then edit passwords
./bootstrap.sh            # clones pinned Wazuh stack, generates certs, brings it up
```
