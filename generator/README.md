# Synthetic log generator

Produces **real-format** logs mixing benign baseline noise with MITRE ATT&CK-mapped
attack scenarios, plus a `ground_truth.jsonl` the validation harness (Phase 6) scores
detections against.

Real formats are used deliberately: Wazuh's built-in decoders parse sshd `auth.log`,
Windows Event JSON, and Suricata `eve.json` out of the box, so the custom work stays at
the *detection-logic* layer rather than plumbing.

## Usage

```bash
pip install -r requirements.txt        # only dep: PyYAML

# 6-hour historical window, all scenarios, reproducible:
python generate.py --hours 6 --seed 1337

# subset of scenarios, no benign noise:
python generate.py --scenarios brute_force_success,dns_beacon --no-baseline

# live demo, replayed 60x faster than real time:
python generate.py --mode stream --compression 60
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--seed` | `1337` | RNG seed; a given seed reproduces identical logs + labels |
| `--mode` | `backfill` | `backfill` writes a historical window at once; `stream` replays in real time |
| `--hours` | `6` | length of the generation window |
| `--compression` | `60` | stream mode: sim-seconds per real-second |
| `--scenarios` | `all` | comma-separated scenario names, or `all` |
| `--no-baseline` | off | skip benign background noise |
| `--out` | `output/` | log output directory |
| `--ground-truth` | `ground_truth/ground_truth.jsonl` | labels path |

## Output

Written to `output/` (tailed by the Wazuh agent — see `infra/config/agent-ossec.conf`):

| File | Format | Sources |
|------|--------|---------|
| `auth.log` | syslog | Linux sshd/sudo |
| `windows_events.json` | Windows Event JSON (`win.system` / `win.eventdata`) | Sysmon 1, Security 4698 |
| `eve.json` | Suricata eve JSON | DNS, flow |

`ground_truth/ground_truth.jsonl` — one label per injected attack event:
`{event_id, timestamp, epoch, technique_id, tactic, scenario, host, source, src_ip,
expected_rules, note}`.

## Design

```
generate.py         CLI: window, seed, mode; places scenarios; writes output
  world.py          seeded hosts / users / IPs + GUID & record-id counters
  baseline.py       benign SSH / Windows / DNS noise (diurnal weighting)
  timeline.py       deferred-event scheduler + sinks + ground-truth labels
  emitters/         pure format functions (no I/O): sshd, windows, suricata
  scenarios/
    *.yaml          declarative playbooks: narrative, MITRE map, tunable params
    engine.py       loads playbooks, dispatches by `kind`
    builders.py     one builder per kind; emits correlated events + labels
```

**Deferred events.** Builders append `(offset, sink, render)` where `render(ts)` formats
the line for an absolute time. The same schedule materializes two ways: *backfill*
(resolve `ts = start + offset`, sort, write) or *stream* (replay in real time, stamping
each line with the wall-clock time it fires). See `timeline.py`.

**Correlation.** Events within a scenario share host / user / src-IP and realistic timing
(burst vs. low-and-slow beacon) so Wazuh correlation rules (Phase 4) can stitch them into
composite alerts.

## v1 scenarios

| Playbook | ATT&CK | Sources |
|----------|--------|---------|
| `brute_force_success` | T1110 → T1078 | `auth.log` |
| `powershell_cradle` | T1059.001, T1105 | `windows_events.json` (Sysmon 1) |
| `scheduled_task` | T1053.005 | `windows_events.json` (Sysmon 1 + Security 4698) |
| `dns_beacon` | T1071.004 | `eve.json` (Suricata DNS) |

## Adding a scenario

1. Add `scenarios/<name>.yaml` with `name`, `kind`, `mitre`, and `params`.
2. Add a builder function to `scenarios/builders.py` and register it in `BUILDERS`.
3. It's picked up automatically; `--scenarios <name>` runs it alone.
