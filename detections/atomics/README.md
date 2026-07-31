# Atomic Red Team validation

Validating detections against **real attacker tooling** instead of only the frozen
generator samples. The [existing harness](../tests/README.md) replays captured events; this
proves the rules fire when an actual technique is executed on the enrolled endpoint.

## The honest shape of this

Atomic Red Team executes real behaviour (dumping LSASS, clearing event logs, PsExec) on a
real host, and our Windows detections read Sysmon telemetry through the
`windows_eventchannel` decoder — which `wazuh-logtest` **cannot decode**. So there is no
faithful way to run atomics inside an ephemeral CI runner against these detections. Pretending
otherwise would be exactly the kind of impressive-but-false validation this project avoids.

So the work splits in two:

| | What | Where |
|---|---|---|
| **CI (hermetic)** | Keep the detection↔atomic *mapping* honest | `validate_atomics.py` |
| **Live (endpoint)** | Actually detonate the atomics and confirm alerts fired | `Invoke-AtomicValidation.ps1` + `assert_alerts.sh` |

## CI: what `validate_atomics.py` guarantees

Every custom detection (level > 0, MITRE-mapped, not a vendor overwrite) is **accounted
for** in [`coverage.yml`](coverage.yml) — mapped to a specific Atomic Red Team test by GUID,
or explicitly exempted with a reason and an alternative validation. Then:

- every mapped **GUID is real** — checked against [`index.snapshot.json`](index.snapshot.json),
  a minimal snapshot built from Atomic Red Team pinned at commit `1ba1dd8`, so a typo'd or
  invented test fails the build;
- the **platform matches** what the atomic supports;
- the live runner's hardcoded list stays **in sync** with the mapping;
- exemptions actually **explain themselves**.

Currently: **16 detections — 10 mapped to atomics, 6 exempted.**

## What the cross-reference surfaced

Mapping our rules to real atomics exposed that our technique tags don't line up 1:1 with
where ART files its tests — which is the point of doing it:

- **Clear-event-log atomics moved.** We (and MITRE) tag log clearing `T1070.001`; at this ART
  commit the atomics live under `T1685.005`, and `T1070.001` has no file at all. The atomic is
  right, the ID differs — recorded per rule (100600, 100601).
- **SSH brute force has no faithful atomic.** Our 100400 is a Linux SSH brute-force-then-success
  correlation; ART's brute-force atomics are Windows password-spray. Exempted, validated by the
  fleet attack simulation instead.
- **Correlation rules need a sequence** (100420, 100430), so no single atomic triggers them;
  they're validated by chaining the component atomics.

## Live validation (on the endpoint)

On the enrolled Windows host (this project's AMIGO), in an **elevated** PowerShell:

```powershell
Install-Module invoke-atomicredteam -Scope CurrentUser -Force   # one-time
Import-Module invoke-atomicredteam

.\Invoke-AtomicValidation.ps1 -WhatIf      # dry run — lists what would execute
.\Invoke-AtomicValidation.ps1              # detonate all mapped atomics (+cleanup)
```

Then confirm the detections saw it, from the lab host / WSL:

```bash
detections/atomics/assert_alerts.sh '<window-start-ISO printed by the PS1>'
```

`assert_alerts.sh` queries the indexer for each expected rule ID since the window start and
fails if any is missing — the atomic ran but the detection didn't see it, which is precisely
the pipeline break worth catching.

> **Safety:** these atomics are real. Run only on a lab endpoint you own and can restore.
> `-WhatIf` first, always.

## Updating the ART snapshot

The snapshot is pinned for reproducibility. To refresh it to a newer Atomic Red Team commit,
re-fetch the referenced techniques at the new ref, rebuild `index.snapshot.json`, update
`meta.atomic_red_team_ref` in `coverage.yml` to match, and re-run the validator — it fails if
the two refs disagree or any mapped GUID no longer exists.
