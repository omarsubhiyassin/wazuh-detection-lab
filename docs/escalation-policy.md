# Escalation policy

Who responds to what, how fast, and when to wake someone up. Pairs with the
per-detection [runbooks.md](runbooks.md) (how to triage a given alert) — this
says *how urgently* and *to whom*. Adapt the names/channels to the real org;
the structure is what matters.

## Severity tiers

Driven by the Wazuh rule **level** (0–15). Level ≥ `NOTIFY_MIN_LEVEL` (default 12)
already pages `#all-soc-alert` via the integrator.

| Tier | Level | Examples | Response time | Notify |
|------|-------|----------|---------------|--------|
| **P1 Critical** | 14–15, or any confirmed correlation (100400/100420/100430) or credential access (100700/100701) | account compromise, LSASS dump, kill-chain | **15 min**, 24/7 | Page on-call **immediately** (phone), post `#soc-incidents`, start an incident |
| **P2 High** | 12–13 | encoded PowerShell, scheduled-task persistence, log clearing, PsExec, download-from-IP | **1 hour** during on-hours; next morning if after-hours and isolated | `#all-soc-alert` (auto), analyst acknowledges |
| **P3 Medium** | 8–11 | base scheduled-task (4698), single tunneling query | **1 business day** | dashboard triage queue |
| **P4 Low / info** | 0–7 | SCA findings, session open/close, agent status | best effort / weekly review | none |

## Roles

- **On-call analyst** — first responder. Acknowledges P1/P2 within the response
  time, triages in the dashboard (sets status + assignee), contains or escalates.
- **Incident lead** (senior analyst / eng) — owns any P1 that becomes an
  incident: coordinates, decides on containment, communicates.
- **Dashboard admin** — manages users/roles, reviews the audit log, tunes rules
  (via the [detection lifecycle](../detections/deploy-rules.sh) + CI).

## Flow

1. **Alert fires** → level ≥ 12 auto-posts to `#all-soc-alert`.
2. **Acknowledge** in the dashboard (status → *acknowledged*, assign yourself)
   within the tier's response time. Unacknowledged P1s auto-escalate (see below).
3. **Triage** per the [runbook](runbooks.md) for that rule. Set *investigating*.
4. **Decide**: benign → *closed* with a note (and tune if it's a recurring FP);
   suspicious → investigate the host; confirmed → **declare an incident**.
5. **Incident (P1):** page the incident lead, open `#soc-incidents`, contain
   (isolate host / disable account / block IP), preserve evidence, then eradicate
   and recover. Record actions; the dashboard triage note + audit log are the
   first timeline.

## Auto-escalation

- A **P1** not acknowledged in 15 min → page the incident lead (backup path).
- Any host with **two+ high alerts** in a short window (e.g. execution +
  persistence, or brute-force + success) is treated as **P1** regardless of
  individual levels — that's the correlation rules' job, and 100400/100420/100430
  already encode the strongest of these.
- **Healthcheck** failures (stack down, ingestion stalled) page like a P2 — a
  blind SIEM is an incident of its own. See [infra/healthcheck.sh](../infra/healthcheck.sh).

## After hours

P1 pages 24/7. Isolated P2/P3 can wait for the next business morning **unless**
they correlate on a host with anything else — then treat as P1. When in doubt,
escalate; a false page costs minutes, a missed compromise costs far more.

## Review cadence

- **Weekly:** clear the P3 triage queue; review closed-as-FP alerts and open
  tuning tickets (fix as allow-list data + a benign test sample — see the
  [runbooks tuning workflow](runbooks.md#tuning-workflow)).
- **Monthly:** review the audit log for access patterns; regenerate the ATT&CK
  coverage layer (`validation/validate.py`); confirm every P1 in the period had
  a documented response.
