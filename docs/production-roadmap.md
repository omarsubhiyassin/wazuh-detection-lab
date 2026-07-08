# Production roadmap — org-ready SIEM

Where [roadmap.md](roadmap.md) tracked the v1 lab build, this tracks the path from
"working lab" to "an org can run its security monitoring on this." Architecture
decision (fixed): **single-tenant, fully automated** — every capability lands in
`bootstrap.sh`/`.env`, so a later managed-single-tenant SaaS is a provisioning
problem, not a re-architecture.

Already done on this track: dashboard session auth (scrypt + HttpOnly cookie,
fail-closed), and the one-command deploy — credentials driven end-to-end from
`.env` (vendored defaults rotated and refused, authenticated agent enrollment,
read-only account, verification report, idempotent re-runs).

## Phase 1 — Data lifecycle & alerting
The stack works but leaks disk and requires someone watching a screen.

- **Retention / index lifecycle**: ISM policy — alerts hot for `ALERTS_RETENTION_DAYS`,
  then delete; shorter window for the internal `wazuh-monitoring-*` / `wazuh-statistics-*`
  indices. Applied idempotently by bootstrap.
- **Notifications**: Wazuh integrator → Slack/email/webhook for alerts at/above a
  `.env` threshold. Turns the SIEM from a dashboard into a pager.
- **Active response** (opt-in): auto-block brute-forcing IPs at the agent firewall,
  with an allowlist to prevent self-lockout.

## Phase 2 — Platform hardening
- **TLS at the edges**: reverse proxy (Caddy/nginx) with real certs in front of both
  dashboards; `DASH_COOKIE_SECURE=true`; stop publishing 9200 to the host.
- **Rotate the last default**: the `wazuh-wui` API account, same bootstrap pattern.
- **Backup/restore**: scheduled indexer snapshots + manager state (`client.keys`,
  groups, config) and a rehearsed `restore.sh`. Untested backups don't count.
- **Self-monitoring**: healthcheck that alerts (via Phase 1) on ingestion stall,
  disk threshold, or container down. A silent SIEM is false confidence.
- **Upgrade rehearsal**: documented, tested version-bump + rollback using the
  existing pinning.

## Phase 3 — Real telemetry
- **Windows**: agent + curated Sysmon config (SwiftOnSecurity base, tuned). The
  existing rules already expect Sysmon-shaped events.
- **Linux**: auditd ruleset (execve, privilege changes, persistence paths).
- **Network**: real Suricata sensor feeding `eve.json`.
- **Fleet automation**: per-OS install/enroll scripts using the enrollment password
  (GPO/Ansible at scale); alert on disconnected agents.
- The synthetic **generator becomes the regression suite** — every rules change must
  keep measured recall at 100%.

## Phase 4 — Detection engineering as a discipline
- **CI**: every rules PR runs the logtest harness; merge deploys to the manager and
  re-runs the validation harness. The pieces exist; this wires them together.
- **Tuning workflow**: baseline real telemetry, encode suppressions as data (like the
  LSASS allowlist), track FP rate per rule.
- **Runbooks**: one page per detection — meaning, triage, escalation. Extends
  [detections.md](detections.md).
- **Coverage cadence**: regenerate the ATT&CK Navigator layer on a schedule so
  coverage stays measured, not aspirational.

## Phase 5 — SOC operations layer
- **Triage state**: acknowledge/investigate/close on alerts — either TheHive
  integration or lightweight status in the custom dashboard (adds a deliberate,
  least-privilege write path).
- **Dashboard RBAC**: multiple users, analyst vs admin, audit log of access —
  extends the existing session-auth layer.
- **Escalation policy**: who gets the level-15 page at 3am, in writing.

## Phase 6 — Productization (managed single-tenant)
- **Tenant provisioning**: wrap bootstrap in Terraform/cloud-init — "new org" =
  one pipeline run producing an isolated VM + stack + creds + enrollment package.
- **Central fleet view**: per-tenant healthchecks reporting to one place.
- **Docs as product**: onboarding guide, agent packages, security one-pager — what
  an org's IT team needs to approve.

**Sequencing:** 1–2 make the box trustworthy, 3 makes it real, 4–5 make it operable
by people other than the author, 6 makes it repeatable. Each phase independently
demoable, as in v1.
