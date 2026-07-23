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

## Phase 4 — Detection engineering as a discipline ✅
- **CI** ✅: [`.github/workflows/detections-ci.yml`](../.github/workflows/detections-ci.yml)
  lints `local_rules.xml` (XML + unique IDs) and runs the full logtest harness against a
  fresh pinned Wazuh manager on every change to `detections/**`. Verified green on GitHub.
- **Safe deploy** ✅: [`detections/deploy-rules.sh`](../detections/deploy-rules.sh) —
  pre-flight XML check, back up live rules, restart, verify analysisd came back, smoke-test
  with the harness, and **auto-rollback** if anything fails (a bad rule otherwise takes the
  whole manager down). CI validates in the cloud; deploy is local because the manager is
  single-tenant/local — for a real remote manager a self-hosted runner would deploy on merge.
- **Runbooks** ✅: [runbooks.md](runbooks.md) — per-detection triage/escalation, plus the
  tuning workflow (fix FPs as allow-list data + a benign test sample guarded by CI).
- **Coverage cadence**: `validation/validate.py` regenerates `coverage.md` + the ATT&CK
  Navigator layer from live indexed data; schedule it via cron (needs the running stack).

## Phase 5 — SOC operations layer ✅
- **Triage state** ✅: acknowledge/investigate/close + assignee + note per alert,
  attributed to the acting user. A deliberate least-privilege write path kept OUT
  of the indexer (a persisted store on the BFF); merged into the alert feed as a
  badge + drawer controls. analyst+ only.
- **Dashboard RBAC** ✅: `dashboard/users.json` directory with roles
  viewer &lt; analyst &lt; admin; `requireRole` gates write/admin endpoints;
  `npm run add-user` manages users. Sessions carry the role.
- **Audit log** ✅: append-only JSONL of logins/logouts and triage actions,
  admin-only panel. Verified end-to-end in the browser against live data.
- **Escalation policy** ✅: [escalation-policy.md](escalation-policy.md) — severity
  tiers, response times, on-call/incident roles, auto-escalation, review cadence.

## Phase 6 — Productization (managed single-tenant)
- **Tenant provisioning**: wrap bootstrap in Terraform/cloud-init — "new org" =
  one pipeline run producing an isolated VM + stack + creds + enrollment package.
- **Central fleet view**: per-tenant healthchecks reporting to one place.
- **Docs as product**: onboarding guide, agent packages, security one-pager — what
  an org's IT team needs to approve.

**Sequencing:** 1–2 make the box trustworthy, 3 makes it real, 4–5 make it operable
by people other than the author, 6 makes it repeatable. Each phase independently
demoable, as in v1.
