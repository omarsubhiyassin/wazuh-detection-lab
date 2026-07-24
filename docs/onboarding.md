# Onboarding a new organization

What it takes to stand up monitoring for a new org, and the one-pager an org's
IT/security team needs to approve it. Mechanics live in
[../deploy/README.md](../deploy/README.md); this is the people/process view.

## Stand-up checklist

1. **Provision the tenant** — `terraform apply` (or the manual path). ~5 min to a
   green stack. Save the generated credentials to the vault; delete the file.
2. **Wire alerting** — set the tenant's `SLACK_WEBHOOK_URL` (or leave it on the
   shared fleet channel); confirm a test alert arrives.
3. **Enroll a pilot endpoint** — one Windows or Linux host via [../fleet/](../fleet/)
   and the tenant's enrollment password. Confirm it goes Active and a real
   detection fires (e.g. encoded PowerShell → rule 100101).
4. **Set retention + backups to the org's policy** — `ALERTS_RETENTION_DAYS`,
   `BACKUP_DIR`/`BACKUP_KEEP`; rehearse a restore (`restore.sh --rehearse`).
5. **Create analyst logins** — `npm run add-user` in `dashboard/` for each
   analyst (role `analyst`) and admin; agree the [escalation policy](escalation-policy.md).
6. **Roll out agents** to the fleet (GPO/Ansible with the installers).
7. **Baseline for 2–4 weeks**, then tune false positives as allow-list data
   (see the [runbooks tuning workflow](runbooks.md#tuning-workflow)).

## Security one-pager (for the org's IT/security to approve)

**What it is.** A single-tenant SIEM (Wazuh: manager + OpenSearch indexer +
dashboards) on a dedicated VM the org controls. No data is shared with other
tenants — isolation is physical, one VM per org.

**What it collects.** Security telemetry from enrolled endpoints only: Windows
Sysmon + Security events, Linux `auth.log`/`syslog`/auditd. No document contents,
keystrokes, or browsing — process/network/auth security events. Data stays on the
tenant VM (the org's cloud account or hardware).

**Network exposure.** Only the agent-comms ports (1514/1515 TCP) face the
network, and enrollment requires a shared password (authd). The indexer (9200),
both dashboards (443, 8787) and the API (55000) are **bound to localhost** and
reached only via SSH tunnel or VPN. SSH is restricted to the admin CIDR.

**Access & audit.** Dashboard access is role-based (viewer/analyst/admin) with
scrypt-hashed passwords and `HttpOnly; Secure; SameSite` sessions; every login
and alert-triage action is written to an append-only audit log. Service accounts
are least-privilege (the dashboard reads alerts through a read-only account).

**Credentials.** No default passwords ship — every secret is generated per
tenant at provisioning and stored only as a hash on the box; the plaintext exists
once, for the vault.

**Data lifecycle.** Alerts auto-expire per the org's retention setting; encrypted
snapshots run daily; restore is rehearsed, not assumed.

**Change safety.** Detection rules are version-controlled, CI-tested against a
real manager on every change, and deployed with an auto-rollback safety net.

**Data handling / privacy.** Security-event metadata only; retention is
org-configured; deletion on decommission is `terraform destroy` (VM + all data).
