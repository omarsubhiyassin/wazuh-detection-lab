# Detection tests

Unit tests for the custom rules in [../rules/local_rules.xml](../rules/local_rules.xml).
Each frozen sample is a real event line from the generator; the harness pipes it through
`wazuh-logtest` on the running manager and asserts the expected rule fires (or that a
benign sample stays at level 0, i.e. produces no alert).

## Run

Requires the lab stack up (see [../../infra/README.md](../../infra/README.md)):

```bash
detections/tests/run_logtest.sh
# override the manager container name if different:
MANAGER=single-node-wazuh.manager-1 detections/tests/run_logtest.sh
```

Exit code is non-zero if any case fails, so it drops straight into CI later.

## Cases

Defined in `cases.tsv` (`expected <TAB> sample <TAB> description`); `expected` is either a
rule ID that must fire or `NOALERT` (fired level must be 0).

| Sample | Expected | Technique |
|--------|----------|-----------|
| `encoded_powershell.log` | 100101 | T1059.001 |
| `schtasks_create.log` | 100110 | T1053.005 |
| `scheduled_task_4698.log` | 100121 | T1053.005 |
| `dns_txt_tunnel.log` | 100300 | T1071.004 |
| `benign_process.log` | NOALERT | — (must not alert) |
| `benign_dns.log` | NOALERT | — (must not alert) |

The two benign cases are the false-positive guard: a normal process creation matches only
the level-0 base rule (100100) and a normal DNS lookup only the level-0 Suricata parent
(86603), so neither generates an alert.

## Adding a case

1. Drop a one-line sample event in `samples/`.
2. Add a row to `cases.tsv` with the expected rule ID (or `NOALERT`).
3. Re-run `run_logtest.sh`.
