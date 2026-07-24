# Tenant provisioning

"New org = one pipeline run." Each tenant is an isolated VM running the full
stack, provisioned unattended. Single-tenant by design — no shared data plane —
so this is a provisioning problem, not a multi-tenancy re-architecture.

## The pieces

| File | Role |
|------|------|
| [`../infra/provision-env.sh`](../infra/provision-env.sh) | generates a fresh `.env` with random secrets + a one-time credentials file (no manual passwords) |
| [`cloud-init.yaml`](cloud-init.yaml) | on a fresh Ubuntu VM: install Docker, clone the repo, run provision-env + bootstrap |
| [`terraform/`](terraform/) | provisions the VM + firewall and feeds it the cloud-init |

## Terraform path (recommended)

```bash
cd deploy/terraform
cat > tenant.tfvars <<EOF
tenant_name   = "acme-soc"
git_repo      = "https://<deploy-token>@github.com/omarsubhiyassin/wazuh-detection-lab.git"
ami           = "ami-xxxxxxxx"   # Ubuntu 22.04+ in your region
key_name      = "my-ec2-key"
admin_cidrs   = ["203.0.113.10/32"]   # your IP/VPN — never 0.0.0.0/0
slack_webhook = "https://hooks.slack.com/services/..."
EOF
terraform init
terraform apply -var-file=tenant.tfvars
```

`apply` needs **your** cloud account. Outputs give the SSH command, the
dashboard SSH-tunnel command, and where the generated credentials land. The VM
boots, provisions itself, and comes up green in a few minutes
(`/var/log/provision-tenant.log`).

## Manual path (any Ubuntu host / bare metal)

```bash
git clone <repo> /opt/detection-lab && cd /opt/detection-lab/infra
sudo sysctl -w vm.max_map_count=262144
./provision-env.sh --tenant acme-soc --root /opt/detection-lab
# optional: set SLACK_WEBHOOK_URL in .env
./bootstrap.sh
```

## After provisioning

1. **Retrieve the credentials**: `infra/.provision-credentials.txt` (mode 600) —
   save to your secrets vault, then **delete the file**. Nothing else records the
   plaintext; bootstrap keeps only hashes.
2. **Reach the dashboards** over an SSH tunnel (they are localhost-bound):
   `ssh -L 8787:localhost:8787 -L 443:localhost:443 ubuntu@<ip>`.
3. **Enroll endpoints** with the agent installers in [`../fleet/`](../fleet/) and
   the tenant's `AGENT_ENROLLMENT_PASSWORD`.

## Fleet view

Every tenant's `healthcheck.sh` posts to Slack tagged with its `TENANT_NAME`, so
one channel is a lightweight fleet board — a red/green line per tenant, plus
recovery notices. (A dedicated multi-tenant status page is future work.)
