output "public_ip" {
  description = "Tenant VM public IP."
  value       = aws_instance.tenant.public_ip
}

output "ssh" {
  description = "SSH in (provisioning log: /var/log/provision-tenant.log)."
  value       = "ssh ubuntu@${aws_instance.tenant.public_ip}"
}

output "dashboards_tunnel" {
  description = "Open the localhost-bound dashboards over an SSH tunnel, then browse https://localhost:8787 and https://localhost:443."
  value       = "ssh -L 8787:localhost:8787 -L 443:localhost:443 ubuntu@${aws_instance.tenant.public_ip}"
}

output "credentials_note" {
  description = "Where the one-time generated credentials land."
  value       = "After boot: cat /opt/detection-lab/infra/.provision-credentials.txt (save to your vault, then delete)."
}
