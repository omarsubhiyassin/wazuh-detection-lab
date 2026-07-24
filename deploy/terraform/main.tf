# One tenant = one `terraform apply`. Provisions an EC2 VM whose user-data is
# the cloud-init that installs Docker, clones the repo, generates fresh secrets
# (provision-env.sh), and deploys the whole stack — unattended.
#
# AWS is used as a concrete example; the shape (VM + firewall + cloud-init)
# ports to any provider. `terraform apply` needs YOUR cloud account/credentials.

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

# Render the shared cloud-init, substituting the __TOKENS__. replace() (not
# templatefile) so the cloud-init's own bash ${VAR} references stay intact.
locals {
  user_data = replace(replace(replace(
    file("${path.module}/../cloud-init.yaml"),
    "__GIT_REPO__", var.git_repo),
    "__TENANT_NAME__", var.tenant_name),
    "__SLACK_WEBHOOK__", var.slack_webhook)
}

# --- Firewall: the security boundary -----------------------------------------
# Only agent traffic faces the internet (and it is authd-password gated). The
# indexer (9200), Wazuh dashboard (443), custom dashboard (8787) and API (55000)
# are bound to localhost on the host — reach them over an SSH tunnel:
#   ssh -L 8787:localhost:8787 -L 443:localhost:443 ubuntu@<ip>
resource "aws_security_group" "tenant" {
  name        = "detection-lab-${var.tenant_name}"
  description = "detection-lab tenant ${var.tenant_name}"

  ingress {
    description = "Wazuh agent comms"
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = var.agent_cidrs
  }
  ingress {
    description = "SSH admin (restrict to your IP/VPN)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "detection-lab-${var.tenant_name}", tenant = var.tenant_name }
}

resource "aws_instance" "tenant" {
  ami                    = var.ami
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.tenant.id]
  user_data              = local.user_data

  root_block_device {
    volume_size = var.disk_gb # indexer + snapshots need headroom
    volume_type = "gp3"
  }
  tags = { Name = "detection-lab-${var.tenant_name}", tenant = var.tenant_name }
}
