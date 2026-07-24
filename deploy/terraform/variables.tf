variable "tenant_name" {
  description = "Fleet identifier for this deployment (a-z0-9-)."
  type        = string
}

variable "git_repo" {
  description = "Clone URL for the detection-lab repo, incl. auth for a private repo (deploy token or SSH)."
  type        = string
}

variable "slack_webhook" {
  description = "Slack incoming-webhook URL for alerts (empty to disable)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "ami" {
  description = "Ubuntu 22.04+ AMI id for the region."
  type        = string
}

variable "instance_type" {
  description = "The indexer is a JVM — give it room. 8 GB RAM minimum."
  type        = string
  default     = "t3.large"
}

variable "disk_gb" {
  description = "Root volume size (indexer data + snapshots)."
  type        = number
  default     = 60
}

variable "key_name" {
  description = "Name of an existing EC2 key pair for SSH admin access."
  type        = string
}

variable "admin_cidrs" {
  description = "CIDRs allowed to SSH in (your IP/VPN — do NOT use 0.0.0.0/0)."
  type        = list(string)
}

variable "agent_cidrs" {
  description = "CIDRs Wazuh agents connect from (1514/1515). Enrollment is authd-password gated."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
