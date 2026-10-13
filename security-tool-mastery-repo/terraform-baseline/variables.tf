variable "admin_ip_cidr" {
  description = "Administrator's IP address in CIDR notation, e.g. 203.0.113.4/32. Never use 0.0.0.0/0 here."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for the lab's S3 bucket"
  type        = string
  default     = "cloud-security-lab-rahul-2026"
}

variable "alert_email" {
  description = "Email address to receive CloudWatch alarm notifications via SNS"
  type        = string
}
