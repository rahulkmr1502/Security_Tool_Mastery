variable "aws_region" {
  description = "Region for all lab resources"
  type        = string
  default     = "ap-south-1"
}

variable "admin_ip_cidr" {
  description = "Administrator's IP in CIDR notation, e.g. 203.0.113.4/32. Never 0.0.0.0/0."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique prefix for the lab's S3 buckets"
  type        = string
  default     = "cloud-security-lab-rahul-2026"
}

variable "alert_email" {
  description = "Email that receives SNS alarm notifications and budget alerts"
  type        = string
}
