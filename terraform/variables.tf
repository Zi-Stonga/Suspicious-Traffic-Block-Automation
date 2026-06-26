variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment: prod, staging, or dev"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "environment must be prod, staging, or dev."
  }
}

variable "owner_tag" {
  description = "Team or individual owning this stack"
  type        = string
  default     = "security-team"
}

variable "alert_email" {
  description = "Email address for block notifications. Must confirm SNS subscription after deploy."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "Must be a valid email address."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 90

  validation {
    condition     = contains([1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1827,3653], var.log_retention_days)
    error_message = "Must be a valid CloudWatch retention value."
  }
}

variable "block_ttl_hours" {
  description = "Hours an automatic block stays active before expiring. Range 1-720."
  type        = number
  default     = 24

  validation {
    condition     = var.block_ttl_hours >= 1 && var.block_ttl_hours <= 720
    error_message = "block_ttl_hours must be between 1 and 720."
  }
}

variable "max_firewall_rules" {
  description = "Capacity of the Network Firewall rule group. Immutable after creation."
  type        = number
  default     = 1000

  validation {
    condition     = var.max_firewall_rules >= 100 && var.max_firewall_rules <= 30000
    error_message = "max_firewall_rules must be between 100 and 30000."
  }
}
