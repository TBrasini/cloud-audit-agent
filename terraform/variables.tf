variable "region" {
  description = "Région AWS utilisée pour l'environnement de démo"
  type        = string
  default     = "eu-west-3"
}

variable "demo_bucket_name" {
  description = "Nom du bucket S3 de démo (doit être globalement unique)"
  type        = string
  default     = "cloud-audit-agent-demo-bucket-changeme"
}
