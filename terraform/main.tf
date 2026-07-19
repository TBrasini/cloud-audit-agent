# ---------------------------------------------------------------------------
# Environnement de démo VOLONTAIREMENT mal configuré, destiné uniquement à
# tester le scanner (scanner/checks.py) dans un compte AWS sandbox/jetable.
#
# NE JAMAIS appliquer ce Terraform sur un compte de production.
# ---------------------------------------------------------------------------

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- S3-01 : bucket sans Block Public Access complet ------------------------
resource "aws_s3_bucket" "demo_public" {
  bucket = var.demo_bucket_name

  tags = {
    Purpose = "cloud-audit-agent-demo"
    Warning = "DO-NOT-USE-IN-PRODUCTION"
  }
}

resource "aws_s3_bucket_public_access_block" "demo_public" {
  bucket = aws_s3_bucket.demo_public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# --- SG-01 : security group ouvert sur le port 22 depuis 0.0.0.0/0 ----------
resource "aws_security_group" "demo_open_ssh" {
  name        = "cloud-audit-agent-demo-open-ssh"
  description = "Demo intentionally insecure SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Purpose = "cloud-audit-agent-demo"
    Warning = "DO-NOT-USE-IN-PRODUCTION"
  }
}

# --- EBS-01 : volume non chiffré --------------------------------------------
resource "aws_ebs_volume" "demo_unencrypted" {
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = false

  tags = {
    Purpose = "cloud-audit-agent-demo"
    Warning = "DO-NOT-USE-IN-PRODUCTION"
  }
}
