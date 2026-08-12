terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project         = "grc-challenge"
      Environment     = "dev"
      ManagedBy       = "terraform"
      ComplianceScope = "pci"
      Purpose         = "evidence-vault"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "pipeline_role_name" {
  type        = string
  description = "The role the GitHub Actions workflow assumes via OIDC."
  default     = "github-actions-terraform-plan"
}

variable "retention_days" {
  type        = number
  description = "Object Lock retention period. Kept at 1 for sandbox teardown."
  default     = 1
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  vault_name = "grc-evidence-vault-${random_id.suffix.hex}"
}

# ---------------------------------------------------------------------------
# The vault.
#
# Object Lock can ONLY be enabled at bucket creation. There is no way to
# retrofit it onto an existing bucket, which is why this is a new bucket
# rather than a change to the week-1 buckets.
#
# Versioning is a hard prerequisite for Object Lock and cannot be suspended
# while Object Lock is on.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "vault" {
  bucket              = local.vault_name
  object_lock_enabled = true

  # Sandbox convenience. Remove for anything real -- the whole point of a
  # vault is that it outlives the person who made it.
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

# GOVERNANCE mode: a principal holding s3:BypassGovernanceRetention can delete
# early, which is how this sandbox gets torn down today. Production evidence
# would use COMPLIANCE, which nobody -- including the account root -- can
# bypass until the retention period expires.
resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket = aws_s3_bucket.vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Pipeline write access.
#
# Deliberately narrow: the pipeline can put objects into this one bucket and
# nothing else. No delete, no bypass, no read of other buckets. A compromised
# workflow can add evidence but cannot remove or alter it.
# ---------------------------------------------------------------------------
data "aws_iam_role" "pipeline" {
  name = var.pipeline_role_name
}

resource "aws_iam_policy" "vault_write" {
  name        = "grc-evidence-vault-write"
  description = "Write-only access to the evidence vault for the CI pipeline."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PutEvidenceObjects"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectRetention",
        ]
        Resource = "${aws_s3_bucket.vault.arn}/*"
      },
      {
        Sid      = "ReadRetentionForVerification"
        Effect   = "Allow"
        Action   = ["s3:GetObjectRetention", "s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.vault.arn}/*"
      },
      {
        Sid      = "ListVaultOnly"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"]
        Resource = aws_s3_bucket.vault.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "pipeline_vault_write" {
  role       = data.aws_iam_role.pipeline.name
  policy_arn = aws_iam_policy.vault_write.arn
}

# ---------------------------------------------------------------------------
output "vault_bucket" {
  description = "Evidence vault bucket name. Feed this to the workflow."
  value       = aws_s3_bucket.vault.id
}

output "vault_arn" {
  value = aws_s3_bucket.vault.arn
}

output "retention_mode" {
  description = "Machine-readable attestation of the preservation control."
  value       = "GOVERNANCE/${var.retention_days}d"
}

