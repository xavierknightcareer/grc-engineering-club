terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region

  # TODO (CM-6): add a default_tags block so every taggable resource carries
  # Project, Environment, ManagedBy, and ComplianceScope automatically.

  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "pci" # or whatever value you choose
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  primary_name = "${var.project_name}-${var.environment}-data-${random_id.suffix.hex}"
  log_name     = "${var.project_name}-${var.environment}-logs-${random_id.suffix.hex}"
}

# The two base buckets are here so the skeleton validates. The controls are yours.
resource "aws_s3_bucket" "primary" {
  bucket = local.primary_name
}

resource "aws_s3_bucket" "log" {
  bucket = local.log_name
}

# ---------------------------------------------------------------------------
# YOUR BUILD: add the controls. Each is one or more resources you write.
#
#   SC-28  encrypt the primary bucket at rest, and the log bucket too.
#   CM-6   turn on versioning for the primary bucket.
#   AC-3   block public access on both buckets. All four flags must be true.
#   AU-3   let the log bucket receive access logs (ownership controls, then a
#          log-delivery-write ACL), and point the primary bucket's logging at it.
#
# Look up the AWS provider resource names in the Terraform registry. The full
# brief on Patreon explains what each control is and how to verify it.
# ---------------------------------------------------------------------------

# ---------- SC-28: encrypt both buckets at rest ----------

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
# ---------- CM-6 Versioning for the primary bucket ----------

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}


# ---------- AC-3 Block public access on both buckets. All four flags must be true ----------

resource "aws_s3_bucket_public_access_block" "primary" {
  bucket = aws_s3_bucket.primary.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket = aws_s3_bucket.log.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


# ----------  AU-3 let the log bucket receive access logs (ownership controls, then a log-delivery-write ACL), and point the primary bucket's logging at it. ----------


resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.log.id
  acl    = "log-delivery-write"

  depends_on = [
    aws_s3_bucket_ownership_controls.log,
    aws_s3_bucket_public_access_block.log
  ]
}

resource "aws_s3_bucket_logging" "primary" {
  bucket = aws_s3_bucket.primary.bucket

  target_bucket = aws_s3_bucket.log.bucket
  target_prefix = "log/"
  target_object_key_format {
    partitioned_prefix {
      partition_date_source = "EventTime"
    }
  }
}