# METADATA
# title: SC-28 - Encryption at Rest (AWS S3)
# description: Every aws_s3_bucket must have a matching server-side encryption configuration.
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: Add aws_s3_bucket_server_side_encryption_configuration referencing the bucket.
package compliance.sc28_aws



# YOUR BUILD: deny any aws_s3_bucket that has no matching
# aws_s3_bucket_server_side_encryption_configuration.
#
# Technique: at plan time the bucket name is unknown, so match by reference, not
# value. Bucket addresses live in input.configuration.root_module.resources[]
# (type == "aws_s3_bucket"). The encryption resource references its bucket in
# .expressions.bucket.references (strings like "aws_s3_bucket.primary.id").
#
# Make the two tests in sc28_encryption_aws_test.rego pass. The stub below keeps
# `deny` defined so the tests load. Replace it.
deny contains msg if {
	false
	msg := "todo"
}



#-------------------Start----------------------
import rego.v1

# All the resources from the plan's configuration section.
resources := input.configuration.root_module.resources

# Every reference string that an encryption block points at.
# Terraform writes these as "aws_s3_bucket.primary.id".
encrypted_refs contains ref if {
	some r in resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
}

deny contains msg if {
	some r in resources
	r.type == "aws_s3_bucket"

	# What an encryption block would reference if it pointed at this bucket.
	addr := concat(".", ["aws_s3_bucket", r.name])

	# Nothing in the plan references it.
	not is_referenced(addr)

	msg := concat("", ["bucket ", r.name, " has no encryption configuration"])
}

is_referenced(addr) if {
	some ref in encrypted_refs
	startswith(ref, addr)
}
