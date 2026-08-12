# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: Every aws_s3_bucket must have a public access block with all four flags true.
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: Add aws_s3_bucket_public_access_block referencing the bucket, all four flags true.
package compliance.ac3_aws



# TODO (your build): deny any aws_s3_bucket that does not have a matching
# aws_s3_bucket_public_access_block with block_public_acls, block_public_policy,
# ignore_public_acls, and restrict_public_buckets all set to true.
#
# Match the bucket by reference the way sc28_encryption_aws.rego does, in
# input.configuration.root_module.resources[].expressions.bucket.references.
# Read the four flag values from input.planned_values.root_module.resources[]
# where .address is the public access block's address.
#
# The stub below keeps `deny` defined (empty) so the test file loads. Replace it.
deny contains msg if {
	false
	msg := "todo"
}



#-------------------Start----------------------
import rego.v1

config_resources := input.configuration.root_module.resources

planned_resources := input.planned_values.root_module.resources

deny contains msg if {
	some r in config_resources
	r.type == "aws_s3_bucket"
	addr := concat(".", ["aws_s3_bucket", r.name])
	not protected(addr)
	msg := concat("", ["bucket ", r.name, " is missing a complete public access block"])
}

# A bucket is protected if some public access block references it AND
# that block has all four flags turned on in planned_values.
protected(addr) if {
	some pab in config_resources
	pab.type == "aws_s3_bucket_public_access_block"

	some ref in pab.expressions.bucket.references
	startswith(ref, addr)

	pab_addr := concat(".", ["aws_s3_bucket_public_access_block", pab.name])
	all_flags_true(pab_addr)
}

all_flags_true(pab_addr) if {
	some p in planned_resources
	p.address == pab_addr
	p.values.block_public_acls
	p.values.block_public_policy
	p.values.ignore_public_acls
	p.values.restrict_public_buckets
}
