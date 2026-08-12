# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# description: Taggable resources must carry the four required compliance tags.
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: Add the missing tags or rely on provider default_tags.
package compliance.cm6_aws



# TODO (your build): deny any taggable resource that is missing one or more
# required tags. With provider default_tags enabled, the merged set is in
# values.tags_all; fall back to values.tags. Read resources from
# input.planned_values.root_module.resources (and child_modules if you nest).
#
# The stub keeps `deny` defined (empty) so the test file loads. Replace it.
deny contains msg if {
	false
	msg := "todo"
}



#-------------------Start----------------------
import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

# Resources that use provider default_tags: the merged set lands in tags_all.
deny contains msg if {
	some r in input.planned_values.root_module.resources
	tags := r.values.tags_all
	missing := missing_tags(tags)
	count(missing) > 0
	msg := concat("", [r.address, " is missing required tags: ", concat(", ", missing)])
}

# Resources with only tags set (no provider default_tags in play).
deny contains msg if {
	some r in input.planned_values.root_module.resources
	not r.values.tags_all
	tags := r.values.tags
	missing := missing_tags(tags)
	count(missing) > 0
	msg := concat("", [r.address, " is missing required tags: ", concat(", ", missing)])
}

# Which required tags are absent from this resource. Sorted so the message
# is stable across runs, which matters when the output is diffed in CI.
missing_tags(tags) := sorted if {
	found := {tag |
		some tag in required
		not tags[tag]
	}
	sorted := sort(found)
}
