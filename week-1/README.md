# S3 Compliance Baseline (SC-28, AC-3, CM-6, AU-3)

I built this Terraform module to lock down an S3 bucket setup against
four compliance controls: SC-28 for encryption at rest, AC-3 for blocking
public access, CM-6 for versioning and consistent tagging, and AU-3 for
access logging. Both buckets get AES-256 encryption and all four
public-access-block flags turned on. The primary bucket has versioning
enabled, and every resource carries the same tags so nothing slips
through untracked. Access logs from the primary bucket flow into a
separate, locked-down log bucket. To prove it actually works instead of
just claiming it, the module exports the Terraform plan to JSON and ships
with a script that checks the live AWS resources against policy.

## What's enforced

| Control | Name                               | How |
|---------|-------------------------------------|-----|
| SC-28   | Protection of Information at Rest  | AES-256 encryption on both buckets |
| AC-3    | Access Enforcement                  | Public access fully blocked (all 4 flags true) on both buckets |
| CM-6    | Configuration Settings              | Versioning on the primary bucket + consistent tags across everything |
| AU-3    | Content of Audit Records            | Primary bucket's access logs ship to a dedicated, locked-down log bucket |

## Running it

```bash
terraform init
terraform validate
terraform plan
terraform apply
```

## Checking it actually worked

Two layers of proof here:

**Before deploying** — the plan gets exported to JSON so you can see exactly
what's about to be created:
```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > evidence/plan.json
```

**After deploying** — `verify.sh` hits the live AWS API and checks that
encryption, versioning, and the public access flags are actually set the
way they're supposed to be:
```bash
./verify.sh
```

## What's in here

- `main.tf` — the buckets and all four controls
- `variables.tf` — inputs (project name, environment, region)
- `outputs.tf` — bucket names/ARNs after apply
- `evidence/plan.json` — the plan output, committed as proof
- `verify.sh` — live compliance checks
