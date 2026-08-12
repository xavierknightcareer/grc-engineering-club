# GRC Engineering Project

A compliance pipeline built as infrastructure: controls defined in Terraform,
expressed as executable policy, enforced in CI, and signed so the results can be
validated by a third party.

Each stage builds on the previous one. The through-line is that every claim the
pipeline makes should be verifiable by someone with no access to this repository
or the underlying AWS account.

## Status

| Stage | Focus | State |
|-------|-------|-------|
| 1 | S3 control baseline in Terraform | Complete |
| 2 | Controls as executable policy (Rego) | Complete |
| 3 | Policy gate in CI, keyless AWS auth | Complete |
| 4 | Signed evidence and chain of custody | Complete |
| 5 | Detective controls: CloudTrail, Security Hub | Not started |
| 6 | OSCAL control mapping and evidence traversal | Not started |

## Architecture

```
week-1/    Terraform defining the controlled resources
             ↓ terraform show -json
week-2/    Rego policies evaluating the plan against NIST families
             ↓ conftest
week-3/    GitHub Actions gate; blocks non-compliant PRs
             ↓ evidence/
week-4/    Cosign keyless signing + S3 Object Lock vault
             ↓ verify-evidence.sh
           CHAIN INTACT
```

Two workflows run on every pull request. `grc-gate` evaluates a committed plan
and is deterministic. `grc-gate-oidc` assumes an AWS role via OIDC, generates the
plan against live account state, and signs the result. Both are required checks
on `main`.

---

## 1. Control baseline

Two S3 buckets — a primary and a dedicated log bucket — with four controls
implemented in Terraform.

| Control | Name | Implementation |
|---------|------|----------------|
| SC-28 | Protection of Information at Rest | AES-256 on both buckets |
| AC-3 | Access Enforcement | All four public access block flags on both buckets |
| CM-6 | Configuration Settings | Versioning on primary; provider-level `default_tags` applied to every taggable resource |
| AU-3 | Content of Audit Records | Primary bucket access logs delivered to the log bucket |

Tagging is enforced through a provider `default_tags` block rather than
per-resource, so a new resource cannot be added untagged.

The module exports the plan to JSON for policy evaluation, and `verify.sh`
queries the live AWS API after apply to confirm encryption, versioning, and the
public access flags match the declared state.

```bash
cd week-1
terraform init && terraform plan -out=tfplan
terraform show -json tfplan > evidence/plan.json
./verify.sh
```

## 2. Controls as executable policy

Three Rego policies assert the same controls independently of the Terraform that
declares them, so drift between intent and implementation fails the build rather
than passing silently.

| Namespace | Control |
|-----------|---------|
| `compliance.sc28_aws` | Encryption configuration present on both buckets |
| `compliance.ac3_aws` | All four public access block flags true |
| `compliance.cm6_aws` | Required tags present on every resource |

Each policy has a companion test file. The suite is six tests: three confirming a
compliant plan produces no denial, three confirming a non-compliant plan is
rejected.

**Matching at plan time.** Bucket names include a `random_id` suffix that does
not exist until apply, so policies cannot match resources by value. They match by
reference instead — `input.configuration.root_module.resources[].expressions.<arg>.references`
holds strings like `aws_s3_bucket.primary.id`. Flag and tag values are read from
`planned_values`. This is what makes the policies effective as a pre-merge gate
rather than a post-deployment audit.

```bash
opa test week-2/policies/ -v
conftest test --policy week-2/policies --all-namespaces plan.json
```

## 3. Enforcement in CI

Both workflows run `conftest` against the plan and block the pull request on any
violation. `main` is protected by a ruleset requiring a pull request and both
checks passing; direct pushes are rejected.

Enforcement was demonstrated with a matched pair of pull requests. A compliant
plan passes the gate and is mergeable. A plan with a control removed fails, and
the required check makes the merge genuinely impossible rather than merely
discouraged. Both runs produce an evidence artifact, since the upload step runs
under `if: always()`.

**No stored cloud credentials.** The baseline approach commits `plan.json` and
evaluates it. `grc-gate-oidc` replaces that with a plan generated in CI:
the workflow authenticates to AWS through GitHub's OIDC provider, the runner
presents a short-lived token, AWS validates it against the role's trust policy,
and returns temporary credentials. The role is read-only — it can plan but not
apply. Both workflows are retained: the committed-plan gate is deterministic and
fast, the OIDC gate evaluates live account state.

One implementation note that cost real time: GitHub emits an **ID-augmented
subject claim** — `repo:owner@<owner_id>/<repo>@<repo_id>:*` — not the
`repo:owner/name:*` form shown in most documentation. A trust policy written
against the documented form fails with `Not authorized to perform
sts:AssumeRoleWithWebIdentity` and no indication of which condition did not
match. Inspecting the raw token claims from within the runner is the fastest way
to resolve it.

Conftest and Terraform are pinned to explicit versions in both workflows, so a
gate result is reproducible against the toolchain that produced it.

## 4. Signed evidence and chain of custody

Evidence produced as a CI artifact can be read but not independently attributed.
Each run now bundles `evidence/`, writes a SHA-256 sidecar, and signs the bundle
with Cosign keyless. `week-4/verify-evidence.sh` checks four properties and
prints `CHAIN INTACT` only if all pass.

| Property | Question | Artifact |
|----------|----------|----------|
| Authenticity | Who produced this? | Sigstore certificate binding the signature to `grc-gate-oidc.yml` on this repo |
| Integrity | Has it changed since? | SHA-256 sidecar, recomputed at verification |
| Timeliness | When was it produced? | Rekor transparency log entry in the signature bundle |
| Preservation | Can it still be retrieved, unaltered? | S3 Object Lock retention on the vault object |

### Keyless signing

A stored private key relocates the trust question rather than resolving it: the
reviewer must then assess key custody, rotation, and exposure history.

Cosign keyless substitutes identity for a key. The workflow presents its OIDC
token, Sigstore issues a short-lived certificate, signs, and records the event in
a public transparency log. The certificate encodes the repository and workflow
that produced the signature.

The resulting attestation does not reside in the AWS account. A principal holding
`AdministratorAccess` cannot forge it, because the record lives in Rekor. Signing
in CI rather than locally also keeps individual engineer identities out of a
permanent public log, and the attestation remains valid after personnel changes.

### Signing precedes enforcement

The gate originally exited non-zero on the first violation, so failed runs
produced no signed evidence. Failed control tests are the records most likely to
be requested during an audit.

The gate now writes its violation count to `GITHUB_ENV` and returns cleanly.
Signing and upload run under `if: always()`. A terminal `Enforce policy gate`
step reads the count and determines job status. Enforcement fails closed: an
unset count exits non-zero rather than being treated as zero violations.

```
✓ Run policy gate            writes POLICY_FAILURES
✓ Install cosign
✓ Bundle, hash, and sign     if: always()
✓ Upload signed evidence     if: always()
✗ Enforce policy gate        exits 1 on violations
```

### Verification results

Appending one byte to a bundle:

```
FAIL  integrity     sha256 mismatch
        expected  6cb5a13fa263d070bb24fa94ef7d320d34f19200a28d87e32628e665974ad072
        actual    d54b342c863a45fd9b4771b9df89cb470e66ddc6ec18ba3c9246588381317df6
```

The digests differ across the full output rather than at the point of
modification, so there is no partial match to adjudicate.

A `workflow_dispatch` run on `main`, verified against the vault:

```
OK    integrity     sha256 matches sidecar
OK    authenticity  signed by grc-gate-oidc.yml on xavierknightcareer/grc-engineering-club
OK    timeliness    rekor entry present in signature bundle
OK    preservation  object locked until 2026-08-13T15:09:16Z

CHAIN INTACT
```

A pull request removing the primary bucket's encryption configuration triggers
SC-28. The job fails; evidence is signed and uploaded regardless. That bundle
verifies `CHAIN INTACT`, and the violation extracted from it:

```json
["bucket primary has no encryption configuration"]
```

A named violation, attributable to a specific workflow run, with integrity
verifiable independently of the party presenting it.

### The vault

`week-4/vault/main.tf` provisions an S3 bucket with Object Lock and versioning
enabled, plus an IAM policy granting the pipeline role `s3:PutObject` scoped to
that bucket. No delete, no `BypassGovernanceRetention`. A compromised workflow
can append evidence but cannot alter or remove existing objects.

**Object Lock is enabled only at bucket creation.** It cannot be applied
retroactively, which is why this is a separate bucket rather than a modification
to the stage 1 build.

**Versioning makes writes non-destructive.** Uploading a modified file over an
existing key succeeds and creates a new version; the original remains locked and
is still the object the signature and sidecar reference. Deletion of the original
is refused:

```
An error occurred (AccessDenied) when calling the DeleteObject operation:
Access Denied because object protected by object lock.
```

Executed under `AdministratorAccess`. Object Lock is enforced independently of
IAM, so no permission grant would have permitted the operation.

---

## Planned

**5. Detective controls.** Multi-region CloudTrail with log file validation
writing to an encrypted bucket (AU-2, AU-12, AU-10), and Security Hub subscribed
to the NIST 800-53 Rev 5 standard (RA-5, SI-4). Captured findings are signed by
the stage 4 pipeline so monitoring output joins the same chain of custody as the
gate results.

**6. OSCAL control mapping.** A component definition with one
`implemented-requirement` per satisfied control, each carrying a `rel: evidence`
link to a signed bundle, plus a profile selecting those control IDs from the NIST
catalog. The objective is traversal: an assessor reads the control statement,
follows the evidence link, runs `verify-evidence.sh`, and confirms the claim
without contacting anyone.

---

## Known gaps

| Gap | Production approach |
|-----|--------------------|
| GOVERNANCE retention, 1 day | COMPLIANCE mode, retention matched to the audit cycle |
| Vault upload performed manually post-run | Workflow uploads directly using the existing write-only policy |
| GitHub Actions referenced by floating major tags | Pin to commit SHAs; unpinned dependencies weaken the attestation |
| Verifier defaults to `refs/heads/main` | PR-triggered runs require `EVIDENCE_REF`; resolve the ref automatically |
| Three controls in policy, four in Terraform | AU-3 is declared but not independently asserted in Rego |

## Verification

```bash
./week-4/verify-evidence.sh evidence.tar.gz
```

Expects `evidence.tar.gz.sha256` and `evidence.sig.bundle` alongside the bundle.

| Variable | Purpose |
|----------|---------|
| `EVIDENCE_REF` | Certificate ref. Default `refs/heads/main`; `refs/pull/N/merge` for PR runs |
| `EVIDENCE_S3_URI` | `s3://bucket/key` — enables the preservation check |
| `EVIDENCE_REPO` | Override repository in the expected identity |
| `EVIDENCE_WORKFLOW` | Override workflow filename in the expected identity |

## Repository layout

```
.github/workflows/
  grc-gate.yml            deterministic gate, committed plan
  grc-gate-oidc.yml       live plan via OIDC, signs evidence
week-1/                   Terraform baseline, verify.sh, committed plan
week-2/policies/          Rego policies and their tests
week-3/                   gate artifacts
week-4/
  verify-evidence.sh      four-property verifier
  vault/                  Object Lock bucket and scoped IAM policy
```

Evidence directories are produced in CI and are not committed. Artifacts are
attached to their workflow runs.

## Requirements

Terraform 1.9+, OPA, Conftest 0.69+, Cosign 3.x, AWS CLI v2.

Sigstore signing and verification are free and require no cloud account. The
vault is the only billable component; it was provisioned, used, verified, and
destroyed the same day.

