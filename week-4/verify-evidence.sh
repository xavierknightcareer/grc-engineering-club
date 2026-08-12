#!/usr/bin/env bash
# verify-evidence.sh <bundle.tar.gz>
set -euo pipefail

BUNDLE="${1:?usage: verify-evidence.sh <bundle.tar.gz>}"
SIDECAR="${BUNDLE}.sha256"
SIGBUNDLE="${BUNDLE%.tar.gz}.sig.bundle"

REPO="${EVIDENCE_REPO:-xavierknightcareer/grc-engineering-club}"
WORKFLOW="${EVIDENCE_WORKFLOW:-grc-gate-oidc.yml}"
REF="${EVIDENCE_REF:-refs/heads/main}"

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
ok()   { printf 'OK    %-13s %s\n' "$1" "$2"; }

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "no sha256 utility found"
fi

# 1. INTEGRITY
[[ -f "$BUNDLE"  ]] || fail "bundle not found: $BUNDLE"
[[ -f "$SIDECAR" ]] || fail "sidecar not found: $SIDECAR"

EXPECTED="$(awk '{print $1}' "$SIDECAR")"
ACTUAL="$(sha256 "$BUNDLE")"

if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  printf 'FAIL  integrity     sha256 mismatch\n' >&2
  printf '        expected  %s\n' "$EXPECTED" >&2
  printf '        actual    %s\n' "$ACTUAL"   >&2
  exit 1
fi
ok integrity "sha256 matches sidecar"

# 2. AUTHENTICITY + TIMELINESS
command -v cosign >/dev/null 2>&1 || fail "cosign not installed"
[[ -f "$SIGBUNDLE" ]] || fail "signature bundle not found: $SIGBUNDLE"

ISSUER="https://token.actions.githubusercontent.com"
IDENTITY="https://github.com/${REPO}/.github/workflows/${WORKFLOW}@${REF}"

if ! cosign verify-blob \
      --bundle "$SIGBUNDLE" \
      --certificate-oidc-issuer "$ISSUER" \
      --certificate-identity "$IDENTITY" \
      "$BUNDLE" >/dev/null 2>&1; then
  printf 'FAIL  authenticity  cosign verify-blob rejected the signature\n' >&2
  printf '        issuer    %s\n' "$ISSUER"   >&2
  printf '        identity  %s\n' "$IDENTITY" >&2
  exit 1
fi
ok authenticity "signed by ${WORKFLOW} on ${REPO}"
ok timeliness "rekor entry present in signature bundle"

# 3. PRESERVATION (stretch)
if [[ -n "${EVIDENCE_S3_URI:-}" ]]; then
  command -v aws >/dev/null 2>&1 || fail "aws cli not installed"

  [[ "$EVIDENCE_S3_URI" =~ ^s3://([^/]+)/(.+)$ ]] \
    || fail "EVIDENCE_S3_URI must look like s3://bucket/key"
  S3_BUCKET="${BASH_REMATCH[1]}"
  S3_KEY="${BASH_REMATCH[2]}"

  RETAIN_RAW="$(aws s3api get-object-retention \
                  --bucket "$S3_BUCKET" --key "$S3_KEY" \
                  --query 'Retention.RetainUntilDate' \
                  --output text 2>/dev/null)" \
    || fail "preservation: no Object Lock retention on that object"

  RETAIN_UTC="${RETAIN_RAW:0:19}"
  NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%S)"

  [[ "$RETAIN_UTC" > "$NOW_UTC" ]] \
    || fail "preservation: retention expired at ${RETAIN_UTC}"

  ok preservation "object locked until ${RETAIN_UTC}Z"
else
  printf 'SKIP  preservation  set EVIDENCE_S3_URI to check Object Lock\n'
fi

echo
echo "CHAIN INTACT"

