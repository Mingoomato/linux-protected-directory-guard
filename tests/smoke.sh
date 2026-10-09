#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${BIN_DIR:-"$root_dir/build"}
bin="$bin_dir/dirguardctl"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/guard/secret"
printf 'guarded\n' >"$tmp/guard/secret/file"
cat >"$tmp/policy.yaml" <<EOF
schema_version: policy.v1
policy_revision: smoke-1
mode: audit
default_action: allow
protected_roots:
  - $tmp/guard
rules:
  - id: deny-secret-write
    scope: $tmp/guard/secret
    operation: open_for_write
    action: deny
    subject: any
EOF

"$bin" policy validate --file "$tmp/policy.yaml"
"$bin" policy explain --file "$tmp/policy.yaml" --path "$tmp/guard/secret/file" --op open_for_write >"$tmp/decision.json"
python3 - "$tmp/decision.json" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1], encoding="utf-8"))
assert decision["decision"] == "deny"
assert decision["enforced"] is False
assert decision["coverage"] == "audit_only"
PY
set +e
"$bin" enforce --root "$tmp/guard" --policy "$tmp/policy.yaml" --confirm-lab-scope >"$tmp/enforce.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
python3 - "$tmp/enforce.out" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["error"] == "PDG_UNSUPPORTED_ENFORCEMENT"
assert result["enforced"] is False
PY

echo "PDG policy smoke: PASS (audit only)"
