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
set +e
"$bin" doctor --json >"$tmp/doctor.json"
doctor_rc=$?
set -e
[ "$doctor_rc" -eq 0 ] || [ "$doctor_rc" -eq 3 ]
python3 - "$tmp/doctor.json" <<'PY'
import json, sys
doctor = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(doctor["fanotify_api_available"], bool)
assert isinstance(doctor["fanotify_api_errno"], int)
assert doctor["fanotify_api_errno"] >= 0
assert doctor["fanotify_mount_mark"] == "not_run_requires_disposable_privileged_vm"
assert doctor["config_bpf_lsm"] in {"enabled", "disabled", "unknown"}
assert isinstance(doctor["active_lsm_bpf"], bool)
assert isinstance(doctor["kernel_btf_available"], bool)
assert isinstance(doctor["bpftool_available"], bool)
assert doctor["bpf_lsm_preflight"] in {"ready", "incomplete"}
assert doctor["bpf_hook_probe"] == "not_run_no_hook_selected"
assert doctor["enforcement"] == "unsupported in this build"
PY
"$bin" status --policy "$tmp/policy.yaml" >"$tmp/status.json"
python3 - "$tmp/status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["mode"] == "audit" and status["enforced"] is False
assert status["policy_revision"] == "smoke-1"
PY
"$bin" disable --root "$tmp/guard" >"$tmp/disable.out"
"$bin" policy explain --file "$tmp/policy.yaml" --path "$tmp/guard/secret/file" --op open_for_write >"$tmp/decision.json"
python3 - "$tmp/decision.json" "$root_dir/contracts/guard-decision-v1.schema.json" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1], encoding="utf-8"))
schema = json.load(open(sys.argv[2], encoding="utf-8"))
assert decision["decision"] == "deny"
assert decision["enforced"] is False
assert decision["coverage"] == "audit_only"
assert set(schema["required"]).issubset(decision)
assert decision["coverage"] in schema["properties"]["coverage"]["enum"]
assert decision["reason_code"] == "deny-secret-write"
assert decision["actor_attribution"] == "unknown"
assert decision["errno"] is None
PY
python3 "$root_dir/tests/policy_validation.py" "$bin" \
    "$tmp/policy.yaml" "$tmp/guard" "$tmp"

quoted_root="$tmp/보호-\"-\\-"
mkdir -p "$quoted_root"
printf 'quoted path\n' >"$quoted_root/file\"name"
cat >"$tmp/quoted-policy.yaml" <<EOF
schema_version: policy.v1
policy_revision: quoted-path
mode: audit
default_action: allow
protected_roots:
  - $quoted_root
rules:
  - id: quoted-path-rule
    scope: $quoted_root
    operation: open_for_read
    action: allow
    subject: any
EOF
"$bin" policy explain --file "$tmp/quoted-policy.yaml" \
    --path "$quoted_root/file\"name" --op open_for_read >"$tmp/quoted-decision.json"
python3 - "$tmp/quoted-decision.json" "$quoted_root/file\"name" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1], encoding="utf-8"))
assert decision["scope_identity"]["path"] == sys.argv[2]
assert decision["decision"] == "allow"
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
