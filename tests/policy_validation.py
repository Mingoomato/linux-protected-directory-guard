#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
base_path = pathlib.Path(sys.argv[2])
lab_root = pathlib.Path(sys.argv[3])
work = pathlib.Path(sys.argv[4])
base = base_path.read_text(encoding="utf-8")

def validate(name, text):
    path = work / f"policy-{name}.yaml"
    path.write_text(text, encoding="utf-8")
    return subprocess.run([
        str(binary), "policy", "validate", "--file", str(path),
    ], capture_output=True, text=True)

def rejected(name, text):
    result = validate(name, text)
    assert result.returncode != 0, (name, result.stdout, result.stderr)

rejected("duplicate-top-field", base.replace(
    "mode: audit\n", "mode: audit\nmode: audit\n", 1))
rejected("duplicate-rule-field", base.replace(
    "    action: deny\n", "    action: deny\n    action: allow\n", 1))
rejected("duplicate-rule-id", base + (
    f"  - id: deny-secret-write\n"
    f"    scope: {lab_root}\n"
    "    operation: open_for_read\n"
    "    action: allow\n"
    "    subject: any\n"))
rejected("overlong-line", base + "#" * 4097 + "\n")
rejected("cumulative-size", base + ("#" + "x" * 3999 + "\n") * 263)
rejected("unknown-field", base.replace(
    "policy_revision: smoke-1\n", "policy_revision: smoke-1\nunknown_key: value\n", 1))
rejected("broad-canonical-root", base.replace(
    str(lab_root), str(lab_root / "../../.."), 1))
rejected("overlapping-conflicting-actions", base + (
    f"  - id: allow-parent-writes\n"
    f"    scope: {lab_root}\n"
    "    operation: open_for_write\n"
    "    action: allow\n"
    "    subject: any\n"))

duplicate_root = base.replace(
    "protected_roots:\n", f"protected_roots:\n  - {lab_root}\n", 1)
rejected("duplicate-root", duplicate_root)

specificity = base + (
    f"  - id: deny-parent-writes\n"
    f"    scope: {lab_root}\n"
    "    operation: open_for_write\n"
    "    action: deny\n"
    "    subject: any\n")
specific_path = work / "policy-specificity.yaml"
specific_path.write_text(specificity, encoding="utf-8")
decision = subprocess.run([
    str(binary), "policy", "explain", "--file", str(specific_path),
    "--path", str(lab_root / "secret/file"), "--op", "open_for_write",
], check=True, capture_output=True, text=True)
assert json.loads(decision.stdout)["reason_code"] == "deny-secret-write"

print("PDG policy validation smoke: PASS")
