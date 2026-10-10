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

# Exercise the CLI's static out-of-root rejection across a fixed 100-path set.
# This is not a substitute for live fanotify filtering or workload testing.
outside_paths = [work / "guard-sibling" / "file"]
outside_paths.extend(work / f"outside-{i}" / "file" for i in range(99))
for path in outside_paths:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("outside protected scope\n", encoding="utf-8")
    result = subprocess.run([
        str(binary), "policy", "explain", "--file", str(specific_path),
        "--path", str(path), "--op", "open_for_write",
    ], capture_output=True, text=True)
    assert result.returncode == 2, (path, result.returncode, result.stdout, result.stderr)
    assert result.stdout == "", (path, result.stdout)
    assert "outside protected roots" in result.stderr, (path, result.stderr)

for invalid_duration in ("abc", "-1", "12s", "999999999999999999999999"):
    result = subprocess.run([
        str(binary), "audit", "--root", str(lab_root), "--policy", str(base_path),
        "--events", str(work / "must-not-open.ndjson"), "--duration", invalid_duration,
    ], capture_output=True, text=True)
    assert result.returncode == 2, (invalid_duration, result.returncode, result.stdout, result.stderr)
    assert "PDG_INVALID_ARGUMENT" in result.stderr, (invalid_duration, result.stderr)

print("PDG policy validation smoke: PASS")
