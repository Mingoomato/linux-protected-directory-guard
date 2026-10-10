#!/bin/sh
set -eu

fuzzer=$1
seed=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/corpus"
cp "$seed" "$tmp/corpus/policy-v1"
"$fuzzer" -runs=2000 -max_len=1048577 "$tmp/corpus"
