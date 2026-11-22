#!/usr/bin/env bash
# Fetch pinned upstream Solidity sources (public code, read-only) for fork-diff.
# Idempotent: skips entries already at the pinned commit. Output: corpus/upstream/<name>/
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=corpus/upstream; mkdir -p "$OUT"
python3 - "$OUT" <<'PY'
import json, subprocess, sys, os
out = sys.argv[1]
for e in json.load(open("auditor/data/upstream_corpus.json"))["entries"]:
    d = os.path.join(out, e["name"])
    pin = os.path.join(d, ".pinned_commit")
    if os.path.exists(pin) and open(pin).read().strip() == e["commit"]:
        print("ok", e["name"]); continue
    os.makedirs(d, exist_ok=True)
    run = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
    if not os.path.isdir(os.path.join(d, ".git")):
        run("init", "-q"); run("remote", "add", "origin", e["repo"])
    run("config", "core.sparseCheckout", "true")
    open(os.path.join(d, ".git", "info", "sparse-checkout"), "w").write("\n".join(p + "/" for p in e["paths"]) + "\n")
    run("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", e["commit"])
    run("checkout", "-q", "FETCH_HEAD")
    head = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert head == e["commit"], (e["name"], head)
    open(pin, "w").write(head)
    print("fetched", e["name"], head[:10])
PY
