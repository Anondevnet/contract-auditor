#!/usr/bin/env python3
"""Regenerate auditor/data/library_hashes.json from OpenZeppelin npm releases (Phase 19).

Developer tool, run manually. Downloads the public npm tarballs (HTTP GET,
no key) into a temporary directory, hashes every contract block with
``auditor.library_code`` normalization, and writes the manifest.

    python3 scripts/build_library_manifest.py 4.9.6 5.0.2 5.1.0 ...
"""
import json
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.library_code import MANIFEST_PATH, build_manifest_entries  # noqa: E402

URL = "https://registry.npmjs.org/@openzeppelin/contracts/-/contracts-{v}.tgz"


def main(versions):
    blocks, files, names = {}, {}, set()
    with tempfile.TemporaryDirectory() as tmp:
        for v in versions:
            tgz = Path(tmp) / f"oz-{v}.tgz"
            with urllib.request.urlopen(URL.format(v=v), timeout=60) as r:  # noqa: S310 - fixed https host
                tgz.write_bytes(r.read())
            dest = Path(tmp) / v
            with tarfile.open(tgz) as t:
                t.extractall(dest, filter="data")
            n = build_manifest_entries(dest / "package", "openzeppelin", v, blocks, files, names)
            print(f"{v}: {n} blocks")
    # Only implementation-bearing blocks are useful for suppression; interfaces are kept for names.
    out = {"version": 1, "source": "npm @openzeppelin/contracts", "versions": list(versions),
           "normalization": "comments removed, whitespace collapsed, sha256 truncated to 24 hex",
           "names": sorted(names), "blocks": {k: v for k, v in sorted(blocks.items())}}
    MANIFEST_PATH.write_text(json.dumps(out, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST_PATH} ({MANIFEST_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main(sys.argv[1:] or ["4.8.3", "4.9.6", "5.0.2", "5.1.0", "5.2.0", "5.3.0", "5.4.0"])
