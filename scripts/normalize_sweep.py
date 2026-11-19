#!/usr/bin/env python3
"""
normalize_sweep.py — turn every httpx JSONL in research/sweep/ into one hits.tsv.

Reads all `stxt*.jsonl` files (so a sweep split across several runs merges cleanly), pulls
the stored response body, and keeps only responses that actually contain a security.txt
field. A 200 that is a soft-404 homepage is discarded.

Usage: ./normalize_sweep.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SWEEP = os.path.join(ROOT, "research", "sweep")

FIELD = re.compile(
    r"^\s*(Contact|Policy|Expires|Encryption|Acknowledgments|Preferred-Languages|"
    r"Canonical|Hiring|CSAF)\s*:", re.I | re.M)
SEP = re.compile(r"\r?\n\r?\n")


def body_of(stored):
    if not stored or not os.path.exists(stored):
        return ""
    raw = open(stored, encoding="utf-8", errors="replace").read()
    parts = SEP.split(raw, maxsplit=2)
    return parts[2] if len(parts) == 3 else ""


def main():
    files = sorted(f for f in os.listdir(SWEEP) if f.startswith("stxt") and f.endswith(".jsonl"))
    if not files:
        print("no stxt*.jsonl files", file=sys.stderr)
        return 1
    rows, seen, total = [], set(), 0
    for name in files:
        for line in open(os.path.join(SWEEP, name), encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            host = (rec.get("input") or "").split("://")[-1].split("/")[0].lower()
            if host in seen:
                continue
            body = body_of(rec.get("stored_response_path") or "")
            if not FIELD.search(body):
                continue
            seen.add(host)
            rows.append((host, rec.get("url", ""), rec.get("status_code", 0), len(body),
                         rec.get("stored_response_path", "")))
    with open(os.path.join(SWEEP, "hits.tsv"), "w", encoding="utf-8") as fh:
        for r in sorted(rows):
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"[+] {total} 200-responses across {len(files)} file(s)")
    print(f"[+] {len(rows)} validated security.txt files -> {SWEEP}/hits.tsv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
