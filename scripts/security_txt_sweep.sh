#!/usr/bin/env bash
# security_txt_sweep.sh — Phase 0 Stage 3
#
# Fetches exactly two published files per domain: /.well-known/security.txt and
# /security.txt. No crawling, no brute forcing, no payloads. A security.txt exists to be
# read by researchers; fetching it is normal web traffic.
#
# Usage: ./security_txt_sweep.sh research/candidates-domains.txt
# Output: research/sweep/{stxt.jsonl, hits.tsv, bodies/<domain>.txt}
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${1:?usage: security_txt_sweep.sh <domains.txt>}"
OUT="$ROOT/research/sweep"
RATE="${RATE:-40}"
THREADS="${THREADS:-20}"
TIMEOUT="${TIMEOUT:-10}"
RETRIES="${RETRIES:-1}"
UA="authorized-security-research/1.0 (+vulnerability-disclosure-policy-review)"

mkdir -p "$OUT/bodies"
: > "$OUT/hits.tsv"
: > "$OUT/stxt.jsonl"

echo "[+] input: $(wc -l < "$INPUT") domains"
echo "[+] rate:  ${RATE} req/s"

# ---- pass 1: RFC 9116 canonical location -------------------------------------
echo "[+] pass 1: /.well-known/security.txt"
httpx -l "$INPUT" \
  -path "/.well-known/security.txt" \
  -mc 200 -fr -silent -json -nc \
  -H "User-Agent: $UA" \
  -rate-limit "$RATE" -threads "$THREADS" -timeout "$TIMEOUT" -retries "$RETRIES" \
  -store-response -srd "$OUT/bodies" \
  -o "$OUT/stxt.jsonl" || true

# ---- pass 2: legacy location, only for domains that missed pass 1 ------------
echo "[+] pass 2: /security.txt (misses only)"
python3 - "$OUT/stxt.jsonl" "$INPUT" "$OUT/.remaining.tmp" <<'PY'
import json, sys
hits, inp, outp = sys.argv[1], sys.argv[2], sys.argv[3]
seen = set()
for line in open(hits, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        seen.add(json.loads(line).get("input", "").lower())
    except json.JSONDecodeError:
        pass
with open(outp, "w", encoding="utf-8") as fh:
    for line in open(inp, encoding="utf-8", errors="replace"):
        d = line.strip().lower()
        if d and d not in seen:
            fh.write(d + "\n")
print(f"    {len(seen)} hits, {sum(1 for _ in open(outp))} remaining")
PY

httpx -l "$OUT/.remaining.tmp" \
  -path "/security.txt" \
  -mc 200 -fr -silent -json -nc \
  -H "User-Agent: $UA" \
  -rate-limit "$RATE" -threads "$THREADS" -timeout "$TIMEOUT" -retries "$RETRIES" \
  -store-response -srd "$OUT/bodies" \
  -o "$OUT/stxt-legacy.jsonl" || true

# ---- normalise: keep only bodies that actually look like security.txt --------
echo "[+] normalising"
python3 - "$OUT" <<'PY'
import json, os, re, sys
out = sys.argv[1]
field = re.compile(r"^\s*(Contact|Policy|Expires|Encryption|Acknowledgments|Preferred-Languages|Canonical|Hiring|CSAF)\s*:", re.I | re.M)
sep = re.compile(r"\r?\n\r?\n")
rows = []
for name in ("stxt.jsonl", "stxt-legacy.jsonl"):
    path = os.path.join(out, name)
    if not os.path.exists(path):
        continue
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (rec.get("input") or "").split("://")[-1].split("/")[0].lower()
        stored = rec.get("stored_response_path") or ""
        body = ""
        if stored and os.path.exists(stored):
            raw = open(stored, encoding="utf-8", errors="replace").read()
            parts = sep.split(raw, maxsplit=2)
            body = parts[2] if len(parts) == 3 else ""
        if not field.search(body):
            continue
        rows.append((host, rec.get("url", ""), rec.get("status_code", 0), len(body), stored))
with open(os.path.join(out, "hits.tsv"), "w", encoding="utf-8") as fh:
    for r in sorted(set(rows)):
        fh.write("\t".join(str(x) for x in r) + "\n")
print(f"    {len(set(rows))} validated security.txt files")
PY

echo "[+] done -> $OUT/hits.tsv"
