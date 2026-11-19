#!/usr/bin/env python3
"""
verify_policy.py — Lane B of Phase 0: hand-verified direct programs.

Takes a TSV of `organisation<TAB>candidate_policy_url` and records the truth: the page is
fetched, the raw body is stored, and the same fixed rules as classify.py decide the status.
A URL that 404s or that turns out to be a platform page is recorded as such — never
"assumed" to be a direct program.

Usage:
    ./verify_policy.py research/seed-candidates.tsv
    ./verify_policy.py --url https://example.com/security --domain example.com --org Example
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from classify import (  # noqa: E402
    POLICIES, DISCLOSE, REWARD, SCOPE, first_sentence, fetch, on_platform,
    parse_security_txt, classify_host,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "research", "manual-verification.tsv")


def evaluate(org, domain, url):
    d = os.path.join(POLICIES, domain)
    status, text, path, ctype = fetch(url, d, "manual-policy")

    row = {"org": org, "domain": domain, "url": url, "http": status,
           "result": "UNKNOWN", "policy_url": url, "evidence": "",
           "evidence_path": path or "", "note": "", "confidence": "LOW"}

    if status is None:
        row["note"] = "fetch error — see evidence column"
        row["evidence"] = text[:200]
        return row
    if status in (401, 403, 429, 451, 503):
        row["result"] = "UNKNOWN"
        row["note"] = f"HTTP {status} — blocked or challenged; page content is not evidence"
        row["evidence"] = f"HTTP {status} from {url}"
        return row
    if status == 202:
        row["result"] = "UNKNOWN"
        row["note"] = "HTTP 202 — anti-bot challenge page; content unreliable"
        row["evidence"] = f"HTTP 202 from {url}"
        return row
    if status >= 400:
        row["note"] = f"HTTP {status} — candidate URL is wrong or gone"
        row["evidence"] = f"HTTP {status} from {url}"
        return row

    plat = on_platform(url)
    if plat:
        row["result"] = "NO - THIRD-PARTY ONLY"
        row["evidence"] = f"policy page is hosted on {plat}"
        row["note"] = "platform program"
        return row

    # the page may itself be a security.txt
    fields = parse_security_txt(text)
    if fields.get("policy"):
        for u in fields["policy"]:
            if u.lower().startswith("http") and on_platform(u):
                row["result"] = "NO - THIRD-PARTY ONLY"
                row["evidence"] = f"Policy: {u} (platform)"
                row["policy_url"] = u
                return row

    blob = text or ""
    has_reward = bool(REWARD.search(blob))
    has_scope = bool(SCOPE.search(blob))
    has_disclosure = bool(DISCLOSE.search(blob))

    if has_reward and has_scope:
        row["result"] = "YES - DIRECT PAID BOUNTY"
        row["evidence"] = first_sentence(blob, REWARD)
    elif has_disclosure or has_scope:
        row["result"] = "YES - DIRECT VDP"
        row["evidence"] = first_sentence(blob, DISCLOSE) or first_sentence(blob, SCOPE)
    elif fields.get("contact"):
        row["result"] = "YES - DIRECT SECURITY CONTACT"
        row["evidence"] = "security.txt Contact: " + "; ".join(fields["contact"])[:200]
    elif "security@" in blob.lower() or "psirt@" in blob.lower():
        row["result"] = "YES - DIRECT SECURITY CONTACT"
        row["evidence"] = "security contact address published on page"
    else:
        # A single page without program language is not proof of absence. Fall back to the
        # organisation's own security.txt before saying anything negative.
        row["result"] = "UNKNOWN"
        row["evidence"] = "candidate page fetched, no disclosure or reward language found"
        row["note"] = "candidate URL may be the wrong page — verify by eye"
        try:
            fb = classify_host(domain)
        except Exception:
            fb = {"status": "UNKNOWN", "evidence": "security.txt lookup failed",
                  "policy_url": "NONE", "evidence_path": ""}
        if fb["status"].startswith(("YES", "NO - THIRD")):
            row["result"] = fb["status"]
            row["policy_url"] = fb["policy_url"]
            row["evidence"] = "via security.txt: " + fb["evidence"][:180]
            row["evidence_path"] = fb.get("evidence_path", "")
            row["note"] = "manual URL inconclusive; security.txt decided it"

    if not has_reward:
        row["note"] = (row["note"] + " no monetary language").strip()
    row["confidence"] = ("HIGH" if (row["result"] == "YES - DIRECT PAID BOUNTY"
                                    and has_scope and not plat)
                         else "MEDIUM" if row["result"].startswith("YES") else "LOW")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("batch", nargs="?", help="TSV: org<TAB>url[<TAB>note]")
    ap.add_argument("--url")
    ap.add_argument("--domain")
    ap.add_argument("--org", default="")
    args = ap.parse_args()

    rows = []
    if args.url:
        if not args.domain:
            print("--domain is required with --url", file=sys.stderr)
            return 2
        rows.append(evaluate(args.org or args.domain, args.domain, args.url))
    else:
        if not args.batch or not os.path.exists(args.batch):
            print("batch file not found", file=sys.stderr)
            return 2
        with open(args.batch, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("\t")]
                if len(parts) < 2:
                    continue
                org, url = parts[0], parts[1]
                domain = parts[2] if len(parts) > 2 and parts[2] else ""
                if not domain:
                    from urllib.parse import urlparse
                    from extract_domains import load_psl, registrable
                    host = (urlparse(url).hostname or "").lower()
                    rules, wild, exc, _ = load_psl()
                    domain = registrable(host, rules, wild, exc) or host
                    if domain.startswith("www."):
                        domain = domain[4:]
                print(f"[*] {org} -> {url}", flush=True)
                rows.append(evaluate(org, domain, url))
                time.sleep(0.5)

    cols = ["org", "domain", "url", "http", "result", "policy_url", "evidence",
            "evidence_path", "note", "confidence"]
    exists = os.path.exists(OUT)
    with open(OUT, "a" if exists else "w", encoding="utf-8") as fh:
        if not exists:
            fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(str(r.get(c, "")).replace("\t", " ").replace("\n", " ")
                               for c in cols) + "\n")

    for r in rows:
        print(f"    {r['result']:<32} {r['org']}  [{r['http']}]")
    print(f"[+] appended {len(rows)} rows to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
