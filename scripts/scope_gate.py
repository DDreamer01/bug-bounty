#!/usr/bin/env python3
"""
scope_gate.py — the only thing standing between curiosity and an unauthorised request.

Usage:
    ./scope_gate.py https://app.example.com/some/path --reason "authz matrix"
    ./scope_gate.py app.example.com
    ./scope_gate.py --list

Exit codes: 0 = ALLOW, 1 = DENY, 2 = configuration error.

Allowlist:  targets/approved-targets.txt
  one pattern per line, optional " | name" suffix, "#" starts a comment
    example.com            exact host only
    *.example.com          any subdomain, NOT the apex
    .example.com           apex + any subdomain

Exclusions: targets/scope.json
  {"targets": [{"host": "example.com", "program": "X",
                "include": ["*.example.com"],
                "exclude": ["status.example.com", "*.internal.example.com"]}]}

Every decision is appended to logs/scope-decisions.log. No decision, no request.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST = os.path.join(ROOT, "targets", "approved-targets.txt")
SCOPEJSON = os.path.join(ROOT, "targets", "scope.json")
LOGFILE = os.path.join(ROOT, "logs", "scope-decisions.log")


def host_from(target: str) -> str:
    """Extract a bare lowercase hostname from a URL or host string."""
    t = target.strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):  # ipv6 literal
        t = t[1 : t.find("]")] if "]" in t else t
    elif t.count(":") == 1:
        t = t.split(":")[0]
    return t.rstrip(".").lower()


def matches(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and host != base
    if pattern.startswith("*"):
        # suffix wildcard: "*-rest.example.io" matches "foo-rest.example.io"
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    if pattern.startswith("."):
        base = pattern[1:]
        return host == base or host.endswith("." + base)
    return host == pattern


def load_allowlist():
    entries = []
    if not os.path.exists(ALLOWLIST):
        return entries
    with open(ALLOWLIST, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "|" in line:
                pattern, name = [p.strip() for p in line.split("|", 1)]
            else:
                pattern, name = line, ""
            if pattern:
                entries.append((pattern, name))
    return entries


def load_scope():
    if not os.path.exists(SCOPEJSON):
        return {"targets": []}
    try:
        with open(SCOPEJSON, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("targets"), list):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {"targets": []}


def log(decision: str, host: str, reason: str, detail: str) -> None:
    os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{stamp}\t{decision}\t{host}\t{detail}\t{reason}\n"
    with open(LOGFILE, "a", encoding="utf-8") as fh:
        fh.write(line)


def decide(host: str, reason: str):
    allow = load_allowlist()
    if not allow:
        log("DENY", host, reason, "empty-allowlist")
        return False, "approved-targets.txt is empty — nothing is authorised"

    hit = None
    for pattern, name in allow:
        if matches(host, pattern):
            hit = (pattern, name)
            break
    if not hit:
        log("DENY", host, reason, "not-in-allowlist")
        return False, f"{host} is not in approved-targets.txt"

    scope = load_scope()
    for entry in scope.get("targets", []):
        base = (entry.get("host") or "").lower()
        includes = entry.get("include") or []
        covers = matches(host, base) or any(matches(host, p) for p in includes)
        if not covers:
            continue
        for exc in entry.get("exclude") or []:
            if matches(host, exc):
                log("DENY", host, reason, f"excluded-by:{exc}")
                return False, f"{host} matches exclusion '{exc}' in scope.json"
        log("ALLOW", host, reason, f"pattern:{hit[0]}|program:{entry.get('program', '')}")
        return True, f"covered by '{hit[0]}'" + (f" ({hit[1]})" if hit[1] else "")

    log("ALLOW", host, reason, f"pattern:{hit[0]}|program:{hit[1] or 'unset'}")
    return True, f"covered by '{hit[0]}'" + (f" ({hit[1]})" if hit[1] else "")


def main() -> int:
    args = [a for a in sys.argv[1:]]
    reason = ""
    if "--reason" in args:
        i = args.index("--reason")
        reason = args[i + 1] if i + 1 < len(args) else ""
        del args[i : i + 2]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    if args[0] == "--list":
        entries = load_allowlist()
        if not entries:
            print("(empty)")
        for pattern, name in entries:
            print(f"{pattern:<40} {name}")
        return 0

    host = host_from(args[0])
    if not host:
        print("DENY — could not parse a hostname from the input")
        return 2

    allowed, detail = decide(host, reason or "unspecified")
    if allowed:
        print(f"ALLOW  {host}  — {detail}")
        return 0
    print(f"DENY   {host}  — {detail}")
    print("       Do not send the request. Get authorisation into approved-targets.txt first.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
