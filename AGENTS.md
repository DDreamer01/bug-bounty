# AGENTS.md — Bug Bounty Sprint Operating Contract

This repository is an authorised security-research workspace. Every agent working here
operates under this contract. It overrides convenience, speed and curiosity.

---

## Mission

Find, validate and responsibly report genuine security vulnerabilities to organisations
that publish an official channel authorising external reports. Ten-day sprint, quality
over volume.

---

## Hard rules

1. **Authorisation precedes action.** No *testing* request is sent to a host that is not in
   `targets/approved-targets.txt`. Run `scripts/scope_gate.py <host>` first, every time,
   including redirects.
   - *Discovery traffic is not testing.* Fetching `/.well-known/security.txt`,
     `/security.txt`, or a policy page an organisation publishes for researchers is Phase 0
     research. It is limited to those documented paths, sends no payload, and never
     authenticates. Everything else — parameters, paths, methods, payloads — requires the
     gate.
2. **Read the scope, not the vibe.** Excluded assets are excluded even when adjacent and
   interesting. A wildcard does not override an explicit exclusion.
3. **Never use credentials you did not create.** Only accounts and sessions you registered
   yourself. No third-party credential material, ever.
4. **Never touch real users' data beyond a single proof.** One record demonstrates the
   flaw. Continuing to enumerate converts a valid report into an incident.
5. **Non-destructive by default.** No `DROP`/`DELETE`/`UPDATE`, no load testing, no
   enumeration loops, no resource-exhaustion tests, no live webshells, no persistence.
6. **Evidence is write-once.** Capture raw request/response before analysis. Redact by
   replacement, never by deleting the original. Do not edit a stored capture — store a
   second, annotated copy.
7. **Never fabricate.** No invented endpoints, status codes, timings, versions, quotes or
   screenshots. If a fetch failed, record the failure. `UNKNOWN` is a valid, expected answer.
8. **Never inflate severity.** Score what you demonstrated. Downgrade when in doubt.
9. **Nothing is submitted without human approval.** Reports go to `reports/` and wait.
   The operator submits, or explicitly instructs submission.
10. **No public disclosure, no pressure tactics, no third-party contact** about a target
    outside its published channel.

---

## Directory map

```
programs/     programs.txt (working)  programs-original.txt (immutable backup)
              PROVENANCE.md (what the source data is)  phase0-report.md
targets/      approved-targets.txt (the ONLY allowlist)  scope.json  target-NNN/
research/     notes, policies, candidate lists, duplicates, evidence/
evidence/     raw captures, organised per target and finding
reports/      draft and final reports
logs/         daily-log.md, scope-decisions.log, command history
scripts/      scope_gate.py, sweep, classify, capture helpers
wordlists/    curated wordlists only, no blind brute force
```

---

## Phase gates

| Gate | Requirement |
|---|---|
| G0 Discovery → shortlist | Policy fetched, body stored, verbatim quote, classification applied |
| G1 Shortlist → testing | Target in `approved-targets.txt`, scope parsed, operator approved |
| G2 Lead → finding | Reproduced twice, root cause identified, impact demonstrated |
| G3 Finding → report | Scope re-verified, duplicates checked, evidence complete, CVSS defensible |
| G4 Report → submitted | Operator sign-off, official channel only |

An agent may not skip a gate. If a gate cannot be satisfied, the work stops and the blocker
is written into `logs/daily-log.md`.

---

## Classification vocabulary (exact strings)

```
YES - DIRECT PAID BOUNTY
YES - DIRECT VDP
YES - DIRECT SECURITY CONTACT
NO - THIRD-PARTY ONLY
NO - NO PROGRAM FOUND
UNKNOWN
```

A `security.txt` is not a bounty. An email address is not a scope. Reward language without
a scope is not a paid program.

---

## Working style

- Hypothesis first: `component trusts <input> for <decision>, so attacker can <impact>`
- One target at a time, one folder per target, one subfolder per finding
- Two-account testing with accounts you created; diff the responses field by field
- Rate limit ~2 req/s per host unless the policy says otherwise
- Prefer manual, targeted requests over scanners on production
- Explain findings in plain language, including *why* the flaw exists
- Log every significant action with timestamp and rationale

---

## Daily log format

Append to `logs/daily-log.md` at the end of each session:

```markdown
## Day N — YYYY-MM-DD

Targets investigated: …
Authorisation status: …
Commands/tools used: …
Observations: …
Candidate vulnerabilities: …
Confirmed findings: …
False positives / rejected leads: …
Reports prepared: …
Reports submitted: …
Blockers: …
Next day priorities: …
```

---

## Tooling available

`subfinder httpx nuclei ffuf nmap amass gau waybackurls python3 go node jq browser-use`
Missing but installable: `sqlmap dnsx katana gf anew`. No Burp (headless host).

Tools serve questions. If you cannot state the question a tool answers, do not run it.

---

## Failure modes to avoid

| Symptom | Correction |
|---|---|
| Scanner output treated as findings | Reproduce manually, then decide |
| "Probably vulnerable" in a report | Remove it, or test it |
| 200 responses assumed to be exposure | Check whose data it actually is |
| Scope assumed from a wildcard | Read the exclusions |
| Severity set by enthusiasm | Set by demonstrated impact |
| Target list built from guesswork | Build from published authorisation only |
