# Bug Bounty Program Research

A reproducible, public-source pipeline for finding organisations that publish their own
security-disclosure or bug-bounty policy, plus the classified results it produced.

The point of this repository is not a giant list of targets. It is a **method with an evidence
trail**: every row in the output points at a page the organisation published, and every
classification is backed by a verbatim quote.

> A published policy is not blanket permission. Read each page, respect its eligible-asset
> list, and stay inside its exclusions.

---

## Contents

| Path | What it is |
|---|---|
| [`program-list.md`](program-list.md) | Direct paid programmes and direct VDPs, de-duplicated, with policy links and quotes |
| [`methodology.md`](methodology.md) | How the data was collected, classified and checked |
| [`data/classification.tsv`](data/classification.tsv) | Full classified result set (4,424 rows) |
| [`AGENTS.md`](AGENTS.md) | Operating rules and phase gates |
| [`skills/`](skills/) | Five purpose-specific research skills |
| [`scripts/`](scripts/) | The pipeline, runnable on its own inputs |
| [`examples/`](examples/) | Example allowlist and scope files for the gate |

## Results at a glance

| Classification | Organisations |
|---|---:|
| Direct paid programme | 133 |
| Direct VDP | 1,124 |
| Direct security contact only | 2,411 |
| Third-party platform only | 555 |
| No programme found | 5 |
| Unknown / fetch blocked | 242 |
| **Total researched** | **4,470** |

After de-duplicating by policy host (one programme can span many domains) the list contains
**73 distinct paid programmes** and **597 distinct VDPs**.

## Using the list

1. Open the policy URL in `program-list.md`.
2. Confirm the programme is still open and read the current scope.
3. Copy the eligible assets into your own allowlist — never widen it from a wildcard alone.
4. Only then send a testing request.

`program-list.md` is generated, not hand-edited:

```bash
python3 scripts/build_program_list.py
```

## The scope gate

`scripts/scope_gate.py` is a two-lock authorisation check. A host must match the allowlist
**and** survive the exclusions in the scope file:

```bash
cp examples/approved-targets.example.txt targets/approved-targets.txt
cp examples/scope.example.json targets/scope.json

python3 scripts/scope_gate.py app.example.com --reason "authz matrix"
# ALLOW  app.example.com  — covered by '*.example.com'
# DENY   status.example.com  — matches exclusion 'status.example.com'
```

Every decision is written to `logs/scope-decisions.log`. Exit codes: `0` allow, `1` deny,
`2` configuration error.

Supported patterns:

| Pattern | Matches |
|---|---|
| `example.com` | exact host |
| `*.example.com` | subdomains only, not the apex |
| `.example.com` | apex and every subdomain |
| `*-rest.example.io` | any host ending in `-rest.example.io` |

An include in the scope file never grants access by itself. The allowlist is the only grant.

## Re-running the discovery pipeline

Requirements: `python3`, `requests`, and [httpx](https://github.com/projectdiscovery/httpx).

```bash
# 1. Fetch /.well-known/security.txt and /security.txt for a host list
RATE=100 THREADS=150 TIMEOUT=6 RETRIES=0 \
  bash scripts/security_txt_sweep.sh hosts.txt

# 2. Keep only responses that contain real security.txt fields
python3 scripts/normalize_sweep.py

# 3. Fetch each Policy: page and classify it; evidence is stored to disk
python3 scripts/classify.py --workers 30

# 4. Render the readable list
python3 scripts/build_program_list.py
```

`classify.py` caches every fetched page next to its result, so re-classifying after a rule
change is fast and never needs a second request.

## Discipline

- An `UNKNOWN` result is a real answer. Do not guess a classification for a page you could not read.
- A `security.txt` is not a bounty. A contact address is not a scope. A programme title is not
  payment evidence — require an explicit payment statement.
- Keep evidence read-only. Store an annotated copy rather than editing the original.
- Reproduce twice before calling something a finding. Downgrade rather than inflate.
- Nothing is submitted without explicit operator approval, through the organisation's own
  published channel.

## Licence

The scripts and documentation are provided as-is for security research. The policy pages
referenced in `program-list.md` remain the property of their respective organisations; the
quotes are short excerpts used for attribution and verification.
