# Methodology

This document explains how `data/classification.tsv` and `program-list.md` were produced.
Every stage is scripted and every classification points at a stored page.

---

## 1. Candidate selection

Three independent pools were combined so that no single source's bias decides the result:

1. **Public top-sites corpus** — the top 50,000 entries of a public ranking.
2. **Seed list** — organisations hand-listed because they were thought to publish a policy.
3. **Custom corpus** — the top 30,000 domains by frequency in a separate unlabelled URL
   collection, used only as a popularity signal.

The pools were lowercased, `www.`-stripped and de-duplicated: 30,000 + 50,000 + 37 seeds
produced 71,245 unique hosts (8,768 appeared in two pools). Three malformed entries were
removed (`com`, `_wildcard_.ph`, `_wildcard_.com.ph`), leaving 71,242.

**A domain appearing in a candidate pool is never authorisation.** Pools only decide what to
look at. Authorisation always comes from the organisation's own published page.

## 2. Discovery traffic

Two requests per host, at a polite controlled rate, with a descriptive user-agent:

```
GET /.well-known/security.txt
GET /security.txt          (only if the first path gave nothing)
```

A 200 is not enough. `scripts/normalize_sweep.py` parses the stored body and keeps only
responses containing an actual `Contact:`, `Policy:`, `Expires:`, `Encryption:`,
`Acknowledgments:` or `Preferred-Languages:` field. Soft-200 homepages are discarded.

Result: 12,228 HTTP-200 responses → **4,424 validated security.txt files**.

Dead hosts were filtered out first with a DNS pre-pass; without it, the sweep spent its time
in DNS timeouts rather than HTTP requests.

## 3. Policy fetch and classification

For each host with a `Policy:` URL, `scripts/classify.py` fetches that page, stores the raw
body and its metadata, strips markup, and applies fixed rules.

The classification vocabulary is exact:

```
YES - DIRECT PAID BOUNTY
YES - DIRECT VDP
YES - DIRECT SECURITY CONTACT
NO - THIRD-PARTY ONLY
NO - NO PROGRAM FOUND
UNKNOWN
```

Third-party platforms are detected by their hostname (including subdomains) and by prose such
as "hosted by X", "our program on X", "submit via X". Platforms found include HackerOne,
Bugcrowd, Intigriti, YesWeHack, Cobalt, Synack, Immunefi, HackenProof, Inspectiv, Cantina and
Sherlock.

## 4. Why the reward rule is strict

Early versions of the classifier reported far too many paid programmes. Each correction came
from reading a sampled quote, not from guessing:

| Version | Paid rows | Mistake being corrected |
|---|---:|---|
| 1 | 736 | English-only keywords, no negation handling |
| 2 | 221 | Negation only detected *before* the noun |
| 3 | 433 | Negation *after* the noun ("does not offer a bug bounty") still passed |
| 4 | 138 | A programme title ("Bug Bounty Program") was treated as payment evidence |
| 5 | 133 | Navigation, cookie banners and legal boilerplate scored as payouts |

The final rule requires a sentence that:

- mentions a reward term,
- mentions security/disclosure context,
- contains **no negation cue anywhere in the sentence**, and
- contains an explicit payment signal — a currency amount, a payout verb, or a reward range.

Candidates are scored, and evidence is the **best** sentence rather than the first one. A
bare heading scores low on purpose. Non-English pages are flagged as `note` fields and must be
read by eye before use.

`UNKNOWN` is used when a fetch fails, a page is bot-protected, or no policy could be reached.
A blocked page is never assumed to be a programme.

## 5. Verification before use

A HIGH-confidence row means: reward language **and** an explicit scope, on the organisation's
own page, in English, with no platform mention. It is still a lead until a human reads the
page.

Manual verification is what catches things rules cannot. For example, one programme in the
shortlist had a banner saying it was temporarily suspended and not paying rewards — the
banner sat above the reward table, so no keyword rule saw it. It was removed before approval.

Other ambiguities are recorded rather than guessed: a policy that references "regional domains"
without listing them, another that excludes "internal services" without defining them, and a
scope that excludes subdomains redirecting to third parties. Each is treated as out of scope
until confirmed in writing.

## 6. Deduplication

One organisation often publishes the same policy through many domains. Rows are grouped by
the policy URL host, so eleven domains pointing at one programme become one entry with the
other domains listed as aliases. This is why 133 paid rows become 73 programmes.

## 7. Known limits

- Coverage is a sample, not a census. A missing row means *not investigated*, never *no programme*.
- Classifications are keyword-derived; non-English and anti-bot pages need a human read.
- Programmes change. A list is a starting point, not a current-state guarantee.
- This project only ever fetched published policy files. No testing traffic was sent during
  discovery.

## 8. Reproducing

```bash
# From the repository root
python3 scripts/build_program_list.py       # rebuild program-list.md from the TSV

# To collect fresh data against your own host list
RATE=100 THREADS=150 TIMEOUT=6 RETRIES=0 bash scripts/security_txt_sweep.sh hosts.txt
python3 scripts/normalize_sweep.py
python3 scripts/classify.py --workers 30
```

`classify.py` writes `policies/<host>/` with the stored response and metadata. Re-running it
after a rule change reuses those files, so the evidence is written once.
