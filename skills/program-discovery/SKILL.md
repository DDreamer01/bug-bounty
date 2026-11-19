---
name: program-discovery
description: Find and classify an organisation's security disclosure channel from official sources — RFC 9116 security.txt, VDP policy pages, bounty pages, security contacts. Use for Phase 0 discovery and for any "does this org authorise testing" question. Never assumes a program exists.
---

# Program Discovery

Goal: answer one question per organisation — **is there a written, official channel that
authorises a stranger to send a vulnerability report, and does it pay?**

Everything here is passive. Discovery never sends a payload, never authenticates, never
touches an asset beyond fetching a file the organisation publishes for exactly this purpose.

---

## 1. Source hierarchy

Trust only in this order. A lower tier never overrides a higher tier.

| Tier | Source | Weight |
|---|---|---|
| 1 | `/.well-known/security.txt` (RFC 9116), served by the org | Authoritative |
| 2 | The `Policy:` URL that security.txt points to | Authoritative |
| 3 | Org's own `/security`, `/trust`, `/responsible-disclosure`, `/vulnerability-disclosure` page | Authoritative |
| 4 | Org's own docs, blog, or press release naming a program | Strong |
| 5 | Platform program page (HackerOne/Bugcrowd/Intigriti/Bugbase/YesWeHack) | Strong for existence, weak for "direct" |
| 6 | Third-party blog, listicle, security-news article | Weak — corroboration only |
| 7 | Search-engine snippet with no fetchable page | **Not evidence** |

If tiers 1–4 are silent, the answer is not "probably has one". It is `NO PROGRAM FOUND`
or `UNKNOWN`.

---

## 2. security.txt (RFC 9116)

Fetch, in this order, and stop at the first `200` with a parseable body:

```
/.well-known/security.txt
/security.txt
```

Two requests per host maximum. No crawling, no directory brute force, no `robots.txt` games.

Fields that matter:

| Field | Use |
|---|---|
| `Contact:` | Where reports go. `mailto:` and `https:` both valid. Multiple allowed. |
| `Policy:` | The human-readable policy. **Fetch it — the classification lives here.** |
| `Expires:` | If past, the file is stale: downgrade confidence, re-check the Policy page |
| `Preferred-Languages:` | Report in a language they read |
| `Hiring:` | Not a program. Ignore for classification. |
| `Acknowledgments:` | Evidence the org actually processes reports |

A `security.txt` with only a `Contact:` and no `Policy:` is a **contact**, not a program.
That distinction is the single most common error in this phase.

Signature blocks (`-----BEGIN PGP SIGNED MESSAGE-----`) may wrap the body — strip them
before parsing. Comments start with `#`.

---

## 3. Classification rules

Apply in order. First match wins. Record the **verbatim quote** that drove the decision.

```
1. Policy page/security.txt points at hackerone.com, bugcrowd.com, intigriti.com,
   bugbase.ai, yeswehack.com, openbugbounty.org, huntr.dev, or similar
   AND no separate direct channel is published
        -> NO - THIRD-PARTY ONLY

2. Explicit monetary reward language (bounty, reward, payout, USD/EUR amount,
   "we pay", tier table, swag-only is NOT monetary)
   AND a defined scope or eligible-asset list
        -> YES - DIRECT PAID BOUNTY

3. A policy exists, defines scope or rules of engagement, no reward language
        -> YES - DIRECT VDP

4. An official security contact exists (security@, PSIRT page, security.txt Contact:)
   with no policy and no scope
        -> YES - DIRECT SECURITY CONTACT

5. Fetched successfully, nothing found
        -> NO - NO PROGRAM FOUND

6. Fetch failed, blocked, ambiguous, or contradictory sources
        -> UNKNOWN
```

### The traps

- **"Security" page that is a product page.** `example.com/security` often sells antivirus
  or describes their own SOC. Read the body; if it never addresses external researchers, it
  is not a program.
- **Bug-bounty *vendor*.** The org sells a bug bounty platform or pentest service. Their
  marketing page is not their own program.
- **Hall of fame without a policy.** A "wall of thanks" implies reports were accepted once.
  It does not establish a current channel or scope.
- **Swag is not money.** T-shirts, points, leaderboards → `YES - DIRECT VDP` at best.
- **Scope by omission.** "Report vulnerabilities to security@" with no asset list means you
  must ask before testing anything beyond the obvious public web property.
- **Stale programs.** Check `Expires:` and the page's own dates. A 2016 policy is `UNKNOWN`
  until confirmed current.
- **Subsidiary confusion.** `brand.com` may be covered by `parent.com`'s policy, or not at
  all. A policy covering "all subsidiaries" is strong; silence is not permission.

---

## 4. Discovery when security.txt is absent

Passive only:

```
site:{org} "responsible disclosure"
site:{org} "vulnerability disclosure"
site:{org} "bug bounty"
site:{org} "report a security issue"
site:{org} inurl:security.txt
site:{org} "security@" OR "psirt@"
```

Then confirm every hit by fetching the page itself. A search snippet is not evidence.
Common real paths worth one direct try each (no brute forcing):

```
/security  /security/  /trust  /trust/security
/security/responsible-disclosure  /vulnerability-disclosure
/.well-known/security.txt  /security.txt  /humans.txt
```

For organisations with an ASN or a certificate-transparency footprint, the *policy* still
comes from the org — CT logs tell you what exists, never what is authorised.

---

## 5. Evidence bar

A record is `VERIFIED` only when all of these are stored:

1. The exact URL fetched
2. HTTP status and `Content-Type`
3. The raw body, saved under `research/evidence/{org}/`
4. The verbatim quote supporting the classification
5. The fetch timestamp (UTC)

Anything less is `UNVERIFIED` or `UNKNOWN`. Never write `VERIFIED` from memory, from a
snippet, or from a previous run.

---

## 6. Output contract

One row per original URL, in `programs/programs.txt`:

```
ORIGINAL_URL | WEBSITE_DESCRIPTION | PROGRAM_STATUS | PROGRAM_URL | SCOPE_STATUS | RESEARCH_EVIDENCE
```

- `ORIGINAL_URL` — never rewritten, never deduplicated away
- `WEBSITE_DESCRIPTION` — what the org does, factual, ≤ 80 chars
- `PROGRAM_STATUS` — one of the six labels, exactly as spelled
- `PROGRAM_URL` — the policy URL, or `NONE`
- `SCOPE_STATUS` — `VERIFIED` | `UNVERIFIED` | `NOT_APPLICABLE` | `UNKNOWN`
- `RESEARCH_EVIDENCE` — short quote + evidence file path

URLs sharing an organisation share the research. They do not each get re-fetched.

---

## 7. Gate

> **A security.txt is not a bounty. A contact address is not a scope.**
>
> Before any target moves to `approved-targets.txt` it must have: a fetched policy,
> a stored body, a verbatim authorisation quote, and an explicit asset list — or an
> explicit statement that no list exists and testing requires prior contact.
>
> If any of those is missing, the status stays `UNKNOWN` and the target stays out of scope.
> Writing `UNKNOWN` is a correct answer. Guessing is not.
