---
name: report-writing
description: Write reproducible, honest vulnerability reports — structure, CVSS scoring, impact statements, evidence handling and responsible disclosure. Use before submitting anything, or when turning notes into a report. Rejects inflated severity and unreproducible findings.
---

# Report Writing

A report is not a story about how clever the hunt was. It is a document that lets a
stranger who has never seen the target reproduce the bug in fifteen minutes and understand
why it matters to the business.

---

## 1. Structure

```markdown
# <Title: <class> in <component> allows <impact>>

## Summary
2–4 sentences. What, where, who can do it, what they gain.

## Severity
Rating + CVSS 3.1 vector + score. One line of justification.

## Affected asset
Exact host, path, parameter, version, and the scope entry that covers it.

## Preconditions
Accounts needed, plan tier, configuration, race window. Be honest — this is what
triage uses to decide "works as intended".

## Steps to reproduce
Numbered. Every step executable by someone with no context.
Include the exact request, or a curl that works when pasted.

## Evidence
Requests and responses, screenshots, video. Redacted.

## Root cause
Which check is missing, in which handler. One paragraph. If you don't know, say
"not determined" — do not invent an implementation detail.

## Impact
What an attacker actually gains, in business terms: data class, volume ceiling,
financial exposure, regulatory consequence, blast radius.

## Remediation
Specific and actionable: enforce ownership check on <handler>, bind token to
<subject>, add server-side validation on <field>. Not "sanitise input".

## Timeline
Discovered / reported / acknowledged / fixed.
```

## 2. Titles

Bad: `IDOR in API`
Good: `Broken object-level authorization in /api/v2/invoices allows any authenticated user to read other tenants' invoices`

Format: `<class> in <component> allows <actor> to <impact>`.

## 3. CVSS honesty

Score the **demonstrated** impact, not the theoretical maximum.

| Situation | Score guidance |
|---|---|
| Read another tenant's data with your own free account | 6.5–7.5 (High) — not Critical |
| Write/modify another tenant's data | 8.0–8.8 |
| Full account takeover of arbitrary users | 8.8–9.1 |
| Pre-auth RCE | 9.8 |
| Requires unlikely user interaction + a long chain | drop one band |
| Requires admin account you already compromised | drop two bands, or informational |

Do not add `S:C` (scope changed) unless the vulnerable component genuinely grants
privileges in another security authority. Do not claim `AV:N` for something that needs
local access.

If you cannot defend the vector to a sceptical reviewer, lower the score.

## 4. Impact writing

Impact is a business sentence, not a security sentence.

| Weak | Strong |
|---|---|
| "Attacker can read data" | "Any of the ~N free-tier accounts can read every invoice in the workspace, including billing address, tax ID and line items — a GDPR Art. 33 reportable event" |
| "Allows privilege escalation" | "A member can promote themselves to workspace owner, then remove the real owner and take over billing" |
| "XSS" | "Stored XSS in the support-ticket subject executes in the admin console, giving any customer session theft of an admin token" |

Never state a number you did not measure. "~N" with the method, or no number.

## 5. Evidence handling

- Save the raw request and response **before** editing anything
- Redact: your own tokens, cookies, API keys, other users' PII, internal hostnames you
  were not authorised to reach
- Redact by replacement, not deletion — `Authorization: Bearer <REDACTED_A_TOKEN>`
- Never crop a screenshot in a way that hides the URL or the response status
- Video beats screenshots for multi-step or timing-dependent bugs
- Keep the chain intact: `evidence/<target>/<finding-id>/` with `request.http`,
  `response.http`, `screenshot-01.png`, `README.md` describing each file

## 6. Duplicate and prior-art check

Before submitting:

1. Search the program's disclosed reports for the same class + component
2. Search the vendor's changelog and advisories
3. Search general web for the endpoint and the bug class
4. Ask: is this "works as intended" by design? Is the data actually sensitive?

If a public report exists, either your finding differs materially (say how) or you don't
submit.

## 7. Disclosure etiquette

- Use only the channel in the policy. Not a DM, not a support ticket, not a cold email to
  an engineer's personal address, unless the policy says so
- One report per vulnerability, unless the program asks otherwise
- No public disclosure before the agreed window, or 90 days by default
- No demands, no deadlines you invented, no "I will publish in 7 days"
- Do not test the fix without permission
- Do not resubmit a closed report as new

## 8. Pre-submission checklist

- [ ] Reproduced twice, second time from a clean browser profile / fresh token
- [ ] Target is in `approved-targets.txt` and the specific asset is in scope
- [ ] Tested with accounts I created, nothing else
- [ ] Impact demonstrated, not asserted
- [ ] CVSS defensible to a sceptic
- [ ] No real user's PII in the evidence
- [ ] Report readable by someone with zero context
- [ ] Duplicate search done and documented in `research/duplicates/`
- [ ] Submitted through the official channel only
- [ ] `logs/daily-log.md` updated

---

## Gate

> **If a reviewer cannot reproduce it from the report alone, it is not ready.**
>
> If the severity would embarrass you when the triager downgrades it, fix it yourself first.
> A downgraded honest report is fine. An inflated one costs credibility you cannot buy back.
