---
name: web-security
description: Authorised web application security assessment following OWASP WSTG, ordered by impact. Use when testing an approved web target for access control, injection, authentication, session, file upload, SSRF and logic flaws. Non-destructive by default.
---

# Web Security Assessment

Method follows OWASP WSTG v4.2, prioritised by **realistic impact**, not by checklist
completeness. A confirmed IDOR beats twenty informational header findings.

---

## 0. Before the first request

1. The target is in `targets/approved-targets.txt`.
2. `scripts/scope_gate.py <host>` returns `ALLOW`.
3. The scope's exclusions are read and understood (often: no DoS, no automated scanners
   against production, no third-party SaaS, no social engineering).
4. You know what "success" looks like for this session — one written hypothesis.

```
Hypothesis: <component> trusts <input> for <decision>, so <attacker> can <impact>.
```

If you cannot write that sentence, you are not ready to test; you are ready to recon.

---

## 1. Priority order

| # | Class | Why first |
|---|---|---|
| 1 | Broken access control / IDOR | Highest payout density, lowest tooling cost, purely logical |
| 2 | Authentication & session | ATO chains, password reset, MFA bypass |
| 3 | Business logic | Invisible to scanners, unique to the app, high value |
| 4 | Injection (SQLi, SSTI, command, LDAP, XXE) | Direct data/exec impact |
| 5 | SSRF | Pivot into cloud metadata and internal services |
| 6 | File upload / path traversal | Webshell, LFI, source disclosure |
| 7 | XSS | Session theft, CSRF bypass, admin action |
| 8 | CSRF | Only with a proven state change |
| 9 | Misconfiguration, headers, TLS | Usually informational — report only with impact |

Headers and TLS grades are noise unless they enable something concrete. Never lead a report
with them.

---

## 2. Access control (WSTG-ATHZ)

The core loop, using **two accounts you own**:

```
A = your account, role 1        B = your account, role 2
1. Perform action as A          -> capture request, note every identifier
2. Replay identical request as B -> expect 401/403
3. Any 200 with A's data        -> BOLA/IDOR candidate
4. Any 200 with A's data via a different verb, path, or content-type -> broken function auth
5. Any 200 with extra fields    -> excessive data exposure / property-level
```

Test each identifier position independently: path segment, query param, JSON body field,
GraphQL argument, header, cookie, hidden form field. Then test **vertical** (low→high role)
and **horizontal** (same role, different tenant).

ID shapes to try, in order: sequential integer, UUID, slug, email, phone, composite
(`tenant_id` + `user_id`). If IDs are UUIDv4 and unguessable, the bug is not "guess harder" —
it is a leaked-ID path (referrer, email, export, API response, PDF, log).

**Hard stop:** the moment a response contains another person's data, stop, screenshot,
record the request/response, and do not enumerate further. One record is a finding;
ten thousand is an incident.

---

## 3. Authentication and session (WSTG-ATHN / SESS)

- Registration: duplicate email, case/unicode variants, `+` aliasing, disposable domains
- Login: user enumeration via message, status, or timing; credential stuffing is **out**
- Password reset: token entropy, token reuse, host-header poisoning of the reset link,
  reset token bound to the account or to the session, response leakage of the token
- MFA: response manipulation, code reuse, no rate limit, backup-code brute force (≤5 tries)
- OAuth/OIDC: `redirect_uri` validation, `state` presence, PKCE downgrade, implicit flow,
  account linking by unverified email
- JWT: `alg:none`, RS256→HS256 confusion, `kid` path traversal, `jku`/`x5u` injection,
  weak HMAC secret (offline crack only), missing `exp` enforcement
- Sessions: cookie flags, fixation, logout invalidation, concurrent session behaviour

---

## 4. Injection

- **SQLi** — error-based first, then boolean/time. Cap time-based at 3 requests. Never
  bulk table extraction on production. Prove with a single `SELECT @@version` or an error string.
- **SSTI** — `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`; escalate to a sandbox read, not a shell.
- **Command injection** — `;sleep 5` timing only, one payload, no reverse shell on prod.
- **XXE** — in-band file read first; OOB only if in-band is filtered.
- **NoSQL** — operator injection `{"$ne":null}`, `$where`, array-vs-scalar confusion.

Prove data access, not code execution, unless code execution is trivially safe to prove.

---

## 5. SSRF

1. Internal-only fetch: `http://127.0.0.1:80`, `http://[::1]`, `http://169.254.169.254/`
2. Cloud metadata: AWS IMDSv1, GCP `Metadata-Flavor: Google`, Azure `Metadata: true`
3. Redirect-based bypass: your own host 302s to the internal target
4. DNS rebinding only if allowlist is hostname-based
5. Blind: your collaborator domain, then check timing and DNS

Stop at proof of reachability. Do not exfiltrate credentials from metadata.

---

## 6. Business logic

Highest-value, least-tooled area. For every state-changing flow ask:

- Can a step be skipped, reordered, or repeated?
- Can a quantity, price, or currency be negative, zero, fractional, or huge?
- Is a coupon or credit single-use, and is the check atomic? (race it with 10 parallel
  requests, not 10,000)
- Does the client's view of state match the server's?
- Is approval a separate actor, and can you be both?
- Can you act on a resource after it is cancelled, expired, or refunded?

Prove financial impact with the smallest possible numbers.

---

## 7. XSS

- Context matters more than payload: HTML, attribute, JS string, URL, CSS, template
- Prove with a benign `alert(document.domain)` in a browser, screenshot the dialog
- Stored: find the sink that renders it for a *different* user (admin panel, export, email)
- DOM: trace `location`/`postMessage`/`innerHTML`; check for framework sanitisation bypass
- Blind: out-of-band callback, then confirm in a real browser session

A reflected XSS in a search page nobody visits is informational. Say so.

---

## 8. Non-destructive rules

| Never | Instead |
|---|---|
| `DROP`, `DELETE`, `UPDATE` on real data | `SELECT` only |
| Mass enumeration of IDs | 2–3 requests, then stop |
| Load testing, fuzzing at volume | Single crafted requests |
| Uploading a live webshell | Upload a benign file proving execution context |
| Modifying other users' records | Read-only proof |
| Automated scanners on production | Manual, targeted, rate-limited |
| Testing third-party SaaS embedded in the app | Out of scope unless explicitly listed |

Rate limit yourself to ~2 req/s per host unless the policy says otherwise. If the app starts
returning 429/503, back off — you are the one who gets blamed.

---

## 9. Gate

> **Two reproductions, one from a clean session, before anything is called a finding.**
>
> Root cause written down. Impact stated in business terms. Scope confirmed. Evidence saved
> with full request and response. If any of those is missing, it is a lead, not a finding —
> and leads do not become reports.
