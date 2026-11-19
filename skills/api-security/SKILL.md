---
name: api-security
description: Authorised API security assessment using OWASP API Security Top 10 (2023), prioritising BOLA and object-property authorisation. Use for REST, GraphQL and mobile-backend APIs on approved targets. Researcher-owned accounts only.
---

# API Security Assessment

Reference: OWASP API Security Top 10 (2023). Priority order below is deliberate — it
follows observed payout distribution, not list order.

---

## 0. Preconditions

- Host approved via `scripts/scope_gate.py`
- Two accounts **you created and own**, ideally different roles and, if available,
  different tenants
- A captured baseline of every request the client makes (browser devtools, or
  `browser-use` network capture, or the `httptoolkit` skill for mobile)
- A written hypothesis

APIs are discovered from the client, not guessed. Harvest endpoint lists from JS bundles,
mobile traffic, OpenAPI/Swagger (`/openapi.json`, `/swagger/v1/swagger.json`, `/api-docs`),
and GraphQL introspection **if the policy permits introspection** — some treat it as
recon, some as an attack. Read the policy.

---

## 1. BOLA — Broken Object Level Authorization

The #1 API risk and the #1 realistic payout.

```
For every request containing an object identifier:
  path        /api/v1/users/1001
  query       ?account_id=1001
  body        {"invoice_id": 1001}
  header      X-Tenant-Id: 1001
  graphql     query { invoice(id: 1001) { total } }
```

Method:

1. As A, capture the request and its response.
2. As B, replay **byte-identical** except the token.
3. Compare: `200` + A's object = BOLA. `403` = correct. `404` = correct-ish. `500` = look closer.
4. Then try: wrong tenant header, removed header, `null`, `*`, `0`, array-wrapped
   (`[1001]`), duplicate keys, case variants, URL-encoded and double-encoded forms.

Never iterate a numeric range. Two or three adjacent IDs prove it; a thousand is an incident.

## 2. Broken authentication

- Token in URL, logs, referrer, or a response body
- No expiry, no revocation, logout does not invalidate
- Password/OTP endpoints without rate limits (test with 5 requests, then stop)
- `Authorization` accepted from query string or cookie interchangeably
- API keys with broader scope than the UI ever uses
- Long-lived refresh tokens replayable after password change

## 3. Broken object property level authorisation (mass assignment)

The inverse of BOLA: not *which* object, but *which fields*.

1. Read the response schema — every field returned is a candidate.
2. In the update request, add fields the UI never sends:
   `role`, `is_admin`, `verified`, `balance`, `credits`, `tenant_id`, `owner_id`,
   `email_verified`, `price`, `discount`, `status`
3. Also try **removing** fields, and sending `null`.
4. Check `PATCH` vs `PUT` vs `POST` — frameworks often bind differently.
5. Read-back is the proof: if the field changed server-side, it is a finding.

Excessive data exposure is the read side: responses returning `password_hash`,
`internal_notes`, `other_users`, full PII, or admin-only fields to a normal user.

## 4. Improper resource consumption

**Out of scope for active testing unless the policy explicitly allows it.** Note the
missing limit (pagination `?limit=999999`, no `max` on upload size, unbounded GraphQL
depth/batch) as an observation, do not demonstrate it.

## 5. Broken function level authorisation

Same endpoint, different privilege: call admin-only operations as a normal user.
Try method swap (`GET`→`POST`→`PUT`→`DELETE`→`PATCH`), path case, trailing slash,
`/api/v1/admin` → `/api/v1/Admin`, version downgrade (`/v1/` where UI uses `/v2/`),
and internal-looking prefixes (`/internal/`, `/beta/`, `/debug/`).

## 6. Sensitive business flow abuse

Automation of a legitimate flow for unfair gain: signup bonus repetition, referral
self-credit, coupon stacking, refund-then-keep, trial reset by email change, OTP reuse
across flows. Prove with the minimum viable repetition.

## 7. SSRF

See `web-security`. In APIs the sink is usually a `url`, `webhook`, `image_url`,
`callback`, `import_from`, or `avatar` parameter.

## 8. Security misconfiguration

CORS reflecting arbitrary origins **with** `Access-Control-Allow-Credentials: true`;
verbose stack traces; `X-Powered-By`; debug endpoints; missing auth on a whole router;
GraphQL playground enabled in production.

## 9. Improper inventory management

Old versions still live: `/v1/` alongside `/v3/`, `api-staging.`, `api-beta.`,
`legacy.`, partner and mobile-only hosts. Old versions usually lack the auth fix the
new one has. Confirm the host is in scope — old infrastructure is often explicitly excluded.

## 10. Unsafe consumption of APIs

The target trusting a third-party API response without validation. Look for
webhook handlers, import features, and SSO assertions. Hard to prove; do not force it.

---

## GraphQL specifics

- Introspection: only if permitted. If disabled, infer from client queries.
- Batching: send 5 aliased queries in one request to test per-object authz cheaply.
- Depth/alias abuse: note it, do not run it.
- `__typename` on unions often leaks hidden types and admin-only mutations.
- Mutations deserve the same BOLA test as REST — argue each argument independently.

---

## Evidence format

For every candidate, store:

```
request.http      full method, path, headers, body (token redacted)
response.http     status, headers, body (PII masked)
comparison.md     A's response vs B's response, field by field
impact.md         what an attacker gains, in business terms
```

---

## Gate

> **Both accounts must be yours.**
>
> If a response contains another person's data, stop immediately, save one example,
> and do not enumerate further. Report the class of exposure, never the volume of
> other accounts you could have reached.
>
> No resource-exhaustion testing. No enumeration loops. No third-party accounts.
