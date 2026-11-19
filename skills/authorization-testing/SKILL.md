---
name: authorization-testing
description: Two-account and privilege-boundary testing methodology — horizontal, vertical and multi-tenant access control, role matrices, and ID boundary probing. Use whenever a target has accounts, roles, or tenants. Only researcher-owned accounts.
---

# Authorization Testing

Access control is the highest-yield bug class in modern web and API targets, and the one
most often reported badly. This skill exists to make the testing disciplined and the
evidence airtight.

---

## 1. Build the role matrix first

Do not test until you can draw this table. Fill it from the UI, the API, and the docs.

| Actor | Role | Tenant | Can read | Can write | Can admin |
|---|---|---|---|---|---|
| A1 | member | T1 | own | own | no |
| A2 | admin | T1 | T1 all | T1 all | T1 |
| B1 | member | T2 | own | own | no |

Minimum viable set: **two accounts, two roles or two tenants.** One account proves nothing —
you cannot distinguish "no authorisation" from "authorisation that happens to allow you".

If registration only yields one role, look for:
- an invite flow (create a second org/workspace)
- a team member role selector
- a separate partner/vendor/business signup
- a sandbox vs production account pair

Never ask a real user to test on your behalf. Never use a credential you did not create.

---

## 2. Horizontal testing (same role, different owner)

The workhorse loop.

```
1. As A, create object X. Record every identifier in the request and response.
2. As A, read X. Save request + response verbatim.
3. As B, send the identical request with only B's token changed.
4. Classify:
     200 + A's data      -> BOLA. Confirmed.
     403 / 401           -> correct
     404                 -> correct (or soft-hide; check response timing)
     500                 -> error-based leak; dig, but do not spam
     200 + empty/placeholder -> possibly filtered; check other endpoints
```

Then repeat for **every verb** on that object: `GET`, `HEAD`, `POST` (create in A's space),
`PUT`, `PATCH`, `DELETE`, and `OPTIONS`. Read access control and write access control are
separate implementations and frequently disagree.

Then repeat for **every transport** of the identifier:
path, query, body, header, cookie, GraphQL arg, multipart field, JWT claim.

## 3. Vertical testing (low role, high function)

As the lowest-privilege account, attempt every high-privilege action you can name:

- user management: list, invite, role change, deactivate, reset password
- billing: plan change, invoice read, payment method, credit grant
- configuration: SSO, webhooks, API keys, audit log, export
- content: publish, delete others', approve, moderate

Try method and path variants, not just the obvious one:

```
POST /admin/users          GET  /admin/users
POST /Admin/users          POST /admin/users/
POST /api/v1/admin/users   POST /api/v1/Admin/users
POST /internal/users       POST /api/admin/users.json
```

Frontend-only guards are the most common failure: the button is hidden, the endpoint is not.

## 4. Multi-tenant isolation

If the product has organisations, workspaces, teams, or projects:

1. Create a workspace in tenant A and one in tenant B (both yours).
2. Find every request carrying a tenant identifier — path, header (`X-Tenant-Id`,
   `X-Org`, `X-Workspace`), subdomain, JWT claim, cookie.
3. Swap the tenant value while keeping your own token.
4. Also try: no tenant header, two conflicting tenant values, a tenant ID in the body
   that contradicts the path, and a subdomain that does not match the token's tenant.

A cross-tenant read is high severity. A cross-tenant write is critical. A cross-tenant
*admin* action ends the test — report immediately.

## 5. Identifier boundary probing

Cheap, high-signal, and easy to overdo. Budget: **3 requests per identifier space.**

| Shape | Probes |
|---|---|
| Integer | `id`, `id±1`, `0`, `-1`, `1e3`, `0x1`, `0001` |
| UUID | your own two UUIDs, one malformed, one v1 if v4 is used |
| Slug | your slug, a known-public slug, a reserved word |
| Email/phone | your second account's |
| Composite | swap only one component, then both |
| Encoded | `%2e`, `%2f`, double-encode, unicode lookalike |

Type juggling is worth one attempt each: `"1"` vs `1`, `[1]` vs `1`, `{"$ne":1}`,
`true` vs `"true"`.

## 6. What makes a finding stand out from a duplicate

Triage teams see "I changed the ID and got data" a hundred times a day. Differentiate:

- **Root cause**, not just the endpoint — is it a missing ownership check in one handler,
  or a missing authorisation middleware on a whole router? The latter is worth more.
- **Breadth** — does the same flaw affect 12 endpoints? Say so once, with a table.
- **Write impact** — read is good, modify/delete is better, privilege grant is best.
- **Chained consequence** — cross-tenant read → PII export → regulatory exposure.
- **Precondition honesty** — if it needs a paid plan or an invite, say so up front.

## 7. Anti-patterns

| Don't | Do |
|---|---|
| Enumerate 1..10000 | Two adjacent IDs, then stop |
| Report 40 endpoints as 40 findings | One finding, one table of affected endpoints |
| Use another user's account "just to confirm" | Only accounts you created |
| Test after the policy says no | Read scope first, every time |
| Call a 403-bypass "critical" | Rate it by what it actually exposes |
| Ignore read-only proof | Read-only cross-tenant data *is* the finding |

## 8. Evidence template

```
target:        <host>
accounts:      A1 (role, tenant)  B1 (role, tenant)   [both researcher-owned]
request_A:     <full request as A>
response_A:    <status, body excerpt>
request_B:     <identical, B's token>
response_B:    <status, body excerpt>
delta:         <what B received that B should not>
root_cause:    <handler / middleware / missing check>
impact:        <what an attacker with a free account gains>
repro:         <numbered, from a clean session>
```

---

## Gate

> **Only accounts you created. Only two or three IDs per space.**
>
> The moment you see data belonging to a real person, stop, keep one example, and write it
> up. Continuing to enumerate is not thoroughness — it is unauthorised access, and it turns
> a valid report into an incident.
