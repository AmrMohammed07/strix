---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures — admin function access, privilege escalation, UI-driven discovery, mandatory real impact with state change proof, and strict false-positive rejection for read-only or intentionally public endpoints
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

## Real Impact Gate — Answer Before Reporting

1. **Did a lower-privileged user successfully perform a privileged action?**
   - Required: actually perform the action AND observe its effect (state change, data access, configuration change)
   - NOT sufficient: receive a 200 status code without confirmation of the action's effect
   - NOT sufficient: receive the same response as an unauthorized attempt (server silently ignores the parameter)

2. **Is the accessed function actually restricted?**
   - Check API documentation — is this endpoint documented as admin-only?
   - Check if the function produces a meaningful result (vs. returning a stubbed/placeholder response)
   - Confirm the function works for an admin user and is denied to regular users by design

3. **What specific privileged action was completed?**
   - Name the exact action: "Created an admin user", "Changed another user's role to admin", "Issued a $500 credit", "Deleted another user's account"
   - Show the before/after state in the database or UI

4. **Have you confirmed with 2+ independent signals?**
   - Signal 1: lower-privileged user's request to admin endpoint returned 200 with meaningful response
   - Signal 2: the effect of the action is confirmed in the system (user now has admin role, credit was issued, etc.)

## Mandatory UI Steps for BFLA Discovery
```
Step 1: Log in as User A (regular user) and enable proxy
Step 2: Navigate through the application — what actions are available in the UI?
Step 3: Open browser DevTools → Network tab
Step 4: Note ALL API calls made during normal navigation
Step 5: Try to discover admin endpoints:
  - Navigate to /admin, /administrator, /manage, /dashboard/admin, /panel, /control
  - Look for admin-related API calls in proxy history
  - Search JS bundles for admin-related routes and endpoints
Step 6: For each discovered admin endpoint:
  a. Note the HTTP method and request format
  b. Try to call it with User A's (non-admin) session
  c. If you get 200: check if the response contains admin data or if the action actually executed
  d. Verify the effect: navigate to the affected resource and confirm the change
Step 7: Screenshot: the unauthorized action's effect confirmed in the UI or database
```

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

## Testing Methodology

1. **Build Actor × Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.


## Additional Techniques — ported from WebSkills (writeup-techniques/priv-esc)

These cover **web vertical privilege escalation** patterns (authenticated normal user → application admin) not already spelled out in the mass-assignment, BFLA, or account-takeover skills. Host/OS post-exploitation privesc (SUID/sudo/capabilities/kernel, Windows service/DLL/token) is deliberately excluded — that is post-shell OS work, not web-app testing.

### Numeric role-*level* hierarchy tampering (distinct from boolean isAdmin)

Many legacy CMS/portal apps model privilege as an integer tier where **lower = more powerful** (e.g. `1 = super administrator … 5 = member`). Unlike an `isAdmin` boolean, the field looks like innocuous UI state, so it is often client-supplied on profile/update and trusted. Intercept a normal update and lower the tier:

```
POST /?c=webuser&m=update
Cookie: PHPSESSID=...

No=3&ID=test&Password=test&Name=test&UserRole=1&Language=en   # UserRole=1 → admin tier
```

Field names seen in the wild to fuzz specifically: `level=`, `UserRole=`, `U_ACCESS=`, `accesslevel=`, `role_id=`, `rolelevel=`, `role_name=`, `group_id=`, `user_type=admin`. Editor at `level=3` re-submitting with `level=1` = super-admin.

### Registration-time privilege field injection

Some apps enforce a privilege binding on **update** but not on **create** (or vice-versa) — the binder differs per route. If a profile-update rejects your `role`/`accesslevel`, retry the same field on the **registration** request, where a hidden field like `U_ACCESS` or `accesslevel=4` may be blindly persisted at account creation:

```
POST /register
username=x&password=...&U_ACCESS=admin&accesslevel=4
```

Always test both create and update paths independently — a rejected field on one route is frequently honored on the other (route-dependent model binding).

### Password-reset parameter tampering → reset the admin's password

Beyond host-header poisoning and token leakage: some reset endpoints take the *target account* from a **request parameter or cookie** rather than from the authenticated session, so swapping it lets you drive a reset against an arbitrary/admin account:

```
GET /lua/admin/password_reset.lua?csrf=XXXX&username=admin&old_password=12345&new_password=123456&confirm_new_password=123456 HTTP/1.1
Cookie: user=admin; session=XXXX
```

Swap both the `username=` param and any identity cookie (`Cookie: user=admin`). If the server keys the reset off the client-supplied identifier, you set the admin's password → vertical ATO.

### Delegation / role-grant workflow abuse

Apps with a "delegate access" or "grant role" feature may let you name **both** the grantee and the granted role in one request, without checking that you are entitled to hand out that role or act on that delegator:

```
selFunc=add&delegate=<ATTACKER>&delegateRole=5&delegatorUserId=<ADMIN>
```

Set `delegateRole` to the highest tier and `delegatorUserId` to a privileged user — the workflow grants your account the elevated role. Treat every "assign role / add member / delegate" action as a privilege-granting sink and confirm it re-checks the actor's own rights.

### JWT `alg=None` / role-claim forgery → admin

Where authorization is derived from a JWT claim, tamper the token rather than the request body: strip the signature with `alg=None`, or flip a role/tier claim (`"role":"admin"`, `"level":1`, `"tenant":"*"`) if the signature is weak/guessable. Forged claim → admin API reachable directly. (Verify signature handling per the improper-authentication methodology before relying on it.)

### Predictable / guessable session token → admin impersonation

If session identifiers are sequential, timestamp-derived, or short (e.g. an app-specific `W2E_SSNID`), an authenticated low-priv user can predict or brute an admin's live session token and impersonate them outright — no reset flow needed. Sample several tokens, check for structure/entropy, and try adjacent/derivable values against admin-only endpoints.

### Confirming web privesc: the before/after 403 diff

Concrete confirmation that turns a "200 OK" into a proven escalation: as the escalated identity, hit an admin-only endpoint that the *same account returned 403/404 on before* the change, and separately re-fetch your own profile to show the `role`/`isAdmin`/`level` field now reflects the injected value. Two independent signals (privileged action now succeeds + persisted privilege field changed) distinguish a real escalation from a silently-ignored parameter.
