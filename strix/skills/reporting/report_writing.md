---
name: report-writing
description: Bug bounty report writing for HackerOne / Bugcrowd / Intigriti / Immunefi — impact-first templates per platform, human-tone guidelines, title and impact formulas, CVSS 3.1 and 4.0 quick scoring, severity decision guide, downgrade counters, and a pre-submit checklist. Use after validating a finding and before submitting. Never use "could potentially" — prove it or do not report.
---

# Report Writing

Impact-first, human tone, no theoretical language. Triagers are tired people who skim — get to the impact in sentence one.

## The Most Important Rule

Never use "could potentially", "could be used to", or "may allow". Either it does the thing or it doesn't; if you haven't proved it, don't claim it.

```
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An attacker can read any user's order history by changing the user_id
       parameter. Confirmed with two accounts: attacker@test.com (ID 123) retrieved
       victim@test.com (ID 456) orders, including shipping address and card last-4."
```

## Title Formula

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

Good: "IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data"; "Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts"; "SSRF via image import URL reaches AWS EC2 metadata service". Bad (vague, useless to triager): "IDOR vulnerability found", "Broken access control", "XSS in user input".

## HackerOne Template

```markdown
## Summary
[One paragraph: what the bug is, where, what an attacker can do. Include endpoint,
method, parameter, data exposed, required access level.]

## Vulnerability Details
**Type:** IDOR / Broken Object Level Authorization
**CVSS 3.1:** 6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**Affected Endpoint:** GET /api/users/{user_id}/orders

## Steps to Reproduce
**Environment:** attacker@test.com (id 123), victim@test.com (id 456), https://target.com
1. Log in as attacker, obtain Bearer token.
2. Send:
   GET /api/users/456/orders HTTP/1.1
   Host: target.com
   Authorization: Bearer ATTACKER_TOKEN
3. Response returns victim's full order history + PII despite a different requester.

## Impact
[Quantified: what data, how many users, what the attacker walks away with.]

## Recommended Fix
Add server-side ownership verification: if order.user_id != current_user.id: raise Forbidden()

## Supporting Materials
[Screenshot / video showing the actual impact.]
```

## Bugcrowd Template

Lead with the VRT category (e.g. `Broken Access Control > IDOR > P2`), then the same impact-first description and structured steps. Add an **Expected vs Actual** block (Expected: 403 Forbidden; Actual: 200 OK with victim data) and a **Severity Justification** paragraph tied to the VRT priority.

## Intigriti Template

Title `[Bug Class]: [one-line impact]`. Impact-first description, structured HTTP steps, quantified Impact with a CVSS 3.1 (or 4.0) vector, and a 1–3 sentence remediation. Intigriti triagers value a PoC video (Loom) over a screenshot for complex bugs; safe harbor is enforced.

## Immunefi Template

```markdown
# [Bug Class] — [Protocol] — [Severity]
## Summary
[Root cause, affected function, economic impact, attack cost. "Attacker can drain $X in Y transactions."]
## Vulnerability Details
**Contract / Function / Bug Class / Severity**
### Root Cause
[Exact vulnerable code snippet with comments]
## Proof of Concept
[Full working Foundry exploit — forge test --match-test test_exploit -vvvv]
## Impact
[Quantified: "drains X% of TVL = $Y, requires $Z gas, repeatable"]
## Recommended Fix
[Specific before/after code change]
```

## CVSS 3.1 Typical Scores

| Bug | Typical CVSS | Severity |
|---|---|---|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass → admin | 9.8 | Critical |
| Stored XSS (any user) | 5.4–8.8 | Med–High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race (double spend) | 7.5 | High |
| JWT none algorithm | 9.1 | Critical |

Metric quick picks: AV Network (internet-reachable), AC Low (repeatable) vs High (race/timing), PR None (no login) / Low (free account) / High (admin), UI None (no victim action) / Required (victim clicks), S Changed (affects browser/OS/cloud), C/I/A High (all data / modify all / crashes service).

## CVSS 4.0 (newer programs)

Replaced 3.1 in Nov 2023. Key changes: new **Attack Requirements (AT)** metric (None/Present), **User Interaction** is None/Passive/Active, **Scope removed**, and split **Vulnerable (VC/VI/VA)** vs **Subsequent (SC/SI/SA)** system impact. Examples: unauthenticated RCE `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` = 10.0; IDOR read PII auth required `.../PR:L/UI:N/VC:H/VI:N/VA:N/SC:N...` = 6.9. If a program uses 4.0, use the FIRST calculator and include the full `CVSS:4.0/...` vector — programs can't dispute a valid vector string.

## Severity Decision Guide

- **Critical (P1)** — any-user ATO without interaction, RCE, SQLi with full DB access, admin auth bypass, SSRF → cloud metadata IAM exfil.
- **High (P2)** — mass PII exposure, user→admin priv-esc, internal SSRF returning data, stored XSS for all users of a sensitive feature, unlimited payment bypass.
- **Medium (P3)** — IDOR on a specific user's non-critical data, XSS needing victim click, CSRF on an important action, demonstrated OTP rate-limit bypass.
- **Low (P4)** — non-sensitive info disclosure, clickjacking on a sensitive action with working PoC, CORS on limited data.

Each YES raises severity: exposes others' PII/financial/health data (+1); enables ATO or priv-esc (+2); zero victim interaction (+1); affects all users (+1); remotely exploitable with no internal access (baseline for High+).

## Downgrade Counters

| Program says | Counter with |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended" |
| "Low CVSS" | "CVSS misses business impact — attacker extracts [X] in [Y] minutes" |
| "Not exploitable" | "Here's the exact response showing victim's data in the attacker session" |

## The 60-Second Pre-Submit Checklist

```
[ ] Title follows the formula
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has a copy-paste-ready HTTP request
[ ] Response showing the bug included (screenshot or JSON body)
[ ] Two test accounts used — not one account testing itself
[ ] CVSS score calculated and included
[ ] Recommended fix is 1–2 sentences
[ ] No typos in endpoint paths or parameter names
[ ] Report < 600 words — triagers skim
[ ] Severity claimed matches impact described
[ ] Never used "could potentially" / "may allow"
[ ] PoC reproducible by the triager from a fresh state
```

## Human Tone

Write to a person: get to impact in sentence one, use "I" (you found it), short paragraphs, bullet steps. Avoid jargon the triager may not know, 5-paragraph explanations of what IDOR is, theoretical chains, passive voice, and qualifiers ("seems to", "appears to"). Escalation language when a payout is being downgraded: "requires only a free account", "the exposed data is subject to GDPR", "an attacker automates this — all [N] records in minutes", "exploitable externally with no internal access".
