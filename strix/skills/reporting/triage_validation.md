---
name: triage-validation
description: Finding validation before writing any report — the 7-Question Gate, 4 pre-submission gates, an always-rejected "never submit" list, a conditionally-valid chain table, common N/A kill signals, CVSS 3.1 quick reference, and kill-fast rules. Use BEFORE writing any report. One wrong answer kills the finding — this protects your N/A / validity ratio.
---

# Triage & Validation

One wrong answer = STOP. Kill it. Move on. N/A hurts your validity ratio; informative is neutral; only submit what passes all gates.

## The 7-Question Gate

Ask IN ORDER. One wrong answer = stop immediately.

**Q1 — Can an attacker use this RIGHT NOW, step by step?** Fill in: (1) setup (own account / another user's ID / no account); (2) the exact HTTP method, URL, headers, body — copy-paste ready; (3) result (read/modify/delete exact data); (4) real-world impact (ATO / PII read / money); (5) cost (time, capital). If you cannot write step 2 as a real HTTP request → KILL IT.

**Q2 — Is the impact on the program's accepted-impact list?** If your bug maps to a listed exclusion → KILL IT.

**Q3 — Is the root cause in an in-scope asset?** Production, in-scope domain, not a third-party service the company merely uses (Stripe, Salesforce, Google Auth). Out of scope → KILL IT.

**Q4 — Does it require privileged access an attacker can't realistically get?** "Admin can do X" = centralization risk → KILL IT (on 99% of programs). "Non-admin can do what only admin should" = valid. Requires physical access / MFA device / compromised victim account = usually invalid or low.

**Q5 — Is this already known or accepted behavior?** Search disclosed reports (endpoint + bug class), GitHub security issues, changelog, API/design docs. Acknowledged / design decision → KILL IT.

**Q6 — Can you prove impact beyond "technically possible"?** XSS → actual cookie/session theft, not `alert(1)`. SSRF → internal endpoint returning data, not just a DNS ping. SQLi → actual rows from a real table, not just an error. IDOR → another user's data in the response, not just a 200. If only "technically possible" → DOWNGRADE severity, don't necessarily kill.

**Q7 — Is this a known-invalid bug class?** If it's on the Never Submit list below without a chain → KILL IT.

**Q8 — Identity check: which session found this, and does it survive?** Record: session identity (low-priv A / high-priv B / API key), anonymous repro (does it work with NO auth header?), cross-identity (does it work under session B with the same data scope?), stale-cred repro (does a logged-out/expired session still get the data?). IDOR/BOLA must work with session A reading session B's data — if it only works with no auth, that's "missing auth", a different bug/severity. Priv-esc must work low→high. Auth bypass must work without a valid session. Blank answers auto-fail auth-related findings. This is the most common reason a "confirmed IDOR" comes back N/A.

## 4 Pre-Submission Gates

Run in sequence; all four must PASS.

**Gate 0 — Reality (30s):** bug is real (confirmed with actual HTTP requests, not code reading alone); in scope (checked the program page); reproducible from a fresh session; evidence ready.

**Gate 1 — Impact (2 min):** can answer "what can the attacker DO that they couldn't before?"; more than "see non-sensitive data"; a real victim (another user's data, company data, financial loss); not relying on the victim doing something unlikely.

**Gate 2 — Dedup (5 min):** searched Hacktivity for this program + similar title/endpoint; searched GitHub issues; read the 5 most recent disclosed reports; not a known issue in changelog/docs; Googled "TARGET ENDPOINT bug bounty".

**Gate 3 — Report Quality (10 min):** title follows the formula; copy-pasteable HTTP request; evidence of actual impact (not just a 200); severity matches CVSS AND program definitions; 1–2 sentence remediation; never used "could potentially".

## Never Submit List

Submitting these destroys your validity ratio:

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass / IDOR shown)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages
Tabnabbing
CSV injection with no code execution shown
CORS wildcard (*) without credential-exfil PoC
Logout CSRF
Self-XSS (own account only)
Open redirect alone (no ATO / OAuth-theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no reset-poisoning PoC)
Rate limit on non-critical forms (search, contact, CF-fronted login)
Session not invalidated on logout / concurrent sessions
Internal IP in error message
Mixed content / SSL weak ciphers
Missing HttpOnly / Secure flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions)
```

## Common N/A Classes — Kill Signals

Kill *before* writing the report if you see the signal:

| Finding | Kill signal — stop if you see this |
|---|---|
| Reflected XSS | `alert(1)` fires but no cookie in response; CSP header present |
| SSRF — DNS callback only | DNS ping but no HTTP reply with internal content |
| IDOR — own data only | User ID in response matches your own test account |
| SQLi — error message only | DB error string but no actual table rows returned |
| CORS wildcard `*` | `Access-Control-Allow-Credentials: true` absent; credentialed request 403s |
| Rate limit missing — non-sensitive | Endpoint is search/contact, or sits behind Cloudflare |
| Nuclei `info` match | Version detection only; no CVE PoC executed |
| MFA rate limit (no lockout) | Many 200s but no OTP code ever accepted |
| Open redirect alone | No OAuth `redirect_uri`; no token/code in the redirected URL |
| Auth bypass — admin precondition | "Admin can do X on behalf of user" — attacker must already be admin |

Decision rule: match a kill signal → classify `[INFORMATIONAL]`, do not validate further, move on.

## Conditionally Valid — Chain Required

Build the chain first, prove it end to end, THEN report:

| Standalone finding | + Chain | Valid result |
|---|---|---|
| Open redirect | OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | sensitive action + working PoC | Medium |
| CORS wildcard | credentialed request exfils PII | High |
| CSRF | sensitive action (transfer / change email / delete) | High |
| Rate limit bypass | OTP / reset-token brute force succeeds | Medium/High |
| SSRF DNS-only | internal service access + data returned | Medium |
| Host header injection | reset email uses injected host | High |
| Prompt injection | reads another user's data (IDOR) | High |
| S3 bucket listing | JS bundles contain API keys / OAuth secrets | Medium/High |
| Self-XSS | CSRF triggers it on the victim | Medium |
| Subdomain takeover | OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | auth-bypass mutation or IDOR on node() | High |

## CVSS 3.1 Quick Reference

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## Kill-Fast Rules

1. 5-minute rule: can't fill Q1's template in 5 minutes → move on.
2. More than 2 simultaneous preconditions → kill it.
3. "What does the attacker walk away with?" — nothing tangible → kill it.
4. "Admin can do X" is never a bug → kill immediately.
5. Documented behavior → kill immediately.
6. 30+ minutes on Q6 with no reproducible PoC → kill it.

Anti-patterns that lose money: writing the report before confirming the bug; submitting theoretical impact; "the API returns more fields than necessary" (is the data actually sensitive?); merging two separate bugs into one report (two payouts lost); overclaiming severity (triagers trust you less next time); under-describing impact (triager doesn't see why it matters).
