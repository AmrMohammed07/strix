---
name: password-spray
description: Password spraying and credential-stuffing methodology — when to spray vs web-vuln hunt, the company-wordlist + breach-ranking + OSINT-username pipeline, spray order and lockout-window math, success detection, legal/scope guardrails, and the spray → authenticated-hunt chain that turns a low-value ATO into a P1/P2
---

# Password Spray & Credential Attack

A parallel branch to web-vuln hunting, not a replacement — both run after recon. Humans pick lazy passwords (`{Company}{Year}!`, `{Product}{Season}`, `{City}123`), so harvesting company-specific vocabulary *before* spraying is what moves the hit-rate from ~0.01% to ~1%.

**Spray-only ATO is usually rejected by mature programs ("user's bad password, not our bug"). The payout is the chain: valid creds → authenticated re-hunt → IDOR/business-logic behind the login wall.**

## When to run (and when not to)
Run when: a real login surface exists (web form / O365 / Okta / OAuth), scope **explicitly permits** authentication/credential testing, and you can tolerate a 30-min-to-hours run at conservative rate.
Skip / KILL when: policy lists "credential stuffing", "brute force", or "password attacks" as out-of-scope (the majority — if silent, **assume disallowed and ask**); only third-party SSO you don't control; aggressive WAF/bot-management on every auth endpoint; an active red-team is engaged; or you have no clean wordlist yet (spraying `rockyou.txt` just burns lockouts).

## Pipeline (4 stages)
```
company wordlist ─▶ breach-rank ─▶ OSINT usernames ─▶ spray
```
1. **Company wordlist** — crawl the target site (CeWL / cewler; add JS-bundle words for SPAs), dedupe, then mutate with hashcat rules (`best66` for spray; `OneRuleToRuleThemAll` is for *offline cracking only*, too many candidates to spray). Use a strict filter on API-doc-heavy sites to drop CSS hex, URL slugs, and example API tokens.
2. **Breach-rank (HIBP k-anonymity)** — send only the first 5 SHA-1 chars; enrich each password with its real-world breach count. Free, no API key, full passwords never leave your machine. **Sweet spot = breach count 1–1000** (proven human use, not yet in every spray list). Drop `>1M` generic (`password`, `123456`) — every WAF expects those. **Never load plaintext breach corpora (DeHashed-style) against live accounts — illegal in most jurisdictions even in-scope; HIBP hash-prefix is the only clean leak source.**
3. **OSINT usernames** — theHarvester (search engines + CT logs) → derive names from email local-parts → username-anarchy permutations. LinkedIn dorking (CrossLinked) is opt-in — some programs forbid employee identification, check policy. CT-log hostnames are a bonus: feed them back into recon for more attack surface.
4. **Spray** — real auth attempts. See guards below.

## Spray order & lockout math (critical)
Spray **`pass[i] × all_users` per round**, never brute per-user:
```
WRONG (locks accounts):  alice: pass1,pass2,pass3...  → alice hits lockout in seconds
RIGHT (spreads failures): Round 1  pass1 → alice,bob,charlie   (1 fail each)
                          [delay]  Round 2  pass2 → alice,bob,charlie  (2 total each)
```
Typical lockout policies: Azure AD smart lockout (10 fails / 10-min sliding), Okta default (10 / 10 min), custom apps (usually 5–10 / hour). A conservative delay (~30 min/round + jitter) keeps every user at 0 strikes inside any sliding window. Fast spray (60s/round) needs explicit program permission and will usually trip O365 smart lockout.

## Success detection
- **HTTP form:** prefer an explicit `--fail-regex` (`Invalid|incorrect|wrong`) or `--success-regex`; a bare "3xx redirect = success" heuristic mis-fires on sites that always redirect.
- **OAuth password grant:** HTTP 200 + `access_token` in JSON = hit; 400 `invalid_grant` / 401 = fail (unambiguous).
- **O365 / Okta:** use a mature engine (TREVORspray) and parse its output.

## Hard guards
- Typed-hostname confirmation before firing (defeats wrong-target slips).
- Pre-flight lockout warning from `passes` count vs threshold.
- Append every attempt to an audit log; **log the password as a hash prefix, never plaintext.**
- Stop on first valid creds by default — that's testing, not grinding.
- If lockouts likely occurred, notify the program immediately with audit timestamps.

## The payout chain: spray → authenticated hunt
```
spray finds creds  ─▶  re-hunt with the session cookie / bearer token
                   ─▶  authenticated surface: admin pages, internal APIs, IDOR on user data
                   ─▶  P1/P2 IDOR or business-logic bug behind the wall
                   ─▶  chain report: "ATO via spray + IDOR exposes all user PII"
```

## Legal red lines (non-negotiable)
1. Never use plaintext breach passwords against live accounts — HIBP hash-prefix only.
2. Stop on first valid creds; don't grind for multiple hits.
3. Proactively disclose any lockouts with audit timestamps.

## Related
- `authentication.md` — login bypass, rate-limit/brute-force testing
- `rate_limit_bypass.md` — bypassing per-IP throttles during spray
- `account_takeover.md` — chaining spray-found creds into full ATO
