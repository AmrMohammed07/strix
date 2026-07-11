---
name: hunting-mindset
description: Attacker critical-thinking framework that feeds the think-tool before every testing decision — developer psychology, trust-boundary questioning, multi-perspective role matrix, What-If experiments, anomaly detection, and Low→Critical escalation decision trees. Use to decide WHAT to probe next and how to turn a weak finding into real impact.
---

# Hunting Mindset — What to Think Before Every Test

The orchestration engine (`root_agent.md`) and the scan modes tell you *when* to think. This file tells you *what* to think. Testing is not "find a bug" — it is "prove an attack scenario." Model the app like its developer did, then attack the shortcut they took.

---

## Question Trust Boundaries

Every client-side control is a suggestion, not an enforcement. For each one, send the request the UI would never send:

- Frontend disables a control? Send the request directly.
- `user_role=user` in a cookie/body? Set it to `admin`.
- `price=1000` in a POST? Set it to `1` or `-1`.
- `<script>` filtered? Try `<img onerror=...>`, `<svg onload=...>`.
- A field is hidden or read-only? It is still attacker-controlled on the wire.

Map where the app **stops trusting input** and where it **assumes input was already validated** upstream. Bugs live at that seam (gateway trusts app, app trusts gateway).

## Reverse-Engineer Developer Psychology

- Feature A has auth checks → a newer sibling feature B probably reuses the helper but forgot one check.
- Complex flows (coupon + points + refund, multi-step checkout) → edge cases were under-tested.
- `/api/v2/user` exists → does `/api/v1/user` still work with weaker auth?
- "Where would a tired developer at 2am skip a check, reuse a helper, or trust a client value?"
- **New == unreviewed.** Endpoints shipped recently have the lowest security maturity.
- **Follow the money.** Payments, billing, credits, refunds concentrate shortcuts.

## Multi-Perspective Role Matrix

Test the same endpoint from every identity — this is where authorization bugs surface:

| Perspective | What to check |
|---|---|
| Horizontal (same role) | User A's token + User B's object ID → IDOR/BOLA |
| Vertical (higher role) | Regular user → `/admin/deleteUser`, admin-only mutation |
| Data-flow (proxy view) | Hidden params in JSON: `debug`, `isAdmin`, `discount_rate` |
| Time / state | Race conditions, post-delete session reuse, stale token |
| Client environment | Mobile UA → older API version with weaker auth |
| Anonymous | The same authed request with the session stripped |

For access-control classes, always compare **two sessions** (low-priv A vs high-priv B) and diff which endpoints behave differently per identity.

## What-If Experiments (turn hypotheses into single requests)

- Skip checkout → hit `/checkout/success` directly.
- Skip MFA → navigate straight to `/dashboard` with the pre-MFA cookie.
- Send the same coupon/redeem request 20× simultaneously → race/double-spend.
- Replace `guid=f8a2…` with `id=100` on a sibling endpoint → IDOR via alternate reference.
- Every idea must become **one reproducible HTTP request** with an observable response diff — otherwise it stays a hypothesis, not a finding.

## Anomaly Detection (log why something "feels wrong")

- **Naming anomaly** — `userId` everywhere but suddenly `user_id` on one route → different dev, likely weaker checks.
- **Error diff** — same 403 but a different JSON shape → different backend/component.
- **200 but wrong body** — tiny/empty body or a "just a moment" page = a soft WAF block, not a real 200.
- **Timing diff** — `POST /check-user` returns 150ms (exists) vs 8ms (doesn't) → user enumeration side-channel.
- **Environment diff** — prod vs dev/staging: debug headers on, CSP disabled, verbose errors.
- **Version diff** — a JS bundle before/after a deploy reveals new endpoints and removed params.

## The A→B Signal: Cluster Hunting

When you confirm bug A, immediately hunt B and C in the same controller/module — the same developer made adjacent mistakes, and chains pay far more than singles.

```
1. CONFIRM A     verify with a real HTTP request
2. MAP SIBLINGS  every endpoint in the same controller/API group
3. TEST SIBLINGS apply the same pattern to each
4. CHAIN         combine A + a different-class sibling B
5. QUANTIFY      "affects N users" / "exposes $X" / "N records"
```

## Escalation Decision Trees (Low → Critical)

Never report a Low as-is if a documented escalation path exists — prove the chain end-to-end first.

```
XSS
 ├─ steal cookie/token?      -> session hijack -> ATO
 ├─ cookie HttpOnly?         -> force email change via XHR -> ATO
 └─ self-XSS only?           -> pair with login/CSRF to fire on victim
IDOR
 ├─ read PII?                -> automate scraping, show scale
 ├─ write/delete?            -> modify victim data -> High
 └─ UUID only?               -> find the UUID-leak source, then retry
SSRF
 ├─ DNS-only?                -> NOT a bug yet; reach cloud metadata
 ├─ 169.254.169.254?         -> exfil IAM keys -> Critical
 └─ internal port scan?      -> Redis/Docker/K8s -> RCE
Open redirect                -> OAuth redirect_uri accepts it -> code theft -> ATO
Host header injection        -> password-reset poisoning -> ATO
Subdomain takeover           -> registered OAuth redirect_uri / CSP entry -> Critical
Stack trace / debug endpoint -> leaked env/secret -> forge token / cloud creds
```

## Impact Gate (before you call anything a finding)

Ask: **"Can an attacker do this RIGHT NOW against a real user who took no unusual action — and does it cause real harm (stolen money, leaked PII, ATO, code execution)?"** If no, it is not a finding.

Kill these on sight (they waste the run): "could theoretically…", multi-precondition scenarios, wrong-but-harmless implementations, dead/unreachable code, DNS-only SSRF, open redirect alone, and any "could be chained if…" without the chain actually built.

## Anti-Patterns to Resist

- Rabbit-holing one parameter — cap it, rotate to the next endpoint/vuln class.
- Tool-only hunting — automation finds duplicates; manual reasoning finds unique bugs.
- Inflating confidence because a bug would be interesting — confidence tracks evidence, not appeal.
- Treating "I didn't find a check" as "there is no check" — search for the middleware/decorator/guard first.
