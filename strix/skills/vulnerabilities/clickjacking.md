---
name: clickjacking
description: Clickjacking testing covering UI redressing, frame embedding, and X-Frame-Options / CSP bypass techniques
---

# Clickjacking

Clickjacking (UI redressing) tricks users into clicking hidden or disguised UI elements by overlaying transparent iframes on top of legitimate pages.

## Attack Surface

**Targets**
- Pages that perform sensitive actions (fund transfers, account changes, password resets, OAuth authorization, social actions)
- Pages missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`

**Defenses to Bypass**
- `X-Frame-Options: DENY / SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none' / 'self'`
- Frame-busting JavaScript

## Testing Methodology

### Step 1 – Check Headers
```
curl -s -I https://target.com | grep -i "x-frame-options\|frame-ancestors"
```
Missing or misconfigured headers indicate framing is allowed.

### Step 2 – Attempt Embedding
```html
<iframe src="https://target.com/sensitive-action" width="800" height="600" style="opacity:0.0001"></iframe>
```
If the page renders inside the iframe, the site is vulnerable.

### Step 3 – Frame-Buster Bypass
If JavaScript frame-busting is used (e.g., `if (top !== self) top.location = self.location`):
- Use `sandbox` attribute to disable JS: `<iframe sandbox="allow-forms" src="...">`
- Double-framing technique to confuse legacy bust code

### Step 4 – Construct PoC
Create a minimal HTML page that overlays the victim page and demonstrates a click being captured on a hidden sensitive button.

## Common Vulnerable Endpoints

- `/settings` — account deletion or email change
- `/transfer` — financial or data operations
- `/oauth/authorize` — third-party authorization grant
- `/2fa/disable` — two-factor authentication removal
- Social actions: like, follow, share buttons

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Sensitive action completable in one click (no CSRF token required) | High |
| Multi-step action, partial automation possible | Medium |
| Cosmetic/low-impact action only | Low |

## Reporting

- Include PoC HTML
- Screenshot or video showing the overlaid UI
- Confirm action was completed without user awareness
- Note whether `X-Frame-Options` or `frame-ancestors` is absent

## Remediation

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```


## Additional Techniques — ported from WebSkills (writeup-techniques/clickjacking)

Distilled from an accepted-writeup corpus. Frame impact by what the coerced click *does*, not by "missing X-Frame-Options" alone — a missing header with no sensitive one-click action is routinely closed as informational.

### Prepopulate the framed form via GET params
If a page fills form fields from GET parameters, frame it with attacker-chosen values so the victim's single click submits them under their session:
```html
<iframe src="https://TARGET/account/email?new=attacker@evil.com"
        style="opacity:0;position:absolute;width:100%;height:100%"></iframe>
<button style="position:absolute;top:Ypx;left:Xpx">Continue</button>
```

### Drag-&-drop data injection into a framed input
When you can't make the victim *type* a value you control, make them *drag* it. A draggable decoy carries `text/plain` = your value; the framed input is the drop target:
```html
<div draggable="true"
     ondragstart="event.dataTransfer.setData('text/plain','attacker@evil.com')">
  Drag me to the box to continue
</div>
<iframe src="https://TARGET/form" style="opacity:0;position:absolute;..."></iframe>
```

### Multistep clickjacking
Walk the victim through several clicks, repositioning the decoy after each, to complete multi-page flows (OAuth Authorize → Confirm, settings → confirm-delete). An SVG-filter variant reads UI state (dialog visible, checkbox checked, success banner) to keep decoys synchronized across steps.

### Double-clickjacking (OAuth authorize, no iframe)
Newer class (WakaTime OAuth). Races the top-level window instead of framing: on the first click the attacker swaps/removes the top window (`window.open` a popup, then `window.close`), so the victim's **second** click of a rapid double-click lands on the underlying OAuth *Authorize* button. Defeats `X-Frame-Options`/`frame-ancestors` because no iframe is used.

### Popup-repositioning UI redress (cross-origin moveTo bypass)
Cross-origin `window.moveTo`/`resizeTo` is blocked, so: open the target in a popup, briefly navigate it to an attacker origin (same-origin → move allowed), `moveTo` it under the cursor, then redirect it back to the target so the next click hits the real button. Re-open with the same window *name* to foreground it without changing the URL.

### SVG-filter cross-origin iframe warping (no DOM access, no JS)
Chromium/WebKit/Gecko allow CSS `filter` (SVG `feImage`/`feColorMatrix`/`feComposite`/`feDisplacementMap`/`feTile`) on **cross-origin iframes**; the iframe's rasterized pixels feed the filter graph, warping the victim UI before it is seen:
- **Distort secrets into a CAPTCHA** — a framable endpoint rendering a token/reset-code/API-key is visually distorted to look like a CAPTCHA; the victim "solves" it by transcribing the real secret into an attacker input.
- **Recontextualize inputs** — matte out placeholder/validation text and overlay attacker labels while the hidden iframe still enforces the real origin's form.
- **Pixel probes / logic gates** — crop 2–4px regions, tile, threshold to booleans (dialog-visible, loaded, checkbox-checked, red-banner) to drive synchronized overlays through multi-step reset/approval/destructive-confirm flows — all without JavaScript.

### Clickjacking to trigger self-XSS
A self-XSS in private account details (only you can set/read) becomes a delivered XSS if the page is framable: clickjack the victim into clicking the control that fires it (api.tumblr.com → self DOM-XSS).

### Full-viewport iframe trap (keep victim inside, steal form data)
Load the whole target in a 100%-screen iframe; detect in-iframe navigation and rewrite the outer URL bar (History/Navigation API) to mimic real browsing. Steal keystrokes/credentials, localStorage, pages visited. Modern (2024+): go fullscreen to hide browser UI, draw a **fake address bar + padlock**, re-focus the iframe on `onmouseleave`, disable context menu/reload shortcuts. If CSP blocks inline JS, `sandbox` the iframe with a remote bootstrapper so the payload lives outside the parent CSP. Payment-skimmer variant overlays a pixel-perfect fake over a hosted Stripe/Adyen iframe and forwards keystrokes.

### Overlaid fake login (opaque top-layer div, no iframe)
No framing needed — an absolutely-positioned opaque `<div>` over the real page with a fake credential form, often delivered via a reflected param that injects the overlay into the trusted page:
```html
<div style="position:absolute;left:0;top:0;width:100%;height:100%;z-index:1000">
  ...attacker login form... </div>
```

### Sandboxed-iframe Basic-Auth dialog phishing
A `sandbox`ed iframe **without** `allow-popups` can still surface the browser's HTTP **Basic Auth** modal — it's spawned by the browser's networking/auth layer, not JS, so sandbox popup restrictions don't suppress it. Navigate a sandboxed iframe to a trusted-origin endpoint returning `401 WWW-Authenticate: Basic` → the browser (and stored password managers) prompt inside your widget.

### Browser-extension `web_accessible_resources` clickjacking
Extension HTML declared `web_accessible_resources` can be iframed by any page. PrivacyBadger (`skin/popup.html` → "Disable for this Website"), MetaMask (framable whitelist page → whitelist an attacker phishing site). Enumerate the extension's `web_accessible_resources` and iframe each HTML. Fix: remove the dir from `web_accessible_resources`.

### DOM-based extension clickjacking (password-manager autofill)
Target the autofill dropdown a password manager injects into the page DOM: (1) inject an invisible focusable login/PII/CC form; (2) focus an input to summon the dropdown; (3) occlude the extension UI while keeping it clickable; (4) align a believable control ("Accept cookies"/CAPTCHA) under it; (5) read filled values and exfiltrate.
```css
[is="extension-root"]{opacity:0 !important;}      /* hide dropdown root */
#cover{position:fixed;inset:0;pointer-events:none;} /* clicks pass through; keep in Top Layer via Popover API */
```
Follow-mouse: move the focused input under the cursor and refocus periodically so one click anywhere selects an item. Impact: CC + PII on attacker sites; on trusted sites with XSS/subdomain-takeover/cache-poisoning, username/password/TOTP (managers autofill across related subdomains); passkeys if the RP doesn't bind the WebAuthn challenge to the session.

### Tapjacking (Android overlay)
A malicious app draws an overlay and passes touches through to the background app. Request `SYSTEM_ALERT_WINDOW`, inflate a WebView with `TYPE_APPLICATION_OVERLAY`, flag it pass-through so real taps hit the underlying activity. Android 12+ "Block untrusted touches" drops overlays of opacity ≥0.8 — bypass by keeping the overlay fully transparent or only partially covering (target area left visible), or use accessibility/IME window types which still receive events (ToxicPanda/BrasDex/Sova).

### Additional defense bypasses seen
- **XFO/CSP absent on subresources & error pages** — images/text files opened via `<iframe>` render as HTML and often lack CSP/XFO; forced 4xx/5xx text/image error responses likewise ship without XFO and can even execute JS inside the frame.
- **CSP `frame-ancestors` partial-coverage bypass** — if only `X-Frame-Options` is set (or only CSP), pick the browser/path that ignores the one present; a variant host/path may lack the header entirely (OLX olx.co.za/olx.com.gh).
- **Top-Layer / Popover to beat z-index** — an overlay promoted to the Top Layer (Popover API) always sits above page stacking; `pointer-events:none` lets the click pass to the occluded real control.

### Sensitivity gate (kill weak reports) + provenance
Framing a static/marketing page with no state-changing single-click action is **N/A**; you must show a concrete sensitive one-click action (delete, transfer, authorize, disclose PII, trigger XSS). H1 triagers expect a **PoC video** for clickjacking. Corpus precedents to anchor severity/impact: Burp Scanner RCE-via-clickjacking ($3000), Twitter Periscope ($1120), wormable player-card, WordPress donation page, Viral DM → Google-cred + malicious-app install, Shipt admin-login, WakaTime double-clickjacking OAuth (→ATO), cards.twitter.com email-steal, vkpay transfer, tumblr clickjack→self-XSS, TikTok delete-developer-app ($500). Note the accountability angle: the request originates from the victim's authenticated browser, so server logs attribute the action to the victim.
