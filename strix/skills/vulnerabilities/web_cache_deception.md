---
name: web-cache-deception
description: Web cache deception testing — tricking caches into storing authenticated user responses for attacker retrieval
---

# Web Cache Deception

Web Cache Deception (WCD) tricks a caching layer into storing a response containing sensitive, user-specific data, which an attacker then retrieves. It's the inverse of cache poisoning: instead of poisoning what other users receive, the attacker makes the cache store what the victim's session returns.

## Attack Surface

**Required Conditions**
1. App returns authenticated/sensitive content for URLs it doesn't recognize (often the "base" path is returned)
2. Cache stores responses based on URL path containing static-looking extensions or path segments
3. Attacker can trick victim into visiting a crafted URL (social engineering or stored link)

**Cache Layers**
- CDN (Cloudflare, Akamai, Fastly, CloudFront)
- Reverse proxy caches (Nginx, Varnish)
- Application-level caches
- Browser caches (less useful for WCD)

**Trigger Patterns**
- Appending fake static file extensions: `/account.php/nonexistent.css`
- Path parameter injection: `/profile;.js`
- URL delimiter confusion: `/account%0a.css`, `/account%23.css`
- Cached path segment: `/account/..%2Fstatic.css`

## Key Vulnerabilities

### Classic Path Confusion

App serves `/account/` content for unknown sub-paths, cache stores it as static:
```
# Attacker crafts URL:
https://target.com/account/sensitive.css

# App behavior: returns /account/ page with victim session data
# Cache behavior: sees .css extension → caches response

# Attacker later fetches same URL (unauthenticated):
GET /account/sensitive.css → Gets victim's account page from cache
```

### Delimiter Confusion

Different URL delimiters interpreted differently by cache vs. app:
```
# Cache normalizes ; as path separator, app sees it as extension start
/profile;.css        → Cache caches as CSS, app serves /profile
/dashboard%0a.jpg    → Cache path includes newline, app strips
/user%23.js          → Cache sees /user#.js, app serves /user
/api/v1%2f..%2faccount.css  → Path traversal after unescaping
```

**Cache-App Delimiter Differentials**
| Delimiter | Cache behavior | App behavior |
|-----------|---------------|--------------|
| `;` | Path separator | Ignored/stripped |
| `%0a` | Part of path | Strip/normalize |
| `%23` | Literal # | Fragment (ignored) |
| `%2f` | Literal slash | Decoded to `/` |
| `%09` | Tab in path | Stripped |

### Path Parameter Injection

```
/account/..;/static.css
/user/profile/../../../cache.png
/api/user/1.json%00.css
```

### Static Directory Poisoning

If authenticated pages are under `/app/` and `/static/` is cached:
```
/app/dashboard/../static/x.js  → App serves dashboard, cache stores as /static/x.js
```

### Unkeyed Headers Causing WCD

When `Vary` header is missing and the cache doesn't key on `Cookie`/`Authorization`:
```
GET /profile HTTP/1.1
Cookie: session=VICTIM_SESSION
# If cache doesn't key on Cookie, first response cached for all users
```

## Testing Methodology

1. **Identify cached endpoints** — Look for `Cache-Control: public`, `Age:` header, `X-Cache: HIT`, CDN headers
2. **Identify cacheable extensions** — `.css`, `.js`, `.png`, `.jpg`, `.ico`, `.woff`, `.svg`
3. **Test path confusion** — Append `/fake.css` to authenticated endpoints and check if cached
4. **Check cache keying** — Does the cache key include `Cookie` or `Authorization`? Test with `Vary` header
5. **Deliver to victim** — Trick victim into visiting crafted URL (via redirect, link in message)
6. **Fetch as attacker** — Request same URL without cookies → verify sensitive data returned
7. **Test delimiter variants** — `;`, `%0a`, `%23`, `%2f`, `%00`, `%09`, `%0d`
8. **Test path traversal** — `/../`, `/%2e%2e/`, `/%2f..%2f`

## Exploitation Flow

```
1. Find: GET /account/settings → Returns sensitive user data (authenticated)
2. Craft: GET /account/settings/nonexistent.css (victim visits this)
3. Cache stores the response keyed to /account/settings/nonexistent.css
4. Attacker fetches: GET /account/settings/nonexistent.css (no cookie)
5. Cache returns victim's settings page
```

### Delivery Mechanisms

- Email link / phishing
- XSS → `window.location` redirect to crafted URL
- Open redirect to crafted URL
- CSRF to force victim to load URL via `<img src=...>`
- Stored content (forums, comments, profiles with links)

## Bypass Techniques

**Cache Buster Avoidance**
- Don't add query params (they may be included in cache key)
- Use path-based variations, not query strings

**Extension Alternatives**
```
.css, .js, .png, .jpg, .gif, .ico, .svg, .woff, .woff2, .ttf, .eot
.json (sometimes cached), .xml, .txt, .pdf
```

**When Semicolons Are Blocked**
```
%3b = ;
%2f = /
%3f = ?
%23 = #
%00 = null byte
%0a = newline
```

## Cache Headers Reference

**Indicators of Caching**
```
Age: 42                     # Seconds since cached
X-Cache: HIT                # Cache hit
CF-Cache-Status: HIT        # Cloudflare
X-Varnish: 12345 67890      # Varnish (two IDs = hit)
Via: 1.1 varnish
```

**Cache Control Headers**
```
Cache-Control: no-store     # Should prevent caching
Cache-Control: private      # CDN shouldn't cache
Vary: Cookie                # Different response per cookie value
```

## Validation

1. Log in as victim, visit crafted URL (e.g., `/account/fake.css`)
2. Clear cookies / use incognito
3. Visit same URL unauthenticated → should return victim's data from cache
4. Confirm `X-Cache: HIT` or `Age: >0` in response headers
5. Show sensitive fields (email, PII, tokens) present in cached response

## False Positives

- Cache correctly keys on `Cookie` or `Authorization` header
- `Vary: Cookie` properly set → different cache entry per user
- `Cache-Control: no-store` or `private` enforced
- App returns 404 or error for unknown sub-paths (no content to cache)

## Impact

- Theft of session tokens, PII, private data from victim's authenticated responses
- Account takeover if session token is in cached response body
- GDPR/privacy violation via exposure of personal data

## Pro Tips

1. `Param Miner` Burp extension detects unkeyed inputs that can cause cache confusion
2. Check if CDN strips cookies before forwarding — if so, the whole site may be miscached
3. Try every path delimiter variant — `;` is the most common but `%0a` often works when `;` is blocked
4. Test on "profile", "account", "dashboard", "settings" endpoints specifically
5. Look for `Age: 0` on first hit then `Age: >0` on second — confirms caching
6. Some CDNs cache based on file extension in ANY path segment, not just the final one
7. Pair with XSS for reliable victim delivery without social engineering

## Summary

Web Cache Deception exploits mismatches between what the cache considers "static" and what the app actually serves. Any endpoint that returns sensitive data for unrecognized sub-paths, combined with a cache that stores by extension, is vulnerable. Fix by configuring caches to key on authentication headers and disabling caching for authenticated content.
