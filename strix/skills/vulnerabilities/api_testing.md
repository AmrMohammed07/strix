# API Security Testing

## Overview
Comprehensive API security testing methodology covering REST, GraphQL, WebSocket, and other API types.

## API Discovery
```
# Common API paths
/api/v1/, /api/v2/, /v1/, /v2/, /rest/, /service/
/api/, /api/docs, /api/swagger, /api/openapi
/.well-known/, /graphql, /graphql/playground

# Swagger/OpenAPI discovery
/swagger.json, /swagger.yaml, /openapi.json, /openapi.yaml
/swagger-ui.html, /api-docs, /docs/api

# JavaScript analysis for API endpoints
grep -E "(api|endpoint|url|path|route)" app.js
```

## Authentication Testing
```
# Test without auth token
# Test with invalid token
# Test with expired token
# Test with token from different user
# Test with empty Authorization header
Authorization: Bearer 
Authorization: Bearer null
Authorization: Bearer undefined

# Token in wrong location
# If token in header, try in query: ?token=...
# If token in cookie, try in header

# JWT-specific: see jwt.md
```

## Authorization Testing (IDOR)
```
# Horizontal privilege escalation
GET /api/users/123/profile → change to /api/users/124/profile
GET /api/orders/ABC123 → enumerate other orders

# Vertical privilege escalation
GET /api/user/settings → try /api/admin/settings
POST /api/user/update → try /api/admin/update

# HTTP method tampering
GET /api/resource/1 (allowed) → POST /api/resource/1 (should be restricted)
```

## Input Validation
```
# Injection in all parameters
# SQL injection in IDs: id=1' or 1=1--
# NoSQL injection: id[$ne]=null
# Command injection: name=test;id
# XSS in string fields
# Path traversal: path=../../etc/passwd

# Type confusion
# String where integer expected: id="abc"
# Negative values: quantity=-1, amount=-100
# Zero values: price=0
# Very large values: 999999999999
```

## REST API Specific Tests
```
# HTTP Methods
OPTIONS /api/resource → lists allowed methods
# Test all methods: GET, POST, PUT, PATCH, DELETE, HEAD, TRACE, CONNECT

# Status code testing
# 200 vs 403 vs 404 reveals existence of resource
# 401 vs 403: 401 = not authenticated, 403 = not authorized

# Content negotiation
Content-Type: application/json → try application/xml, text/html
Accept: application/json → try application/xml

# Versioning attacks
/api/v1/ vs /api/v2/ → old version may lack security controls
```

## Mass Assignment
```
# Add privileged fields to POST/PUT/PATCH body
{"username": "user", "role": "admin"}
{"email": "user@x.com", "isAdmin": true, "isPremium": true}
{"amount": 100, "discount": 99}

# JSON parameter pollution
{"id":1,"id":2}  # which takes precedence?
```

## Rate Limiting
```
# Test all endpoints for rate limiting
# Authentication endpoint (login, register, reset)
# API endpoint limits (requests/minute/hour)
# See rate_limit_bypass.md
```

## API Versioning Abuse
```
# Old API versions often less secured
# Try: v1, v2, v3... and internal versions
/api/v1/admin → /api/v0/admin (older, less restrictive?)
/api/internal/admin
/api/beta/admin
```

## GraphQL Testing
```
# See protocols/graphql.md for detailed GraphQL testing
# Quick tests:
# Introspection: {"query":"{__schema{types{name}}}"}
# Batch queries for rate limit bypass
# Nested queries for DoS
```

## Error Message Analysis
```
# Extract information from error messages
# Stack traces, database errors, file paths
# Internal service names, versions
# SQL queries in error messages

# Test with:
- Invalid data types
- Null/empty values
- Very long inputs
- Special characters
```

## CORS Testing
```
# See cors_misconfiguration.md
# Quick test: add Origin: https://attacker.com
# Check: Access-Control-Allow-Origin header in response
# Check: Access-Control-Allow-Credentials: true
```

## API Key Testing
```
# Check if API key is truly required
# Test with expired/invalid keys
# Test key rotation (old key still works?)
# Check key scope (does user key work for admin endpoints?)
# Test key in different locations: header, query param, body
```

## Pagination & Data Exposure
```
# Over-fetching: request all records
?limit=99999&offset=0
?page_size=1000

# Negative pagination
?limit=-1&offset=-1
?page=-1

# Check if sorting/filtering exposes hidden fields
?sort=secret_field
?filter[secret]=value
```

## Testing Methodology
1. Map all API endpoints (from JS, Swagger, responses)
2. Test authentication on each endpoint
3. Test authorization (IDOR) on each endpoint
4. Test HTTP methods on each endpoint
5. Inject in all parameters
6. Test mass assignment
7. Check CORS configuration
8. Test rate limiting
9. Analyze error messages
10. Test API versioning

## Tools
- Postman / Insomnia for manual testing
- `ffuf` for endpoint fuzzing
- Burp Suite for interception and scanning
- `arjun` for parameter discovery
- `kiterunner` for API wordlist scanning
