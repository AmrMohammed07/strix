---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# Information Disclosure

## Real Impact Gate — Severity Classification

**Information disclosure severity depends entirely on what was disclosed and whether it enables further exploitation.**

| Finding | Severity | Condition |
|---------|----------|-----------|
| Source code exposed (/.git/config + git dump) | High/Critical | Actual source code with credentials/logic retrieved |
| .env file exposed with real credentials | Critical | Credentials enable further access — verify they work |
| Stack trace revealing internal paths | Low/Informational | Interesting but limited exploitability alone |
| Server version in header | Informational | Only relevant if the version has a known exploitable CVE |
| phpinfo() exposed | Medium | Reveals configuration details that aid further attacks |
| Debug endpoint with sensitive data | High | Only if sensitive data is actually present |
| API key in JS bundle — verify it's active | High | Verify the key actually grants access before reporting |
| Error message revealing SQL syntax | Low | Useful for confirming SQLi injection point — report as SQLi if exploited |
| Internal IP address in response | Low/Informational | Only if it enables further attack |

**DO NOT report server version in X-Powered-By header as a vulnerability unless that exact version has an actively exploitable known CVE.**
**DO NOT report generic stack traces without demonstrating what the trace enables.**
**DO verify any exposed credentials/API keys are actually active before reporting — expired/revoked keys are Informational only.**

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Testing Methodology

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.


## Additional Techniques — ported from WebSkills (writeup-techniques/info-disclosure)

### App-server source read via path normalization (WEB-INF / servlet source)
Read `WEB-INF/web.xml` (DB creds, servlet mappings, hidden admin paths) and raw servlet/CGI source by abusing path-normalization quirks — distinct from DVCS/backup artifact dumping.
```
GET /%2e/WEB-INF/web.xml HTTP/1.1                                   # Jetty CVE-2021-28164
/resin-doc/viewfile/?contextpath=/&servletpath=&file=WEB-INF/web.xml # Caucho Resin
<script>.cgi%3F                                                     # Apache CGI source disclosure (append %3F)
/cgi-bin/pdesk.cgi?lang=../../../../../../proc/version%00           # null-byte legacy source read
```

### TRACE / method-override to leak proxy-injected internal headers
Reverse proxies append internal auth headers that echo back in a TRACE response — not covered by the fork's header-fingerprinting section.
```
TRACE / HTTP/1.1        # echoes request incl. internal headers the proxy added
# also try: OPTIONS, X-HTTP-Method-Override when GET is filtered
```

### Adobe AEM disclosure surface
```
/crx/de                 /bin/querybuilder.json     /system/console
```
`QueryBuilder` / DefaultGetServlet dump the JCR tree, users, and paths. Dispatcher blocks `/crx` etc. → bypass with `;`-tricks / extension confusion to reach the servlet.

### Sentry instance misconfig
Public Sentry instance/issues leak source, DSN, and env vars; Sentry can also be a blind-SSRF pivot (NordVPN). Distinct third-party surface not in fork.

### Jira user-enumeration CVEs (concrete endpoints)
```
GET /rest/api/latest/groupuserpicker?query=admin     # CVE-2019-8449
POST /secure/QueryComponent!Jql.jspa                  # Jira 8.11–8.15, CVE-2020-14181
```

### Supabase frontend-key exposure → total RLS bypass
A `service_role` key (or `JWT_SECRET`) shipped in frontend JS bypasses ALL Row-Level Security → full DB read/write and forge any user's token. Also `PUBLIC_BUCKET` / `STORAGE_NO_RLS` storage misconfig. Higher-impact than a generic leaked API key.

### Product-specific debug endpoints
```
awstats.pl?debug=1        (AWStats)
/cutenews/index.php?debug (CuteNews → phpinfo dump)
/webcgi/webbatch.exe?dumpinputdata
?debug   ?debug=1   ?debug=2
```

### GitLab `secret_key_base` disclosure → session/cookie forgery
`secret_key_base` leaked via crafted encoding chars ($3500) lets an attacker forge signed session cookies / signed tokens — a specific secret→ATO chain beyond generic "key → cloud access."

### Disclosure-specific filter/WAF bypass bank
For reaching blocked internal/config paths and dodging extension filters:
```
..;/    %2e%2e/    trailing %3F    %00 (null byte)
case / extension variation: .ENV  %2egit  file.php.bak  file.php~  file.php.swp
HTTP method swap when GET filtered: TRACE / OPTIONS / DEBUG / X-HTTP-Method-Override
```

### Diff-based confirmation (avoid custom-404 false positives)
Request a known-nonexistent path vs the target file; `200` + real content (not the styled 404 body) confirms exposure. For `.git`, confirm `/.git/HEAD` returns `ref: refs/heads/…` before claiming a dump.

### Client-side / deeplink / Wayback-archived-token leaks
Insecure deeplinks return PII directly (Grab), path-traversal in a deeplink query reaches private info (Basecamp), and Wayback/CDN-cached responses preserve one-time tokens (Omise email-confirmation token via Wayback) — an archival channel that widens exposure even after the app is fixed.
