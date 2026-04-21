package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse

/**
 * Analyzes responses to detect successful vulnerability exploitation
 * STRICT validation to minimize false positives
 */
class ResponseAnalyzer {
    // Minimum confidence thresholds
    companion object {
        const val MIN_CONFIDENCE_TO_REPORT = 85
        const val HIGH_CONFIDENCE = 95
        const val MEDIUM_CONFIDENCE = 85
    }

    // STRICT detection patterns - must be unambiguous indicators
    private val errorPatterns: Map<VulnClass, List<ErrorPattern>> =
        mapOf(
            VulnClass.SQLI to
                listOf(
                    // MySQL - very specific patterns
                    ErrorPattern(Regex("You have an error in your SQL syntax", RegexOption.IGNORE_CASE), 95, "MySQL syntax error"),
                    ErrorPattern(
                        Regex("check the manual that corresponds to your (MySQL|MariaDB) server version", RegexOption.IGNORE_CASE),
                        95,
                        "MySQL version error",
                    ),
                    ErrorPattern(Regex("Warning.*mysql_.*query", RegexOption.IGNORE_CASE), 90, "PHP MySQL warning"),
                    ErrorPattern(Regex("mysql_fetch_(array|assoc|row)", RegexOption.IGNORE_CASE), 85, "PHP MySQL function error"),
                    // PostgreSQL
                    ErrorPattern(Regex("ERROR:\\s+syntax error at or near", RegexOption.IGNORE_CASE), 95, "PostgreSQL syntax error"),
                    ErrorPattern(Regex("pg_query\\(\\).*failed", RegexOption.IGNORE_CASE), 90, "PHP PostgreSQL error"),
                    // SQL Server
                    ErrorPattern(
                        Regex("Unclosed quotation mark after the character string", RegexOption.IGNORE_CASE),
                        95,
                        "MSSQL unclosed quote",
                    ),
                    ErrorPattern(Regex("Incorrect syntax near", RegexOption.IGNORE_CASE), 90, "MSSQL syntax error"),
                    ErrorPattern(Regex("ODBC SQL Server Driver", RegexOption.IGNORE_CASE), 85, "MSSQL ODBC error"),
                    // Oracle
                    ErrorPattern(Regex("ORA-0[0-9]{4}:", RegexOption.IGNORE_CASE), 95, "Oracle error code"),
                    ErrorPattern(Regex("PLS-[0-9]{5}:", RegexOption.IGNORE_CASE), 95, "Oracle PL/SQL error"),
                    // SQLite
                    ErrorPattern(Regex("SQLITE_ERROR", RegexOption.IGNORE_CASE), 90, "SQLite error"),
                    ErrorPattern(Regex("near \".*\": syntax error", RegexOption.IGNORE_CASE), 90, "SQLite syntax error"),
                ),
            VulnClass.LFI to
                listOf(
                    // Must match actual file content patterns, not just keywords
                    ErrorPattern(Regex("root:x:0:0:root:/root:", RegexOption.IGNORE_CASE), 95, "/etc/passwd content"),
                    ErrorPattern(Regex("daemon:x:\\d+:\\d+:daemon:/", RegexOption.IGNORE_CASE), 90, "/etc/passwd daemon"),
                    ErrorPattern(Regex("nobody:x:\\d+:\\d+:nobody:", RegexOption.IGNORE_CASE), 90, "/etc/passwd nobody"),
                    ErrorPattern(Regex("\\[boot loader\\]\\s*\\n.*timeout=", RegexOption.IGNORE_CASE), 95, "boot.ini content"),
                    ErrorPattern(Regex("\\[fonts\\]\\s*\\n", RegexOption.IGNORE_CASE), 90, "win.ini [fonts]"),
                    ErrorPattern(Regex("; for 16-bit app support\\s*\\n\\["), 95, "win.ini header"),
                ),
            VulnClass.CMDI to
                listOf(
                    // Very specific command output patterns
                    ErrorPattern(Regex("uid=\\d+\\([a-zA-Z0-9_-]+\\)\\s+gid=\\d+\\([a-zA-Z0-9_-]+\\)"), 95, "id command output"),
                    ErrorPattern(Regex("^[a-zA-Z]+\\\\[a-zA-Z0-9_-]+$", RegexOption.MULTILINE), 85, "whoami output"),
                    // Avoid false positives from normal content
                ),
            VulnClass.SSTI to
                listOf(
                    // Only match if 49 appears where it shouldn't (not in normal content)
                    ErrorPattern(Regex("TemplateError", RegexOption.IGNORE_CASE), 85, "Template error"),
                    ErrorPattern(Regex("jinja2\\.exceptions", RegexOption.IGNORE_CASE), 95, "Jinja2 exception"),
                    ErrorPattern(Regex("mako\\.exceptions\\.RuntimeException", RegexOption.IGNORE_CASE), 95, "Mako exception"),
                    ErrorPattern(Regex("freemarker\\.core\\.[A-Z]", RegexOption.IGNORE_CASE), 95, "Freemarker error"),
                    ErrorPattern(Regex("Velocity\\s+Runtime\\s+Exception", RegexOption.IGNORE_CASE), 95, "Velocity error"),
                ),
            VulnClass.XXE to
                listOf(
                    ErrorPattern(Regex("root:x:0:0:root:/root:", RegexOption.IGNORE_CASE), 95, "XXE file read"),
                    ErrorPattern(Regex("DOCTYPE.*ENTITY.*SYSTEM", RegexOption.IGNORE_CASE), 70, "XXE syntax detected"),
                ),
            // ===== A02: Security Misconfiguration =====
            VulnClass.STACK_TRACE_EXPOSURE to
                listOf(
                    // Java
                    ErrorPattern(
                        Regex("at\\s+[a-zA-Z0-9_.]+\\([a-zA-Z0-9_.]+\\.java:\\d+\\)", RegexOption.IGNORE_CASE),
                        90,
                        "Java stack trace",
                    ),
                    ErrorPattern(
                        Regex("java\\.lang\\.(NullPointerException|Exception|RuntimeException)", RegexOption.IGNORE_CASE),
                        90,
                        "Java exception",
                    ),
                    // Python
                    ErrorPattern(Regex("Traceback \\(most recent call last\\)", RegexOption.IGNORE_CASE), 95, "Python traceback"),
                    ErrorPattern(Regex("File \".*\\.py\", line \\d+", RegexOption.IGNORE_CASE), 90, "Python file reference"),
                    // .NET
                    ErrorPattern(
                        Regex("at\\s+[a-zA-Z0-9_.]+\\s+in\\s+.*\\.cs:line\\s+\\d+", RegexOption.IGNORE_CASE),
                        90,
                        ".NET stack trace",
                    ),
                    ErrorPattern(Regex("System\\.(Web|Data|IO)\\.[A-Z][a-zA-Z]+Exception", RegexOption.IGNORE_CASE), 90, ".NET exception"),
                    // PHP
                    ErrorPattern(
                        Regex("Fatal error:.*in\\s+/.*\\.php\\s+on\\s+line\\s+\\d+", RegexOption.IGNORE_CASE),
                        95,
                        "PHP fatal error",
                    ),
                    ErrorPattern(Regex("Stack trace:.*#\\d+\\s+/.*\\.php\\(\\d+\\)", RegexOption.IGNORE_CASE), 90, "PHP stack trace"),
                    // Node.js
                    ErrorPattern(
                        Regex("at\\s+[a-zA-Z0-9_$.]+\\s+\\(.*\\.js:\\d+:\\d+\\)", RegexOption.IGNORE_CASE),
                        90,
                        "Node.js stack trace",
                    ),
                ),
            VulnClass.VERSION_DISCLOSURE to
                listOf(
                    // Server versions
                    ErrorPattern(Regex("Server:\\s*(Apache|nginx|IIS)/[0-9.]+", RegexOption.IGNORE_CASE), 85, "Server version"),
                    ErrorPattern(
                        Regex("X-Powered-By:\\s*(PHP|ASP\\.NET|Express)/[0-9.]+", RegexOption.IGNORE_CASE),
                        85,
                        "Framework version",
                    ),
                    ErrorPattern(Regex("X-AspNet-Version:\\s*[0-9.]+", RegexOption.IGNORE_CASE), 85, "ASP.NET version"),
                ),
            VulnClass.VERBOSE_ERROR to
                listOf(
                    ErrorPattern(Regex("ODBC.*Driver", RegexOption.IGNORE_CASE), 85, "ODBC driver error"),
                    ErrorPattern(Regex("Microsoft.*SQL.*Server", RegexOption.IGNORE_CASE), 85, "SQL Server error"),
                    ErrorPattern(Regex("supplied argument is not a valid", RegexOption.IGNORE_CASE), 85, "PHP type error"),
                    ErrorPattern(Regex("mysql_connect\\(\\):.*denied", RegexOption.IGNORE_CASE), 90, "MySQL connection error"),
                ),
            VulnClass.DEBUG_ENDPOINT to
                listOf(
                    ErrorPattern(Regex("Django Debug Toolbar", RegexOption.IGNORE_CASE), 95, "Django debug"),
                    ErrorPattern(Regex("Whoops!.*There was an error", RegexOption.IGNORE_CASE), 90, "Laravel debug"),
                    ErrorPattern(Regex("phpinfo\\(\\)", RegexOption.IGNORE_CASE), 95, "PHP info exposed"),
                    ErrorPattern(Regex("Spring Boot Actuator", RegexOption.IGNORE_CASE), 90, "Spring actuator"),
                ),
            // ===== A05: More Injection Types =====
            VulnClass.NOSQL_INJECTION to
                listOf(
                    ErrorPattern(Regex("MongoError", RegexOption.IGNORE_CASE), 90, "MongoDB error"),
                    ErrorPattern(Regex("CastError.*ObjectId", RegexOption.IGNORE_CASE), 85, "MongoDB cast error"),
                    ErrorPattern(Regex("\\\$where.*disallowed", RegexOption.IGNORE_CASE), 85, "MongoDB \$where blocked"),
                ),
            VulnClass.GRAPHQL_INJECTION to
                listOf(
                    ErrorPattern(Regex("\"__schema\"", RegexOption.IGNORE_CASE), 90, "GraphQL schema exposed"),
                    ErrorPattern(Regex("\"__typename\"", RegexOption.IGNORE_CASE), 85, "GraphQL typename"),
                    ErrorPattern(Regex("\"queryType\".*\"fields\"", RegexOption.IGNORE_CASE), 90, "GraphQL introspection"),
                ),
            // ===== Host Header Injection =====
            VulnClass.HOST_HEADER_INJECTION to
                listOf(
                    ErrorPattern(Regex("evil-burp-ai-test\\.com", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Injected host reflected"),
                ),
            // ===== Git Exposure =====
            VulnClass.GIT_EXPOSURE to
                listOf(
                    ErrorPattern(Regex("ref:\\s*refs/heads/", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Git HEAD content"),
                    ErrorPattern(
                        Regex("\\[core\\]\\s*\\n.*repositoryformatversion", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Git config",
                    ),
                    ErrorPattern(Regex("^DIRC", RegexOption.MULTILINE), 90, "Git index signature"),
                ),
            // ===== Backup Disclosure =====
            VulnClass.BACKUP_DISCLOSURE to
                listOf(
                    // Look for source code patterns in backup files
                    ErrorPattern(
                        Regex("^\\s*<\\?php|^\\s*<\\?=", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)),
                        90,
                        "PHP source code",
                    ),
                    ErrorPattern(
                        Regex(
                            "^\\s*(from\\s+[a-zA-Z]+\\s+import|import\\s+[a-zA-Z])",
                            setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                        ),
                        85,
                        "Python source",
                    ),
                    ErrorPattern(
                        Regex(
                            "^\\s*(public\\s+class|private\\s+void|package\\s+[a-z])",
                            setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                        ),
                        85,
                        "Java source",
                    ),
                ),
            // ===== Debug Exposure =====
            VulnClass.DEBUG_EXPOSURE to
                listOf(
                    ErrorPattern(Regex("actuator|management\\.endpoints", RegexOption.IGNORE_CASE), 90, "Spring Actuator"),
                    ErrorPattern(Regex("_profiler|symfony.*debug", RegexOption.IGNORE_CASE), 90, "Symfony Profiler"),
                    ErrorPattern(Regex("telescope.*dashboard|laravel.*telescope", RegexOption.IGNORE_CASE), 90, "Laravel Telescope"),
                    ErrorPattern(
                        Regex("phpinfo\\(\\)|PHP Version|Configuration.*PHP", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "PHP Info",
                    ),
                    ErrorPattern(Regex("ELMAH.*Error|elmah\\.axd", RegexOption.IGNORE_CASE), 90, "ELMAH errors"),
                    ErrorPattern(Regex("Werkzeug.*Debugger|flask.*debug", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Flask Debug"),
                ),
            // ===== Subdomain Takeover Indicators =====
            VulnClass.SUBDOMAIN_TAKEOVER to
                listOf(
                    ErrorPattern(
                        Regex("There isn't a GitHub Pages site here", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "GitHub Pages unclaimed",
                    ),
                    ErrorPattern(
                        Regex("NoSuchBucket|The specified bucket does not exist", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "S3 bucket unclaimed",
                    ),
                    ErrorPattern(Regex("Heroku \\| No such app", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Heroku unclaimed"),
                    ErrorPattern(Regex("Domain not configured|Repository not found", RegexOption.IGNORE_CASE), 90, "Unclaimed resource"),
                    ErrorPattern(Regex("NXDOMAIN|Name or service not known", RegexOption.IGNORE_CASE), 85, "DNS not resolving"),
                    ErrorPattern(
                        Regex("The request could not be satisfied.*CloudFront", RegexOption.IGNORE_CASE),
                        90,
                        "CloudFront unclaimed",
                    ),
                    ErrorPattern(
                        Regex("Sorry, this shop is currently unavailable.*Shopify", RegexOption.IGNORE_CASE),
                        90,
                        "Shopify unclaimed",
                    ),
                ),
            // ===== S3/Cloud Misconfiguration =====
            VulnClass.S3_MISCONFIGURATION to
                listOf(
                    ErrorPattern(
                        Regex("ListBucketResult|<Contents>.*<Key>", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "S3 bucket listing",
                    ),
                    ErrorPattern(Regex("AccessControlPolicy|<Grant>|<Grantee>", RegexOption.IGNORE_CASE), 90, "S3 ACL exposed"),
                    ErrorPattern(Regex("BlobNotFound|ContainerNotFound", RegexOption.IGNORE_CASE), 85, "Azure blob error"),
                ),
            // ===== Cache Poisoning =====
            VulnClass.CACHE_POISONING to
                listOf(
                    ErrorPattern(
                        Regex("evil-burp-ai-cache\\.com", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Poisoned host in cached response",
                    ),
                ),
            // ===== Source Map Disclosure =====
            VulnClass.SOURCEMAP_DISCLOSURE to
                listOf(
                    ErrorPattern(
                        Regex("\"sources\":\\s*\\[.*\\.js\"|\"mappings\":", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Source map content",
                    ),
                    ErrorPattern(Regex("//[#@]\\s*sourceMappingURL=", RegexOption.IGNORE_CASE), 90, "Source map reference"),
                ),
            // ===== OAuth Misconfiguration =====
            VulnClass.OAUTH_MISCONFIGURATION to
                listOf(
                    ErrorPattern(
                        Regex("redirect_uri.*evil-burp-ai\\.com", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "OAuth redirect bypass",
                    ),
                    ErrorPattern(Regex("access_token.*[a-zA-Z0-9_-]{20,}", RegexOption.IGNORE_CASE), 90, "Token in URL/referrer"),
                ),
        )

    // Strict success patterns for exploits
    private val successPatterns: Map<VulnClass, List<SuccessPattern>> =
        mapOf(
            VulnClass.XSS_REFLECTED to
                listOf(
                    // Use our unique marker to avoid false positives
                    SuccessPattern(
                        Regex("<script[^>]*>\\s*alert\\s*\\(\\s*['\"]?XSS-BURP-AI-1337['\"]?\\s*\\)\\s*</script>", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Script tag with unique marker",
                    ),
                    SuccessPattern(
                        Regex(
                            "<[a-z]+[^>]+on(error|load|click|mouseover)\\s*=\\s*['\"]?alert\\s*\\(['\"]?XSS-BURP-AI-1337",
                            RegexOption.IGNORE_CASE,
                        ),
                        HIGH_CONFIDENCE,
                        "Event handler with unique marker",
                    ),
                    SuccessPattern(
                        Regex("<svg[^>]+onload\\s*=\\s*['\"]?alert\\(['\"]?XSS-BURP-AI-1337", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "SVG onload with marker",
                    ),
                    SuccessPattern(
                        Regex("<img[^>]+onerror\\s*=\\s*['\"]?alert\\(['\"]?XSS-BURP-AI-1337", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "IMG onerror with marker",
                    ),
                    // Generic patterns for manual payloads - LOWER confidence to reduce FPs
                    // alert(1) can match legitimate JS code, so keep below threshold unless confirmed manually
                    SuccessPattern(
                        Regex("<script[^>]*>\\s*alert\\s*\\(\\s*['\"]?1['\"]?\\s*\\)\\s*</script>", RegexOption.IGNORE_CASE),
                        75,
                        "Script tag with alert(1) - needs manual verification",
                    ),
                ),
            VulnClass.XSS_DOM to
                listOf(
                    SuccessPattern(
                        Regex("DOM-XSS-BURP-AI", RegexOption.IGNORE_CASE),
                        90,
                        "DOM XSS marker reflected",
                    ),
                ),
            VulnClass.OPEN_REDIRECT to
                listOf(
                    // Must be in Location header, not just body content
                    SuccessPattern(
                        Regex("^Location:\\s*(https?:)?//evil\\.com", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        95,
                        "Redirect to evil.com",
                    ),
                ),
            VulnClass.HEADER_INJECTION to
                listOf(
                    SuccessPattern(
                        Regex("^X-Injected:\\s*burp-ai-test", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        HIGH_CONFIDENCE,
                        "Injected header",
                    ),
                ),
            VulnClass.CRLF_INJECTION to
                listOf(
                    SuccessPattern(
                        Regex("^Set-Cookie:\\s*burp-ai-test=true", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        HIGH_CONFIDENCE,
                        "CRLF cookie injection",
                    ),
                ),
            VulnClass.SSRF to
                listOf(
                    // Very specific cloud metadata patterns
                    SuccessPattern(Regex("ami-[a-f0-9]{8,17}", RegexOption.IGNORE_CASE), 95, "AWS AMI ID"),
                    SuccessPattern(Regex("i-[a-f0-9]{8,17}", RegexOption.IGNORE_CASE), 90, "AWS Instance ID"),
                    SuccessPattern(Regex("arn:aws:[a-z]+:", RegexOption.IGNORE_CASE), 95, "AWS ARN"),
                    SuccessPattern(Regex("projects/\\d+/", RegexOption.IGNORE_CASE), 85, "GCP project"),
                    SuccessPattern(Regex("root:x:0:0:root:/root:", RegexOption.IGNORE_CASE), 95, "File read via SSRF"),
                ),
            // ===== A01: CORS Misconfiguration =====
            VulnClass.CORS_MISCONFIGURATION to
                listOf(
                    SuccessPattern(
                        Regex("^Access-Control-Allow-Origin:\\s*\\*", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        85,
                        "ACAO wildcard",
                    ),
                    SuccessPattern(
                        Regex(
                            "^Access-Control-Allow-Origin:\\s*https?://evil\\.com",
                            setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE),
                        ),
                        HIGH_CONFIDENCE,
                        "ACAO reflects evil.com",
                    ),
                    SuccessPattern(
                        Regex("^Access-Control-Allow-Origin:\\s*null", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        90,
                        "ACAO null",
                    ),
                    SuccessPattern(
                        Regex("^Access-Control-Allow-Credentials:\\s*true", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        85,
                        "Credentials allowed",
                    ),
                ),
            // ===== A02: Missing Security Headers =====
            VulnClass.MISSING_SECURITY_HEADERS to
                listOf(
                    // Negative patterns - absence of headers is the vulnerability
                    // This is handled differently in passive analysis
                ),
            // ===== A04: Insecure Cookies =====
            VulnClass.INSECURE_COOKIE to
                listOf(
                    // Session cookies without Secure/HttpOnly
                    // Detected in passive analysis by examining Set-Cookie headers
                ),
            // ===== Directory Listing =====
            VulnClass.DIRECTORY_LISTING to
                listOf(
                    SuccessPattern(Regex("Index of /", RegexOption.IGNORE_CASE), 90, "Apache directory listing"),
                    SuccessPattern(Regex("<title>Directory listing for", RegexOption.IGNORE_CASE), 90, "Python directory listing"),
                    SuccessPattern(Regex("\\[To Parent Directory\\]", RegexOption.IGNORE_CASE), 90, "IIS directory listing"),
                    SuccessPattern(Regex("<h1>Directory listing of", RegexOption.IGNORE_CASE), 90, "Generic directory listing"),
                ),
            // ===== Host Header Injection =====
            VulnClass.HOST_HEADER_INJECTION to
                listOf(
                    SuccessPattern(Regex("evil-burp-ai-test\\.com", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Injected host in response"),
                    SuccessPattern(
                        Regex("localhost[^a-zA-Z].*reset|password.*localhost", RegexOption.IGNORE_CASE),
                        90,
                        "Localhost in password reset",
                    ),
                ),
            // ===== Cache Poisoning =====
            VulnClass.CACHE_POISONING to
                listOf(
                    SuccessPattern(Regex("evil-burp-ai-cache\\.com", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Injected host cached"),
                    // Check for cache headers indicating response was cached
                    SuccessPattern(
                        Regex("^X-Cache:\\s*(HIT|hit)", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        85,
                        "Response cached",
                    ),
                ),
            // ===== Cache Deception =====
            VulnClass.CACHE_DECEPTION to
                listOf(
                    // Look for sensitive data in responses with static extensions
                    SuccessPattern(
                        Regex("email.*@|password|credit.*card|ssn|api.*key", RegexOption.IGNORE_CASE),
                        85,
                        "Sensitive data potentially cached",
                    ),
                ),
            // ===== Git Exposure =====
            VulnClass.GIT_EXPOSURE to
                listOf(
                    SuccessPattern(
                        Regex("ref:\\s*refs/heads/(main|master|develop)", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Git HEAD file",
                    ),
                    SuccessPattern(
                        Regex("\\[core\\]\\s*\\n\\s*repositoryformatversion", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Git config",
                    ),
                    SuccessPattern(
                        Regex("\\[remote\\s+\"origin\"\\]\\s*\\n\\s*url\\s*=", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Git remote config",
                    ),
                ),
            // ===== Backup Disclosure =====
            VulnClass.BACKUP_DISCLOSURE to
                listOf(
                    SuccessPattern(Regex("<\\?php", RegexOption.IGNORE_CASE), 90, "PHP source in backup"),
                    SuccessPattern(Regex("#!/usr/bin/(env\\s+)?(python|bash|sh|ruby|perl)", RegexOption.IGNORE_CASE), 90, "Script shebang"),
                    SuccessPattern(
                        Regex("^package\\s+[a-z]+\\.[a-z]+", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
                        85,
                        "Java package declaration",
                    ),
                ),
            // ===== Debug Exposure =====
            VulnClass.DEBUG_EXPOSURE to
                listOf(
                    SuccessPattern(Regex("\\{.*\"status\".*\"UP\".*\"components\"", RegexOption.IGNORE_CASE), 90, "Spring Actuator health"),
                    SuccessPattern(Regex("PHP Version|phpinfo\\(\\)", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "PHP info page"),
                    SuccessPattern(Regex("Werkzeug Debugger|Debug.*Traceback", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Flask debugger"),
                    SuccessPattern(Regex("Laravel.*Telescope", RegexOption.IGNORE_CASE), 90, "Laravel Telescope"),
                    SuccessPattern(Regex("_profiler.*token|Symfony.*Profiler", RegexOption.IGNORE_CASE), 90, "Symfony Profiler"),
                ),
            // ===== Source Map Disclosure =====
            VulnClass.SOURCEMAP_DISCLOSURE to
                listOf(
                    SuccessPattern(
                        Regex("\"version\"\\s*:\\s*3,\\s*\"sources\"", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Source map v3",
                    ),
                    SuccessPattern(
                        Regex("\"sourcesContent\"\\s*:\\s*\\[", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "Source map with content",
                    ),
                ),
            // ===== Subdomain Takeover =====
            VulnClass.SUBDOMAIN_TAKEOVER to
                listOf(
                    SuccessPattern(
                        Regex("There isn't a GitHub Pages site here", RegexOption.IGNORE_CASE),
                        HIGH_CONFIDENCE,
                        "GitHub Pages takeover",
                    ),
                    SuccessPattern(Regex("NoSuchBucket", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "S3 bucket takeover"),
                    SuccessPattern(Regex("Heroku \\| No such app", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "Heroku takeover"),
                ),
            // ===== S3 Misconfiguration =====
            VulnClass.S3_MISCONFIGURATION to
                listOf(
                    SuccessPattern(Regex("<ListBucketResult", RegexOption.IGNORE_CASE), HIGH_CONFIDENCE, "S3 bucket listing"),
                    SuccessPattern(Regex("<Name>[^<]+</Name>\\s*<Prefix>", RegexOption.IGNORE_CASE), 90, "S3 bucket response"),
                ),
            // ===== OAuth Misconfiguration =====
            VulnClass.OAUTH_MISCONFIGURATION to
                listOf(
                    SuccessPattern(Regex("access_token=", RegexOption.IGNORE_CASE), 90, "Token in URL fragment"),
                    SuccessPattern(Regex("code=[a-zA-Z0-9_-]{10,}", RegexOption.IGNORE_CASE), 85, "Auth code in URL"),
                ),
            // ===== Price Manipulation =====
            VulnClass.PRICE_MANIPULATION to
                listOf(
                    // Look for acceptance of negative/zero values
                    SuccessPattern(Regex("total.*-\\d|price.*-\\d|amount.*-\\d", RegexOption.IGNORE_CASE), 90, "Negative value accepted"),
                    SuccessPattern(Regex("total.*:\\s*0[^0-9]|price.*:\\s*0[^0-9]", RegexOption.IGNORE_CASE), 85, "Zero value accepted"),
                ),
            // ===== API Version Bypass =====
            VulnClass.API_VERSION_BYPASS to
                listOf(
                    SuccessPattern(
                        Regex("deprecated|legacy|old.*version|v0\\.|beta", RegexOption.IGNORE_CASE),
                        85,
                        "Old API version accessible",
                    ),
                ),
        )

    // Patterns that should DISQUALIFY a finding (false positive indicators)
    private val falsePositiveIndicators: Map<VulnClass, List<Regex>> =
        mapOf(
            VulnClass.SQLI to
                listOf(
                    // Documentation, tutorials, and educational content
                    Regex("documentation", RegexOption.IGNORE_CASE),
                    Regex("example", RegexOption.IGNORE_CASE),
                    Regex("tutorial", RegexOption.IGNORE_CASE),
                    Regex("learn.*sql|sql.*course|sql.*training", RegexOption.IGNORE_CASE),
                    // Code blocks in pages
                    Regex("```sql|<code>.*SELECT|syntax.*reference", RegexOption.IGNORE_CASE),
                    // SQL in blog/article content
                    Regex("blog.*sql|article.*database|how.*to.*query", RegexOption.IGNORE_CASE),
                ),
            VulnClass.XSS_REFLECTED to
                listOf(
                    // Security documentation/OWASP content
                    Regex("XSS.*prevention", RegexOption.IGNORE_CASE),
                    Regex("sanitize", RegexOption.IGNORE_CASE),
                    Regex("escaped", RegexOption.IGNORE_CASE),
                    Regex("OWASP|cross-site.*scripting.*attack", RegexOption.IGNORE_CASE),
                    // Security scanning results or reports
                    Regex("security.*report|vulnerability.*scan|penetration.*test", RegexOption.IGNORE_CASE),
                ),
            VulnClass.CMDI to
                listOf(
                    // uid/gid appearing in documentation
                    Regex("user.*id.*=.*\\d+.*,.*group.*id.*=.*\\d+", RegexOption.IGNORE_CASE),
                    // Linux documentation
                    Regex("man.*page|linux.*command|bash.*tutorial", RegexOption.IGNORE_CASE),
                ),
            VulnClass.STACK_TRACE_EXPOSURE to
                listOf(
                    // Admin consoles/log viewers (intentional stack traces)
                    Regex("log.*viewer|admin.*console|debug.*panel", RegexOption.IGNORE_CASE),
                    Regex("error.*log.*page|exception.*viewer|stack.*trace.*viewer", RegexOption.IGNORE_CASE),
                ),
            VulnClass.SSTI to
                listOf(
                    // Template documentation
                    Regex("jinja2.*documentation|template.*tutorial|mustache.*guide", RegexOption.IGNORE_CASE),
                    Regex("template.*syntax|template.*engine.*docs", RegexOption.IGNORE_CASE),
                ),
            VulnClass.LFI to
                listOf(
                    // Documentation mentioning file paths
                    Regex("/etc/passwd.*example|file.*path.*documentation", RegexOption.IGNORE_CASE),
                    Regex("linux.*file.*system|unix.*directory.*structure", RegexOption.IGNORE_CASE),
                ),
            VulnClass.SSRF to
                listOf(
                    // Cloud documentation
                    Regex("aws.*documentation|metadata.*service.*docs", RegexOption.IGNORE_CASE),
                    Regex("cloud.*security.*guide|instance.*metadata.*protection", RegexOption.IGNORE_CASE),
                ),
        )

    data class ErrorPattern(
        val regex: Regex,
        val confidence: Int,
        val evidence: String,
    )

    data class SuccessPattern(
        val regex: Regex,
        val confidence: Int,
        val evidence: String,
    )

    /**
     * Analyze a response to determine if vulnerability was confirmed
     * Returns null if confidence is below MIN_CONFIDENCE_TO_REPORT
     */
    fun analyze(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
    ): VulnConfirmation? {
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val modifiedHeaders =
            modified
                .response()
                ?.headers()
                ?.map { "${it.name()}: ${it.value()}" }
                ?.joinToString("\n") ?: ""
        val fullResponse = modifiedHeaders + "\n\n" + modifiedBody
        val originalHeaders =
            original
                .response()
                ?.headers()
                ?.map { "${it.name()}: ${it.value()}" }
                ?.joinToString("\n") ?: ""
        val originalBody = original.response()?.bodyToString() ?: ""
        val originalFull = originalHeaders + "\n\n" + originalBody

        // Check for false positive indicators first
        if (isFalsePositive(vulnClass, fullResponse)) {
            return null
        }

        val confirmation =
            when (payload.detectionMethod) {
                DetectionMethod.ERROR_BASED -> analyzeErrorBased(original, modified, payload, vulnClass, fullResponse, originalFull)
                DetectionMethod.REFLECTION -> analyzeReflection(original, modified, payload, vulnClass, fullResponse, originalFull)
                DetectionMethod.CONTENT_BASED -> analyzeContentBased(original, modified, payload, vulnClass, fullResponse, originalFull)
                DetectionMethod.BLIND_BOOLEAN -> analyzeBooleanBased(original, modified, payload, vulnClass)
                DetectionMethod.BLIND_TIME -> null // Time-based needs special handling in ActiveAiScanner
                DetectionMethod.OUT_OF_BAND -> null // OOB needs external callback server
            }

        // Only return if confidence meets threshold
        return confirmation?.takeIf { it.confidence >= MIN_CONFIDENCE_TO_REPORT }
    }

    private fun isFalsePositive(
        vulnClass: VulnClass,
        response: String,
    ): Boolean {
        val indicators = falsePositiveIndicators[vulnClass] ?: return false
        // If false positive indicators are found alongside potential vuln indicators,
        // it's likely documentation/examples, not a real vuln
        return indicators.any { it.containsMatchIn(response) }
    }

    private fun analyzeErrorBased(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        fullResponse: String,
        originalFull: String,
    ): VulnConfirmation? {
        val patterns = errorPatterns[vulnClass] ?: return null

        for (pattern in patterns) {
            val match = pattern.regex.find(fullResponse)
            if (match != null) {
                // CRITICAL: Verify this error wasn't in the original response
                if (pattern.regex.containsMatchIn(originalFull)) {
                    continue // Error already present, not caused by our payload
                }

                return createConfirmation(
                    original,
                    modified,
                    payload,
                    vulnClass,
                    pattern.confidence,
                    "${pattern.evidence}: '${match.value.take(80)}'",
                )
            }
        }
        return null
    }

    private fun analyzeReflection(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        fullResponse: String,
        originalFull: String,
    ): VulnConfirmation? {
        // For XSS, we need STRICT validation
        if (vulnClass == VulnClass.XSS_REFLECTED) {
            val patterns = successPatterns[vulnClass] ?: return null

            for (pattern in patterns) {
                val match = pattern.regex.find(fullResponse)
                if (match != null) {
                    // Verify payload wasn't already in original response
                    if (pattern.regex.containsMatchIn(originalFull)) {
                        continue
                    }

                    // Additional check: verify it's in HTML body, not in a comment or script string
                    if (isInSafeContext(match.value, fullResponse)) {
                        continue
                    }

                    return createConfirmation(
                        original,
                        modified,
                        payload,
                        vulnClass,
                        pattern.confidence,
                        "${pattern.evidence}: '${match.value.take(60)}'",
                    )
                }
            }
        }
        return null
    }

    /**
     * Check if the matched content is inside a "safe" context (HTML comment, JS string, etc.)
     */
    private fun isInSafeContext(
        matchValue: String,
        fullResponse: String,
    ): Boolean {
        val matchIndex = fullResponse.indexOf(matchValue)
        if (matchIndex == -1) return false

        // Check if inside HTML comment
        val beforeMatch = fullResponse.substring(0, matchIndex)
        val lastCommentStart = beforeMatch.lastIndexOf("<!--")
        val lastCommentEnd = beforeMatch.lastIndexOf("-->")
        if (lastCommentStart > lastCommentEnd) {
            return true // Inside HTML comment
        }

        // Check if inside <script> tag as a string (not actual code)
        // This is a simplified check - real analysis would need a parser
        val lastScriptStart = beforeMatch.lastIndexOf("<script", ignoreCase = true)
        val lastScriptEnd = beforeMatch.lastIndexOf("</script>", ignoreCase = true)
        if (lastScriptStart > lastScriptEnd) {
            // We're inside a script tag - check if the match looks like it's in a string
            val scriptContent = fullResponse.substring(lastScriptStart, matchIndex)
            val quotesBefore = scriptContent.count { it == '"' || it == '\'' }
            if (quotesBefore % 2 == 1) {
                return true // Likely inside a JS string
            }
        }

        return false
    }

    private fun analyzeContentBased(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        fullResponse: String,
        originalFull: String,
    ): VulnConfirmation? {
        // Use both error and success patterns
        val allPatterns = mutableListOf<SuccessPattern>()
        errorPatterns[vulnClass]?.forEach {
            allPatterns.add(SuccessPattern(it.regex, it.confidence, it.evidence))
        }
        successPatterns[vulnClass]?.forEach { allPatterns.add(it) }

        for (pattern in allPatterns) {
            val match = pattern.regex.find(fullResponse)
            if (match != null) {
                // CRITICAL: Verify content wasn't in original response
                if (pattern.regex.containsMatchIn(originalFull)) {
                    continue
                }

                return createConfirmation(
                    original,
                    modified,
                    payload,
                    vulnClass,
                    pattern.confidence,
                    "${pattern.evidence}: '${match.value.take(80)}'",
                )
            }
        }

        // Special handling for SSTI math evaluation
        // Use highly unique numbers: 97601 (1337*73) and 94011 (31337*3)
        // These are extremely rare in normal content (not prices, IDs, years, etc.)
        if (vulnClass == VulnClass.SSTI) {
            // Check for 97601 (1337*73)
            if (payload.value.contains("1337*73")) {
                if (fullResponse.contains("97601") && !originalFull.contains("97601")) {
                    return createConfirmation(
                        original,
                        modified,
                        payload,
                        vulnClass,
                        HIGH_CONFIDENCE,
                        "SSTI math evaluated: 1337*73=97601",
                    )
                }
            }
            // Check for 94011 (31337*3)
            if (payload.value.contains("31337*3")) {
                if (fullResponse.contains("94011") && !originalFull.contains("94011")) {
                    return createConfirmation(
                        original,
                        modified,
                        payload,
                        vulnClass,
                        HIGH_CONFIDENCE,
                        "SSTI math evaluated: 31337*3=94011",
                    )
                }
            }
            // Check for Jinja2-specific 7*'7' = "7777777"
            if (payload.value.contains("7*'7'")) {
                if (fullResponse.contains("7777777") && !originalFull.contains("7777777")) {
                    return createConfirmation(
                        original,
                        modified,
                        payload,
                        vulnClass,
                        HIGH_CONFIDENCE,
                        "SSTI (Jinja2): 7*'7'=7777777",
                    )
                }
            }
        }

        return null
    }

    private fun analyzeBooleanBased(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
    ): VulnConfirmation? {
        // Boolean-based detection requires DUAL CONFIRMATION from paired testing
        // Single FALSE condition is not enough - could be cache/rate-limiting
        // This method only marks candidates - actual confirmation requires paired testing in ActiveAiScanner

        val originalBody = original.response()?.bodyToString() ?: ""
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val originalStatus = original.response()?.statusCode() ?: 0
        val modifiedStatus = modified.response()?.statusCode() ?: 0
        val originalLength = originalBody.length
        val modifiedLength = modifiedBody.length

        // Calculate similarity
        val diff = calculateDifference(originalBody, modifiedBody)

        // Identify payload type
        val isTrueCondition =
            payload.value.contains("1'='1") ||
                payload.value.contains("1=1") ||
                payload.expectedEvidence.contains("Same response", ignoreCase = true)

        val isFalseCondition =
            payload.value.contains("1'='2") ||
                payload.value.contains("1=2") ||
                payload.expectedEvidence.contains("Different", ignoreCase = true)

        // For FALSE condition - check if there's significant difference (candidate for paired testing)
        if (isFalseCondition) {
            val lengthDiff = kotlin.math.abs(originalLength - modifiedLength)
            val lengthDiffPercent = if (originalLength > 0) lengthDiff.toDouble() / originalLength else 0.0

            // Need either: status code change, OR >20% length change, OR very low similarity
            val hasSignificantDiff =
                originalStatus != modifiedStatus ||
                    lengthDiffPercent > 0.2 ||
                    diff.similarity < 0.6

            if (hasSignificantDiff) {
                // Return TENTATIVE result - needs paired testing confirmation
                // Confidence capped at 75 until paired testing confirms
                return createConfirmation(
                    original,
                    modified,
                    payload,
                    vulnClass,
                    75, // Below threshold - requires paired confirmation
                    "CANDIDATE: FALSE condition diff detected (similarity: ${(diff.similarity * 100).toInt()}%) - needs TRUE condition verification",
                )
            }
        }

        return null
    }

    /**
     * Perform dual confirmation for Boolean-based SQLi
     * Requires BOTH TRUE and FALSE conditions to behave as expected:
     * - TRUE condition -> response similar to original
     * - FALSE condition -> response different from original
     * This eliminates FPs from cache/rate-limiting/random variations
     */
    fun analyzeBooleanBasedDual(
        original: HttpRequestResponse,
        trueResponse: HttpRequestResponse,
        falseResponse: HttpRequestResponse,
        truePayload: Payload,
        falsePayload: Payload,
        vulnClass: VulnClass,
    ): VulnConfirmation? {
        val originalBody = original.response()?.bodyToString() ?: ""
        val trueBody = trueResponse.response()?.bodyToString() ?: ""
        val falseBody = falseResponse.response()?.bodyToString() ?: ""

        val originalStatus = original.response()?.statusCode() ?: 0
        val trueStatus = trueResponse.response()?.statusCode() ?: 0
        val falseStatus = falseResponse.response()?.statusCode() ?: 0

        // Calculate similarities
        val trueDiff = calculateDifference(originalBody, trueBody)
        val falseDiff = calculateDifference(originalBody, falseBody)
        val trueFalseDiff = calculateDifference(trueBody, falseBody)

        // DUAL CONFIRMATION CRITERIA:
        // 1. TRUE condition should be similar to original (similarity > 0.8)
        // 2. FALSE condition should be different from original (similarity < 0.7)
        // 3. TRUE and FALSE should be different from each other

        val trueIsSimilarToOriginal = trueDiff.similarity > 0.8 && trueStatus == originalStatus
        val falseIsDifferentFromOriginal = falseDiff.similarity < 0.7 || falseStatus != originalStatus
        val trueAndFalseAreDifferent = trueFalseDiff.similarity < 0.7 || trueStatus != falseStatus

        // All three conditions must be met
        if (trueIsSimilarToOriginal && falseIsDifferentFromOriginal && trueAndFalseAreDifferent) {
            // Calculate confidence based on strength of evidence
            val statusEvidence = if (trueStatus == originalStatus && falseStatus != originalStatus) 15 else 0
            val contentEvidence =
                when {
                    trueDiff.similarity > 0.95 && falseDiff.similarity < 0.5 -> 15
                    trueDiff.similarity > 0.9 && falseDiff.similarity < 0.6 -> 10
                    else -> 5
                }
            val diffEvidence =
                when {
                    trueFalseDiff.similarity < 0.4 -> 10
                    trueFalseDiff.similarity < 0.6 -> 5
                    else -> 0
                }

            val baseConfidence = 70
            val totalConfidence = minOf(HIGH_CONFIDENCE, baseConfidence + statusEvidence + contentEvidence + diffEvidence)

            if (totalConfidence >= MIN_CONFIDENCE_TO_REPORT) {
                return createConfirmation(
                    original,
                    falseResponse,
                    falsePayload,
                    vulnClass,
                    totalConfidence,
                    "Boolean blind CONFIRMED with dual testing: TRUE(similarity:${(trueDiff.similarity * 100).toInt()}%, status:$trueStatus) vs FALSE(similarity:${(falseDiff.similarity * 100).toInt()}%, status:$falseStatus)",
                )
            }
        }

        return null
    }

    /**
     * Analyze time-based payloads by comparing response times
     * STRICT: requires significant delay matching expected time with tight tolerances
     * to reduce false positives from network latency/server load
     */
    fun analyzeTimeBased(
        baselineTimeMs: Long,
        payloadTimeMs: Long,
        expectedDelayMs: Long,
    ): Boolean {
        // STRICT validation to minimize false positives:
        // 1. Baseline must be under 1 second (fast server) to ensure delay is from payload
        // 2. Actual delay must be within tight window: 90%-120% of expected

        // If baseline is slow (>1s), time-based detection is unreliable
        if (baselineTimeMs > 1000) {
            return false
        }

        val actualDelay = payloadTimeMs - baselineTimeMs
        val minRequired = (expectedDelayMs * 0.9).toLong() // Tightened from 0.8
        val maxAllowed = (expectedDelayMs * 1.2).toLong() // Tightened from 1.5

        return actualDelay >= minRequired && actualDelay <= maxAllowed
    }

    /**
     * Calculate similarity between two response bodies
     */
    fun calculateDifference(
        original: String,
        modified: String,
    ): ResponseDiff {
        if (original == modified) {
            return ResponseDiff(similarity = 1.0, addedLines = 0, removedLines = 0)
        }

        val originalLines = original.lines().toSet()
        val modifiedLines = modified.lines().toSet()

        val common = originalLines.intersect(modifiedLines).size
        val total = originalLines.union(modifiedLines).size

        val similarity = if (total > 0) common.toDouble() / total else 0.0
        val addedLines = (modifiedLines - originalLines).size
        val removedLines = (originalLines - modifiedLines).size

        return ResponseDiff(
            similarity = similarity,
            addedLines = addedLines,
            removedLines = removedLines,
        )
    }

    private fun createConfirmation(
        original: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        confidence: Int,
        evidence: String,
    ): VulnConfirmation =
        VulnConfirmation(
            target =
                ActiveScanTarget(
                    originalRequest = original,
                    injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "", ""),
                    vulnHint = VulnHint(vulnClass, 0, ""),
                    priority = 0,
                ),
            payload = payload,
            originalResponse = original,
            exploitResponse = modified,
            confidence = confidence,
            evidence = evidence,
            confirmed = true,
        )
}

data class ResponseDiff(
    val similarity: Double,
    val addedLines: Int,
    val removedLines: Int,
)
