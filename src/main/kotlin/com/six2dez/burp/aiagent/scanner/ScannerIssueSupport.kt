package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

object ScannerIssueSupport {
    fun mapSeverity(vulnClass: VulnClass): AuditIssueSeverity =
        when (vulnClass) {
            VulnClass.SQLI, VulnClass.CMDI, VulnClass.SSTI, VulnClass.XXE,
            VulnClass.DESERIALIZATION, VulnClass.REQUEST_SMUGGLING, VulnClass.RFI, VulnClass.LDAP_INJECTION,
            VulnClass.XPATH_INJECTION, VulnClass.NOSQL_INJECTION,
            VulnClass.ACCOUNT_TAKEOVER, VulnClass.MFA_BYPASS, VulnClass.OAUTH_MISCONFIGURATION,
            VulnClass.GIT_EXPOSURE, VulnClass.SUBDOMAIN_TAKEOVER, VulnClass.HOST_HEADER_INJECTION,
            VulnClass.CACHE_POISONING,
            -> AuditIssueSeverity.HIGH

            VulnClass.ACCESS_CONTROL_BYPASS,
            VulnClass.XSS_REFLECTED, VulnClass.XSS_STORED, VulnClass.XSS_DOM,
            VulnClass.LFI, VulnClass.SSRF, VulnClass.IDOR, VulnClass.PATH_TRAVERSAL,
            VulnClass.BOLA, VulnClass.BFLA, VulnClass.BAC_HORIZONTAL, VulnClass.BAC_VERTICAL,
            VulnClass.MASS_ASSIGNMENT, VulnClass.AUTH_BYPASS, VulnClass.SESSION_FIXATION,
            VulnClass.GRAPHQL_INJECTION, VulnClass.STACK_TRACE_EXPOSURE,
            VulnClass.SOURCEMAP_DISCLOSURE, VulnClass.BACKUP_DISCLOSURE,
            VulnClass.DEBUG_EXPOSURE, VulnClass.S3_MISCONFIGURATION, VulnClass.CACHE_DECEPTION,
            VulnClass.PRICE_MANIPULATION, VulnClass.RACE_CONDITION_TOCTOU, VulnClass.EMAIL_HEADER_INJECTION,
            VulnClass.API_VERSION_BYPASS, VulnClass.UNRESTRICTED_FILE_UPLOAD,
            -> AuditIssueSeverity.MEDIUM

            VulnClass.OPEN_REDIRECT, VulnClass.HEADER_INJECTION, VulnClass.CRLF_INJECTION,
            VulnClass.JWT_WEAKNESS, VulnClass.BUSINESS_LOGIC,
            VulnClass.CORS_MISCONFIGURATION, VulnClass.DIRECTORY_LISTING, VulnClass.DEBUG_ENDPOINT,
            VulnClass.VERSION_DISCLOSURE, VulnClass.MISSING_SECURITY_HEADERS, VulnClass.VERBOSE_ERROR,
            VulnClass.INSECURE_COOKIE, VulnClass.SENSITIVE_DATA_URL, VulnClass.WEAK_CRYPTO,
            VulnClass.LOG_INJECTION, VulnClass.CSRF, VulnClass.RATE_LIMIT_BYPASS,
            VulnClass.WEAK_SESSION_TOKEN,
            -> AuditIssueSeverity.LOW
        }

    fun remediation(vulnClass: VulnClass): String =
        when (vulnClass) {
            VulnClass.SQLI -> "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
            VulnClass.XSS_REFLECTED, VulnClass.XSS_STORED, VulnClass.XSS_DOM -> "Encode all user input before rendering in HTML. Use Content-Security-Policy headers."
            VulnClass.LFI, VulnClass.PATH_TRAVERSAL -> "Validate and sanitize file paths. Use allowlists for permitted files. Avoid user input in file operations."
            VulnClass.RFI -> "Disable remote file inclusion in PHP. Validate URLs against allowlist."
            VulnClass.SSTI -> "Use logic-less templates or sandbox template execution. Never pass user input directly to template engines."
            VulnClass.CMDI -> "Avoid system commands with user input. If necessary, use strict allowlists and proper escaping."
            VulnClass.SSRF -> "Validate and allowlist destination URLs. Block requests to internal networks and cloud metadata endpoints."
            VulnClass.IDOR, VulnClass.BOLA -> "Implement proper authorization checks. Don't rely on obscurity of IDs."
            VulnClass.BFLA, VulnClass.BAC_HORIZONTAL, VulnClass.BAC_VERTICAL -> "Implement role-based access control. Verify user permissions for each action."
            VulnClass.MASS_ASSIGNMENT -> "Use allowlists for permitted fields in object binding. Never trust client-provided field names."
            VulnClass.OPEN_REDIRECT -> "Validate redirect URLs against an allowlist. Use relative URLs where possible."
            VulnClass.XXE -> "Disable external entity processing in XML parsers. Use JSON instead of XML where possible."
            VulnClass.HEADER_INJECTION, VulnClass.CRLF_INJECTION -> "Strip or encode CR/LF characters from user input used in HTTP headers."
            VulnClass.DESERIALIZATION -> "Avoid deserializing untrusted data. Use allowlists for permitted classes."
            VulnClass.REQUEST_SMUGGLING -> "Normalize or reject conflicting Content-Length/Transfer-Encoding headers. Use a single HTTP parser across all tiers."
            VulnClass.CSRF -> "Implement anti-CSRF tokens. Use SameSite cookies and verify Origin/Referer on state-changing requests."
            VulnClass.UNRESTRICTED_FILE_UPLOAD -> "Restrict file types, validate content, store outside web root, and enforce random names."
            VulnClass.JWT_WEAKNESS -> "Use strong algorithms (RS256). Validate all JWT claims. Don't accept 'none' algorithm."
            VulnClass.LDAP_INJECTION -> "Use parameterized LDAP queries. Escape special LDAP characters in user input."
            VulnClass.XPATH_INJECTION -> "Use parameterized XPath queries. Validate and sanitize user input."
            VulnClass.AUTH_BYPASS -> "Implement proper authentication checks on all protected resources."
            VulnClass.BUSINESS_LOGIC -> "Review business logic for edge cases. Implement proper validation and state management."
            VulnClass.NOSQL_INJECTION -> "Use parameterized queries. Sanitize user input. Disable server-side JavaScript."
            VulnClass.GRAPHQL_INJECTION -> "Disable introspection in production. Implement query depth/complexity limits."
            VulnClass.LOG_INJECTION -> "Sanitize log entries. Encode CRLF characters. Use structured logging."
            VulnClass.CORS_MISCONFIGURATION -> "Use explicit allowlist for origins. Never reflect arbitrary origins. Avoid wildcard with credentials."
            VulnClass.DIRECTORY_LISTING -> "Disable directory listing in web server config. Add index files."
            VulnClass.DEBUG_ENDPOINT -> "Disable debug mode in production. Remove debug endpoints and tools."
            VulnClass.STACK_TRACE_EXPOSURE -> "Configure custom error pages. Never expose stack traces to users."
            VulnClass.VERSION_DISCLOSURE -> "Remove or obfuscate version headers. Configure server to hide version info."
            VulnClass.MISSING_SECURITY_HEADERS -> "Add security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS."
            VulnClass.VERBOSE_ERROR -> "Use generic error messages. Log details server-side only."
            VulnClass.INSECURE_COOKIE -> "Set Secure, HttpOnly, SameSite flags on cookies. Use proper cookie scope."
            VulnClass.SENSITIVE_DATA_URL -> "Never put passwords/tokens in URLs. Use POST body or headers."
            VulnClass.WEAK_CRYPTO -> "Use strong, modern algorithms. Avoid MD5, SHA1, DES. Use TLS 1.2+."
            VulnClass.SESSION_FIXATION -> "Regenerate session ID after login. Invalidate old sessions."
            VulnClass.WEAK_SESSION_TOKEN -> "Use cryptographically secure random session tokens. Use sufficient entropy."
            VulnClass.RATE_LIMIT_BYPASS -> "Implement robust rate limiting. Don't rely on client-side controls."
            VulnClass.ACCOUNT_TAKEOVER -> "Implement secure password reset flows with short-lived tokens. Require email verification for email changes. Use rate limiting on auth endpoints."
            VulnClass.HOST_HEADER_INJECTION -> "Validate Host header against allowlist. Don't use Host header in password reset URLs or cache keys. Use absolute URLs with hardcoded domains."
            VulnClass.EMAIL_HEADER_INJECTION -> "Sanitize all email header inputs. Strip newlines and carriage returns. Use email libraries that handle escaping."
            VulnClass.OAUTH_MISCONFIGURATION -> "Strictly validate redirect_uri against exact match allowlist. Use state parameter with unpredictable values. Don't expose tokens in URLs."
            VulnClass.MFA_BYPASS -> "Implement rate limiting on MFA verification. Don't expose backup codes in responses. Ensure MFA cannot be skipped via direct navigation."
            VulnClass.PRICE_MANIPULATION -> "Validate all price/quantity calculations server-side. Never trust client-provided prices. Use signed carts or recalculate totals."
            VulnClass.RACE_CONDITION_TOCTOU -> "Use database-level locking for critical operations. Implement idempotency keys. Use atomic operations for balance/inventory changes."
            VulnClass.CACHE_POISONING -> "Don't use unkeyed headers in cached responses. Validate all header inputs. Use separate caches for authenticated/unauthenticated content."
            VulnClass.CACHE_DECEPTION -> "Don't cache responses based on URL extension alone. Use Cache-Control headers. Validate authentication before serving cached content."
            VulnClass.SOURCEMAP_DISCLOSURE -> "Don't deploy source maps to production. If needed, restrict access to authenticated users only. Remove sourceMappingURL comments."
            VulnClass.GIT_EXPOSURE -> "Block access to .git directories in web server config. Don't deploy version control directories. Use .gitignore and verify deployment scripts."
            VulnClass.BACKUP_DISCLOSURE -> "Don't store backup files in web-accessible directories. Configure web server to block common backup extensions. Use secure backup storage."
            VulnClass.DEBUG_EXPOSURE -> "Disable debug endpoints in production. Use environment-based configuration. Protect actuator endpoints with authentication."
            VulnClass.S3_MISCONFIGURATION -> "Use private bucket policies by default. Enable S3 Block Public Access. Audit bucket policies regularly. Use presigned URLs for temporary access."
            VulnClass.SUBDOMAIN_TAKEOVER -> "Remove dangling DNS records. Monitor for unclaimed resources. Use CNAME verification before DNS changes."
            VulnClass.API_VERSION_BYPASS -> "Deprecate old API versions completely. Don't leave deprecated versions accessible. Use consistent security across all versions."
            VulnClass.ACCESS_CONTROL_BYPASS -> "Don't rely on client IP headers for access control. Implement proper authentication and authorization. Use consistent access control across path variations and HTTP methods."
        }
}
