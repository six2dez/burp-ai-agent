package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse

/**
 * Data models for the AI Active Scanner
 */

enum class InjectionType {
    URL_PARAM,
    BODY_PARAM,
    HEADER,
    PATH_SEGMENT,
    COOKIE,
    JSON_FIELD,
    XML_ELEMENT,
}

enum class VulnClass {
    // ===== A01: Broken Access Control =====
    IDOR,
    BOLA, // Broken Object Level Authorization (API-specific IDOR)
    BFLA, // Broken Function Level Authorization
    BAC_HORIZONTAL, // Broken Access Control - horizontal privilege escalation
    BAC_VERTICAL, // Broken Access Control - vertical privilege escalation
    MASS_ASSIGNMENT,
    SSRF,
    CORS_MISCONFIGURATION,
    DIRECTORY_LISTING,

    // ===== A02: Security Misconfiguration =====
    DEBUG_ENDPOINT,
    STACK_TRACE_EXPOSURE,
    VERSION_DISCLOSURE,
    MISSING_SECURITY_HEADERS,
    VERBOSE_ERROR,

    // ===== A04: Cryptographic Failures =====
    INSECURE_COOKIE, // Missing Secure/HttpOnly flags
    SENSITIVE_DATA_URL, // Passwords/tokens in URL
    WEAK_CRYPTO,

    // ===== A05: Injection =====
    SQLI,
    XSS_REFLECTED,
    XSS_STORED,
    XSS_DOM,
    CMDI,
    SSTI,
    XXE,
    LDAP_INJECTION,
    XPATH_INJECTION,
    NOSQL_INJECTION,
    GRAPHQL_INJECTION,
    LOG_INJECTION,
    LFI,
    RFI,
    PATH_TRAVERSAL,
    HOST_HEADER_INJECTION, // Host header manipulation for cache poisoning/password reset hijack
    EMAIL_HEADER_INJECTION, // Cc, Bcc, Subject injection in email functionality

    // ===== A06: Insecure Design =====
    BUSINESS_LOGIC,
    RATE_LIMIT_BYPASS,
    PRICE_MANIPULATION, // Negative prices, quantity tampering, discount abuse
    RACE_CONDITION_TOCTOU, // Time-of-check/Time-of-use race conditions

    // ===== A07: Authentication Failures =====
    JWT_WEAKNESS,
    AUTH_BYPASS,
    SESSION_FIXATION,
    WEAK_SESSION_TOKEN,
    ACCOUNT_TAKEOVER, // Password reset flaws, email change, token reuse
    OAUTH_MISCONFIGURATION, // OAuth redirect_uri bypass, token leak, state issues
    MFA_BYPASS, // 2FA bypass, backup code exposure, rate limit on OTP

    // ===== A08: Integrity Failures =====
    DESERIALIZATION,
    REQUEST_SMUGGLING,
    CSRF,
    UNRESTRICTED_FILE_UPLOAD,

    // ===== Cache Attacks =====
    CACHE_POISONING, // Web cache poisoning via header injection
    CACHE_DECEPTION, // Web cache deception (caching sensitive data)

    // ===== Information Disclosure (Bug Bounty High Value) =====
    SOURCEMAP_DISCLOSURE, // JavaScript source maps exposing source code
    GIT_EXPOSURE, // .git directory accessible
    BACKUP_DISCLOSURE, // Backup files (.bak, .old, .swp, etc.)
    DEBUG_EXPOSURE, // Debug endpoints (actuator, profiler, telescope)

    // ===== Cloud/Infrastructure =====
    S3_MISCONFIGURATION, // Public S3 buckets, Azure blobs, GCS
    SUBDOMAIN_TAKEOVER, // Dangling DNS, unclaimed cloud resources

    // ===== API Security =====
    API_VERSION_BYPASS, // Accessing old/deprecated API versions

    // ===== Access Control Bypass =====
    ACCESS_CONTROL_BYPASS, // 403 bypass via headers, path manipulation, method switching

    // ===== Other =====
    OPEN_REDIRECT,
    HEADER_INJECTION,
    CRLF_INJECTION,
}

object ScanPolicy {
    val PASSIVE_ONLY_VULN_CLASSES =
        setOf(
            VulnClass.CORS_MISCONFIGURATION,
            VulnClass.MISSING_SECURITY_HEADERS,
            VulnClass.VERSION_DISCLOSURE,
            VulnClass.INSECURE_COOKIE,
            VulnClass.REQUEST_SMUGGLING,
            VulnClass.CSRF,
            VulnClass.UNRESTRICTED_FILE_UPLOAD,
            VulnClass.DESERIALIZATION,
            VulnClass.SUBDOMAIN_TAKEOVER,
            VulnClass.S3_MISCONFIGURATION,
            VulnClass.SOURCEMAP_DISCLOSURE,
            VulnClass.GIT_EXPOSURE,
            VulnClass.BACKUP_DISCLOSURE,
            VulnClass.DEBUG_EXPOSURE,
        )
    val IDOR_CLASSES = setOf(VulnClass.IDOR, VulnClass.BOLA)
    val AUTHZ_BYPASS_CLASSES =
        setOf(
            VulnClass.BFLA,
            VulnClass.BAC_HORIZONTAL,
            VulnClass.BAC_VERTICAL,
            VulnClass.AUTH_BYPASS,
        )
    val CACHE_CLASSES = setOf(VulnClass.CACHE_POISONING, VulnClass.CACHE_DECEPTION)

    fun isAllowedForMode(
        mode: ScanMode,
        vulnClass: VulnClass,
    ): Boolean {
        if (mode == ScanMode.FULL) return true
        return when (mode) {
            ScanMode.BUG_BOUNTY -> vulnClass in bugBountyClasses()
            ScanMode.PENTEST -> vulnClass in pentestClasses()
            ScanMode.FULL -> true
        }
    }

    private fun bugBountyClasses(): Set<VulnClass> =
        setOf(
            VulnClass.SQLI,
            VulnClass.XSS_REFLECTED,
            VulnClass.XSS_STORED,
            VulnClass.XSS_DOM,
            VulnClass.SSRF,
            VulnClass.CMDI,
            VulnClass.SSTI,
            VulnClass.XXE,
            VulnClass.IDOR,
            VulnClass.BOLA,
            VulnClass.BAC_HORIZONTAL,
            VulnClass.BAC_VERTICAL,
            VulnClass.BFLA,
            VulnClass.AUTH_BYPASS,
            VulnClass.OAUTH_MISCONFIGURATION,
            VulnClass.MFA_BYPASS,
            VulnClass.ACCOUNT_TAKEOVER,
            VulnClass.HOST_HEADER_INJECTION,
            VulnClass.CACHE_POISONING,
            VulnClass.CACHE_DECEPTION,
            VulnClass.OPEN_REDIRECT,
            VulnClass.PRICE_MANIPULATION,
            VulnClass.RACE_CONDITION_TOCTOU,
            VulnClass.ACCESS_CONTROL_BYPASS,
        )

    private fun pentestClasses(): Set<VulnClass> = VulnClass.values().filterNot { it in PASSIVE_ONLY_VULN_CLASSES }.toSet()
}

/**
 * Scan modes for different use cases
 */
enum class ScanMode {
    BUG_BOUNTY, // Prioritize high-impact vulns, minimize noise
    PENTEST, // More exhaustive, includes info disclosure
    FULL, // All vulnerability classes
    ;

    companion object {
        fun fromString(value: String?): ScanMode {
            if (value.isNullOrBlank()) return FULL
            return entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: FULL
        }
    }
}

/**
 * Context information to prioritize findings by impact
 */
data class VulnContext(
    val affectsAuth: Boolean = false, // /login, /password, /oauth
    val affectsPayment: Boolean = false, // /checkout, /payment, /cart
    val affectsAdmin: Boolean = false, // /admin, /dashboard, /manage
    val affectsPII: Boolean = false, // Contains email, phone, address
    val isAPIEndpoint: Boolean = false, // /api/, JSON response
) {
    /**
     * Calculate impact multiplier based on context
     * Used to adjust severity of findings
     */
    fun getImpactMultiplier(): Double {
        var multiplier = 1.0
        if (affectsAuth) multiplier += 0.3
        if (affectsPayment) multiplier += 0.4
        if (affectsAdmin) multiplier += 0.3
        if (affectsPII) multiplier += 0.2
        if (isAPIEndpoint) multiplier += 0.1
        return multiplier
    }

    companion object {
        /**
         * Analyze URL/request to determine context
         */
        fun fromUrl(
            url: String,
            responseBody: String = "",
        ): VulnContext {
            val lowerUrl = url.lowercase()
            val lowerBody = responseBody.lowercase()

            return VulnContext(
                affectsAuth =
                    listOf("/login", "/signin", "/auth", "/password", "/reset", "/oauth", "/sso", "/2fa", "/mfa", "/token")
                        .any { lowerUrl.contains(it) },
                affectsPayment =
                    listOf("/checkout", "/payment", "/cart", "/order", "/purchase", "/billing", "/subscription", "/stripe", "/paypal")
                        .any { lowerUrl.contains(it) },
                affectsAdmin =
                    listOf("/admin", "/dashboard", "/manage", "/control", "/settings", "/config", "/internal")
                        .any { lowerUrl.contains(it) },
                affectsPII =
                    listOf("email", "phone", "address", "ssn", "social_security", "credit_card", "passport", "driver_license")
                        .any { lowerBody.contains(it) },
                isAPIEndpoint =
                    lowerUrl.contains("/api/") ||
                        lowerUrl.contains("/v1/") ||
                        lowerUrl.contains("/v2/") ||
                        lowerUrl.contains("/graphql") ||
                        responseBody.trim().startsWith("{"),
            )
        }
    }
}

enum class PayloadRisk {
    SAFE, // Read-only detection (errors, reflections)
    MODERATE, // May read sensitive data (UNION SELECT, file read)
    DANGEROUS, // May modify/delete data (DROP, rm, etc.)
    ;

    companion object {
        fun fromString(value: String?): PayloadRisk {
            if (value.isNullOrBlank()) return SAFE
            return entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: SAFE
        }
    }
}

enum class DetectionMethod {
    ERROR_BASED, // Look for error messages
    BLIND_BOOLEAN, // Compare response differences
    BLIND_TIME, // Measure response time
    REFLECTION, // Check if payload reflected
    OUT_OF_BAND, // DNS/HTTP callback (requires collaborator)
    CONTENT_BASED, // Check for specific content (file contents, etc.)
}

data class InjectionPoint(
    val type: InjectionType,
    val name: String,
    val originalValue: String,
    val position: Int? = null, // For body injection position
)

data class VulnHint(
    val vulnClass: VulnClass,
    val confidence: Int,
    val evidence: String,
    val injectionPoints: List<InjectionPoint> = emptyList(),
)

data class ActiveScanTarget(
    val originalRequest: HttpRequestResponse,
    val injectionPoint: InjectionPoint,
    val vulnHint: VulnHint,
    val priority: Int = 50, // 0-100, higher = more urgent
    val queuedAtEpochMs: Long = System.currentTimeMillis(),
) {
    val id: String = "${originalRequest.request().url()}_${injectionPoint.name}_${vulnHint.vulnClass}"
}

data class ActiveScanQueueItem(
    val id: String,
    val url: String,
    val vulnClass: String,
    val injectionPoint: String,
    val status: String,
    val queuedAtEpochMs: Long,
)

data class Payload(
    val value: String,
    val vulnClass: VulnClass,
    val detectionMethod: DetectionMethod,
    val risk: PayloadRisk,
    val expectedEvidence: String, // What to look for in response
    val timeDelayMs: Long? = null, // For time-based payloads
)

data class VulnConfirmation(
    val target: ActiveScanTarget,
    val payload: Payload,
    val originalResponse: HttpRequestResponse,
    val exploitResponse: HttpRequestResponse,
    val confidence: Int, // 0-100
    val evidence: String,
    val confirmed: Boolean,
)

data class ActiveScanResult(
    val target: ActiveScanTarget,
    val payloadsTested: Int,
    val confirmation: VulnConfirmation?,
    val error: String? = null,
)

data class ActiveScannerStatus(
    val enabled: Boolean,
    val queueSize: Int,
    val scanning: Boolean,
    val scansCompleted: Int,
    val vulnsConfirmed: Int,
    val currentTarget: String?,
)
