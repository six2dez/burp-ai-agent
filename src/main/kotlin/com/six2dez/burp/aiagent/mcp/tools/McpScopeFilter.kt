package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext

/**
 * Scope-enforcement helpers for MCP tools.
 *
 * Two complementary primitives:
 *
 *  - [filterInScope] — for tools that READ Burp HTTP data (proxy history, site map,
 *    WebSocket history, etc.). When [McpToolContext.scopeOnly] is true, returns only items
 *    whose URL (as extracted by the caller-supplied lambda) satisfies
 *    `api.scope().isInScope(url)`. Items whose URL extractor returns `null` are
 *    conservatively dropped under scopeOnly (no scope decision possible). When
 *    [McpToolContext.scopeOnly] is false, the input is returned verbatim — bytewise no-op,
 *    and `api.scope()` is NEVER invoked.
 *
 *  - [rejectIfOutOfScope] — for tools that SEND requests to a URL (http1_request,
 *    repeater_tab, intruder, etc.). When [McpToolContext.scopeOnly] is true AND the URL is
 *    out of scope, returns a documented rejection string the caller can return directly to
 *    the MCP client. Returns `null` when the URL is allowed (caller proceeds) and also when
 *    [McpToolContext.scopeOnly] is false (no enforcement → tool runs as today).
 *
 * Both helpers are pure: no logging, no audit events, no side effects beyond the necessary
 * `api.scope().isInScope(...)` call. This keeps them deterministically testable and avoids
 * doubling up on the existing tool-handler telemetry that runs in `runTool`.
 *
 * See GitHub issue #69 (sub-concern 4) and 07-03-PLAN.md for the original motivation.
 */
internal object McpScopeFilter {
    /**
     * Returns items whose URL (as extracted by [urlOf]) is in scope, when `ctx.scopeOnly`
     * is true. Items whose URL extractor returns `null` are dropped when scopeOnly is true
     * (no scope decision possible — fail closed, consistent with the historical
     * `proxy_history_annotate` per-call behaviour) and kept when scopeOnly is false.
     * Bytewise no-op when scopeOnly is false; `api.scope()` is NOT invoked in that path.
     */
    fun <T> filterInScope(
        items: Sequence<T>,
        urlOf: (T) -> String?,
        ctx: McpToolContext,
    ): Sequence<T> {
        if (!ctx.scopeOnly) return items
        val scope = ctx.api.scope()
        return items.filter { item ->
            val url = urlOf(item) ?: return@filter false
            scope.isInScope(url)
        }
    }

    /** Convenience overload for [List] inputs (collected lists from Montoya APIs). */
    fun <T> filterInScope(
        items: List<T>,
        urlOf: (T) -> String?,
        ctx: McpToolContext,
    ): Sequence<T> = filterInScope(items.asSequence(), urlOf, ctx)

    /**
     * Returns `null` when the URL is permitted, or a documented rejection string when
     * [McpToolContext.scopeOnly] is true AND the URL is out of scope. The returned string
     * is suitable for direct return from an MCP tool handler — it identifies the offending
     * URL and suggests `scope_include` as the remediation.
     *
     * Returns `null` unconditionally when [McpToolContext.scopeOnly] is false, so call
     * sites can safely apply this helper without gating on the toggle themselves.
     */
    fun rejectIfOutOfScope(
        url: String,
        ctx: McpToolContext,
    ): String? {
        if (!ctx.scopeOnly) return null
        if (ctx.api.scope().isInScope(url)) return null
        return "Refused: $url is out of scope (mcpScopeOnly=true). Use scope_include to add it."
    }

    /**
     * Derives an HTTPish URL from a Burp [HttpServiceParams]-style triple (hostname/port/https)
     * and a raw HTTP request content. The path is extracted from the request line
     * (`METHOD path HTTP/x.y`) if present; falls back to `/` when no path can be parsed.
     *
     * Used by write-style MCP tools to perform the scope check BEFORE constructing the
     * Montoya `HttpRequest` (which requires Burp's static factory and so is unavailable in
     * pure-JVM unit tests). The resulting URL is equivalent to what `HttpRequest.url()` would
     * return at runtime, modulo any query rewriting Burp itself does — both flow into
     * `api.scope().isInScope(...)` identically.
     */
    fun deriveScopeUrl(
        hostname: String,
        port: Int,
        usesHttps: Boolean,
        rawRequest: String,
    ): String {
        val scheme = if (usesHttps) "https" else "http"
        val path =
            rawRequest
                .lineSequence()
                .firstOrNull { it.isNotBlank() }
                ?.let { line ->
                    // Request-line format: METHOD SP request-target SP HTTP-version
                    val parts = line.trim().split(' ', limit = 3)
                    parts.getOrNull(1)?.takeIf { it.isNotBlank() }
                }
                ?: "/"
        val portSuffix =
            when {
                usesHttps && port == 443 -> ""
                !usesHttps && port == 80 -> ""
                else -> ":$port"
            }
        // request-target may already be an absolute URI (CONNECT, OPTIONS *); pass it through.
        return if (path.startsWith("http://") || path.startsWith("https://") || path == "*") {
            path
        } else {
            "$scheme://$hostname$portSuffix$path"
        }
    }
}
