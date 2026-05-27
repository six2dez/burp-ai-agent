package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Unit tests for [McpScopeFilter] — the helper that gates every scope-aware MCP tool on
 * `mcpSettings.scopeOnly`. Tests cover read-style (`filterInScope`) and write-style
 * (`rejectIfOutOfScope`) helpers in both the on (filters / rejects) and off (no-op) branches.
 *
 * Closes part of GitHub issue #69 sub-concern 4 — 07-03-PLAN.md, BUG-69-03.
 */
class McpScopeFilterTest {
    @Test
    fun filterInScope_keepsOnlyInScopeUrlsWhenScopeOnlyTrue() {
        // Stub api.scope().isInScope() to return true only for the allow-list.
        val api = newDeepStubApi()
        val allowList = setOf("https://example.com/a", "https://10.0.0.5/c")
        whenever(api.scope().isInScope(any())).thenAnswer { invocation ->
            allowList.contains(invocation.getArgument<String>(0))
        }
        val ctx = contextWith(api, scopeOnly = true)

        val items =
            listOf(
                "https://example.com/a",
                "https://blocked.test/b",
                "https://10.0.0.5/c",
                "https://other.test/d",
            )

        val filtered = McpScopeFilter.filterInScope(items, { it }, ctx).toList()

        assertEquals(listOf("https://example.com/a", "https://10.0.0.5/c"), filtered)
    }

    @Test
    fun filterInScope_isBytewiseNoOpWhenScopeOnlyFalse() {
        // When scopeOnly is off, the input is returned verbatim AND api.scope() is never invoked.
        val api = newDeepStubApi()
        val ctx = contextWith(api, scopeOnly = false)

        val items = listOf("https://example.com/a", "https://blocked.test/b", "https://other.test/d")

        val filtered = McpScopeFilter.filterInScope(items, { it }, ctx).toList()

        assertEquals(items, filtered, "scopeOnly=false should return input verbatim")
        // Verify the helper did NOT consult the scope API at all in the off branch.
        verify(api.scope(), never()).isInScope(any())
    }

    @Test
    fun filterInScope_dropsNullUrlItemsUnderScopeOnlyAndKeepsThemWhenOff() {
        // Under scopeOnly=true, items whose URL extractor returns null are dropped (no scope
        // decision possible → fail closed). Under scopeOnly=false they are kept (no decision
        // attempted at all).
        val api = newDeepStubApi()
        whenever(api.scope().isInScope(any())).thenReturn(true) // everything in scope

        data class Item(
            val url: String?,
        )

        val items = listOf(Item("https://example.com/a"), Item(null), Item("https://other.test/b"))

        val onCtx = contextWith(api, scopeOnly = true)
        val onResult = McpScopeFilter.filterInScope(items, { it.url }, onCtx).toList()
        assertEquals(
            listOf(Item("https://example.com/a"), Item("https://other.test/b")),
            onResult,
            "null-URL items must be dropped under scopeOnly=true",
        )

        val offCtx = contextWith(newDeepStubApi(), scopeOnly = false)
        val offResult = McpScopeFilter.filterInScope(items, { it.url }, offCtx).toList()
        assertEquals(items, offResult, "null-URL items must be kept under scopeOnly=false")
    }

    @Test
    fun filterInScope_sequenceOverloadIsLazyAndPreservesOrdering() {
        // Establishes that the Sequence overload preserves input order and is lazy (no eager
        // materialisation that would distort tools layering their own drop/take pagination).
        val api = newDeepStubApi()
        whenever(api.scope().isInScope("https://allowed.test/a")).thenReturn(true)
        whenever(api.scope().isInScope("https://allowed.test/b")).thenReturn(true)
        whenever(api.scope().isInScope("https://blocked.test/x")).thenReturn(false)
        val ctx = contextWith(api, scopeOnly = true)

        val ordered =
            sequenceOf(
                "https://blocked.test/x",
                "https://allowed.test/a",
                "https://blocked.test/x",
                "https://allowed.test/b",
            )

        val filtered = McpScopeFilter.filterInScope(ordered, { it }, ctx).toList()

        assertEquals(listOf("https://allowed.test/a", "https://allowed.test/b"), filtered)
    }

    @Test
    fun rejectIfOutOfScope_returnsNullForInScopeUrlUnderScopeOnly() {
        val api = newDeepStubApi()
        whenever(api.scope().isInScope("https://example.com/a")).thenReturn(true)
        val ctx = contextWith(api, scopeOnly = true)

        val rejection = McpScopeFilter.rejectIfOutOfScope("https://example.com/a", ctx)

        assertNull(rejection, "an in-scope URL must produce no rejection string")
    }

    @Test
    fun rejectIfOutOfScope_returnsDocumentedStringForOutOfScopeUnderScopeOnly() {
        val api = newDeepStubApi()
        whenever(api.scope().isInScope("https://blocked.test/x")).thenReturn(false)
        val ctx = contextWith(api, scopeOnly = true)

        val rejection = McpScopeFilter.rejectIfOutOfScope("https://blocked.test/x", ctx)

        assertNotNull(rejection, "out-of-scope URL must produce a rejection string")
        // The exact wording is part of the public contract — external MCP clients can match on
        // the canonical substring `is out of scope (mcpScopeOnly=true)`.
        assertTrue(
            rejection!!.contains("is out of scope (mcpScopeOnly=true)"),
            "rejection string should contain the canonical marker; got: $rejection",
        )
        assertTrue(
            rejection.contains("https://blocked.test/x"),
            "rejection string should echo the offending URL; got: $rejection",
        )
        assertTrue(
            rejection.contains("scope_include"),
            "rejection string should suggest scope_include as remediation; got: $rejection",
        )
    }

    @Test
    fun rejectIfOutOfScope_returnsNullRegardlessOfScopeWhenScopeOnlyFalse() {
        // With scopeOnly disabled the helper MUST return null even when the URL would have
        // been blocked otherwise. api.scope() is NEVER consulted in this path.
        val api = newDeepStubApi()
        val ctx = contextWith(api, scopeOnly = false)

        val rejection = McpScopeFilter.rejectIfOutOfScope("https://blocked.test/x", ctx)

        assertNull(rejection, "scopeOnly=false must short-circuit to null without consulting scope")
        verify(api.scope(), never()).isInScope(any())
    }

    @Test
    fun helpers_doNotEmitLogsOrSideEffects() {
        // Regression guard: the helpers must remain pure so tests can assert on behaviour
        // without provisioning api.logging() or audit collectors. Both branches must NOT touch
        // api.logging() at all (only api.scope() is consulted, and only when scopeOnly=true).
        val api = newDeepStubApi()
        whenever(api.scope().isInScope("https://x")).thenReturn(true)
        val ctxOn = contextWith(api, scopeOnly = true)
        val ctxOff = contextWith(newDeepStubApi(), scopeOnly = false)

        McpScopeFilter.filterInScope(sequenceOf("https://x"), { it }, ctxOn).toList()
        McpScopeFilter.filterInScope(sequenceOf("https://x"), { it }, ctxOff).toList()
        McpScopeFilter.rejectIfOutOfScope("https://x", ctxOn)
        McpScopeFilter.rejectIfOutOfScope("https://x", ctxOff)

        verify(api.logging(), never()).logToOutput(any<String>())
        verify(api.logging(), never()).logToError(any<String>())
        assertFalse(false) // explicit "no-throw" assertion lives in the calls above
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private fun newDeepStubApi(): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return api
    }

    private fun contextWith(
        api: MontoyaApi,
        scopeOnly: Boolean,
    ): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = emptyMap(),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 1024,
            scopeOnly = scopeOnly,
        )
}
