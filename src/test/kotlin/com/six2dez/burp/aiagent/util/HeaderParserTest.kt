package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

/**
 * Bug #66 — pin the contract that protects OpenAI-compatible backends from a malformed
 * `Authorization: Bearer ` header when no API key is configured.
 *
 * The implementation already short-circuits on blank tokens and refuses to overwrite a
 * user-supplied `Authorization` header. These tests exist so that any future refactor of
 * [HeaderParser.withBearerToken] cannot reintroduce the original regression.
 */
class HeaderParserTest {
    @Test
    fun emptyTokenLeavesBaseHeadersUnchanged() {
        val base = mapOf("Content-Type" to "application/json")
        val result = HeaderParser.withBearerToken("", base)
        assertEquals(base, result)
        assertFalse(result.keys.any { it.equals("Authorization", ignoreCase = true) })
    }

    @Test
    fun whitespaceOnlyTokenLeavesBaseHeadersUnchanged() {
        // `trim()` happens inside withBearerToken; whitespace-only tokens must also be a no-op.
        val base = mapOf("Content-Type" to "application/json")
        val result = HeaderParser.withBearerToken("   ", base)
        assertEquals(base, result)
        assertFalse(result.keys.any { it.equals("Authorization", ignoreCase = true) })
    }

    @Test
    fun nonEmptyTokenIsAddedAsBearerWhenAuthorizationIsAbsent() {
        val result = HeaderParser.withBearerToken("xyz", emptyMap())
        assertEquals(mapOf("Authorization" to "Bearer xyz"), result)
    }

    @Test
    fun existingAuthorizationHeaderIsNotOverwritten() {
        val base = mapOf("Authorization" to "Bearer existing")
        val result = HeaderParser.withBearerToken("xyz", base)
        assertEquals(base, result)
    }

    @Test
    fun existingAuthorizationHeaderIsNotOverwrittenCaseInsensitively() {
        // Some users type "authorization: Bearer ..." in lowercase; the guard must still trip.
        val base = mapOf("authorization" to "Bearer existing")
        val result = HeaderParser.withBearerToken("xyz", base)
        assertEquals(base, result)
        // No second key with a different casing should appear.
        assertEquals(1, result.size)
    }
}
