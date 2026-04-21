package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class McpStdioBridgeCompatibilityTest {
    @Test
    fun stdioBridge_doesNotExposeReflectionHelperMethods() {
        val declared =
            McpStdioBridge::class.java.declaredMethods
                .map { it.name }
                .toSet()

        assertFalse(declared.contains("createSource"))
        assertFalse(declared.contains("createSink"))
    }
}
