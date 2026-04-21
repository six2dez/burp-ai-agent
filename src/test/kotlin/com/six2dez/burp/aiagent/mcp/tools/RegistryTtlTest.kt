package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.scanner.ScanTask
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class RegistryTtlTest {
    @AfterEach
    fun resetRegistries() {
        ScannerTaskRegistry.clear()
        ScannerTaskRegistry.configureTtlMinutes(120)
        CollaboratorRegistry.clear()
        CollaboratorRegistry.configureTtlMinutes(60)
    }

    @Test
    fun scannerTaskRegistry_expiresEntriesByTtl() {
        val task = mock<ScanTask>()
        ScannerTaskRegistry.configureTtlMillisForTests(5)
        val id = ScannerTaskRegistry.put(task)

        assertSame(task, ScannerTaskRegistry.get(id))
        Thread.sleep(15)
        assertNull(ScannerTaskRegistry.get(id))
    }

    @Test
    fun collaboratorRegistry_expiresEntriesByTtl() {
        val client = mock<CollaboratorClient>()
        CollaboratorRegistry.configureTtlMillisForTests(5)
        CollaboratorRegistry.put("secret", client)

        assertSame(client, CollaboratorRegistry.get("secret"))
        Thread.sleep(15)
        assertNull(CollaboratorRegistry.get("secret"))
    }
}
