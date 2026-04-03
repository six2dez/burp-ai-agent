package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class AgentSupervisorRestartPolicyTest {

    @Test
    fun repeatedImmediateCrashesSuppressAutoRestart() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(true)
        val registry = BackendRegistry(api)
        val launches = AtomicInteger(0)
        val failingBackend = FailingBackend(launches)
        backendsField(registry).apply {
            clear()
            put(failingBackend.id, failingBackend)
        }

        val workerPool = NoOpExecutorService()
        val supervisor = AgentSupervisor(
            api = api,
            registry = registry,
            audit = mock<AuditLogger>(),
            workerPool = workerPool
        )

        try {
            supervisor.applySettings(
                TestSettings.baselineSettings(preferredBackendId = failingBackend.id).copy(
                    autoRestart = true
                )
            )
            assertTrue(supervisor.startOrAttach(failingBackend.id))

            repeat(4) {
                lastRestartAt(supervisor).set(0L)
                invokeCheckHealth(supervisor)
            }

            val suppressed = autoRestartSuppressed(supervisor).get()
            assertTrue(!suppressed.isNullOrBlank())
            assertTrue(suppressed!!.contains("Auto-restart suppressed"))
            assertTrue(launches.get() >= 1)
        } finally {
            supervisor.shutdown()
            registry.shutdown()
            workerPool.shutdownNow()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun backendsField(registry: BackendRegistry): ConcurrentHashMap<String, AiBackend> {
        val field = registry.javaClass.getDeclaredField("backends")
        field.isAccessible = true
        return field.get(registry) as ConcurrentHashMap<String, AiBackend>
    }

    @Suppress("UNCHECKED_CAST")
    private fun autoRestartSuppressed(supervisor: AgentSupervisor): AtomicReference<String?> {
        val field = supervisor.javaClass.getDeclaredField("autoRestartSuppressed")
        field.isAccessible = true
        return field.get(supervisor) as AtomicReference<String?>
    }

    private fun lastRestartAt(supervisor: AgentSupervisor): AtomicLong {
        val field = supervisor.javaClass.getDeclaredField("lastRestartAt")
        field.isAccessible = true
        return field.get(supervisor) as AtomicLong
    }

    private fun invokeCheckHealth(supervisor: AgentSupervisor) {
        val method = supervisor.javaClass.getDeclaredMethod("checkHealth")
        method.isAccessible = true
        method.invoke(supervisor)
    }

    private class FailingBackend(private val launches: AtomicInteger) : AiBackend {
        override val id: String = "failing-backend"
        override val displayName: String = "Failing Backend"

        override fun launch(config: BackendLaunchConfig): AgentConnection {
            launches.incrementAndGet()
            return DeadConnection
        }
    }

    private object DeadConnection : AgentConnection {
        override fun isAlive(): Boolean = false

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?
        ) {
            onComplete(IllegalStateException("dead"))
        }

        override fun stop() = Unit
    }

    private class NoOpExecutorService : AbstractExecutorService() {
        @Volatile
        private var shutdown = false

        override fun shutdown() {
            shutdown = true
        }

        override fun shutdownNow(): MutableList<Runnable> {
            shutdown = true
            return Collections.emptyList()
        }

        override fun isShutdown(): Boolean = shutdown

        override fun isTerminated(): Boolean = shutdown

        override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = true

        override fun execute(command: Runnable) {
            // Intentionally no-op to keep auto-restart submissions pending in this test.
        }
    }
}
