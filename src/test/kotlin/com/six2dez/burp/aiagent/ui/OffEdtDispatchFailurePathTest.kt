package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * CR-04 — a throwing error sink costs a log line and nothing else.
 *
 * `OffEdtDispatch.run`'s failure-path `logError` used to sit OUTSIDE any `try`, on the path to the
 * single `SwingUtilities.invokeLater`. `logError` is `api.logging().logToError` at every production
 * call site, and a Montoya API handle whose extension has been unloaded is not guaranteed to keep
 * accepting calls — which is exactly the co-occurring condition, because that sink is reached only
 * when `work` failed and one reason `work` fails is that the extension is tearing down. A throw there
 * killed the runnable outright: `ChatPanel` never ran its tail, `setSendingState(false)` never fired,
 * `runningTool` kept a token nobody would clear, the completion callback was silently dropped, and the
 * panel sat in UI-SPEC state S3 — Send hidden, input disabled — for the rest of the Burp session with
 * nothing running.
 *
 * **A separate suite rather than three more scenarios in [ChatPanelEdtConfinementTest]**, which already
 * carries an inline `LargeClass` suppression it should not grow past, and whose fixture builds a whole
 * `ChatPanel` these four scenarios do not need — they drive the dispatcher directly, which is the
 * component under test.
 *
 * **Naming constraint (hard), inherited from [ChatPanelTestHarness]'s KDoc.** `build.gradle.kts`
 * excludes `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest` and
 * `*SupervisionTest` under `-PexcludeHeavyTests=true`, which is what the PR gate passes.
 * `*FailurePathTest` carries none of them, so this suite runs on the gate. Do not rename it into that
 * set.
 *
 * **Every timeout here is a deadlock failsafe, never a threshold the work is measured against** —
 * nothing in this file compares an elapsed duration to anything.
 */
class OffEdtDispatchFailurePathTest {
    /**
     * `OffEdtDispatch` is an `object` singleton, so both hooks are process-global.
     *
     * Left registered, this suite would capture — and hold — events emitted by every test class that
     * runs after it, and a stale throwing observer would fail suites that have nothing to do with
     * CR-04 (WR-08). Same `register(null)` discipline as `AuditLogger.registerGlobalEmitter`.
     */
    @BeforeEach
    fun installObservers() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver(null)
    }

    @AfterEach
    fun releaseObservers() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver(null)
    }

    /**
     * CR-04's fatal case: `work` failed AND the error sink throws, which is the pairing the review
     * names as co-occurring rather than hypothetical.
     *
     * Three claims from one drive, and each is a different limb of the damage the unguarded sink did:
     * the EDT tail RAN at all (the busy clear and the completion callback both live in it), the tail
     * received the ORIGINAL throwable rather than the logger's, and the work still recorded as settled.
     *
     * **The original-throwable clause is threat `T-23-07-06`, not decoration.**
     * `ChatPanel.reportFailedToolCall` keys its SC3 `errorClass` audit field off the throwable's own
     * class, so a `Result` that arrived carrying the logger's failure would file every failed tool call
     * under the wrong cause — a defect in the audit log rather than in the UI.
     *
     * Against the unwrapped sink this test fails in-band on the settle await: the worker thread dies
     * before `invokeLater` is ever reached, so no tail is queued and nothing settles.
     */
    @Test
    fun aThrowingErrorSinkDoesNotCostTheEdtTail() {
        val settled = CountDownLatch(1)
        val tail = AtomicReference<Result<String>?>(null)
        OffEdtDispatch.registerSettledObserver { settled.countDown() }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            OffEdtDispatch.run<String>(
                threadName = PROBE_THREAD_NAME,
                label = "failure-path-tail",
                logError = { throw InjectedSinkFailure(SINK_FAILURE) },
                work = { throw InjectedWorkFailure(WORK_FAILURE) },
                onEdt = { result -> tail.set(result) },
            )
            assertTrue(
                settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "CR-04: the work never settled, so the EDT tail was never reached. A throwing logError " +
                    "on the path to invokeLater kills the runnable outright and strands the panel in S3.",
            )
        }

        val result = requireNotNull(tail.get()) { "The EDT tail never ran, so the busy clear and the completion callback were both dropped." }
        val failure = requireNotNull(result.exceptionOrNull()) { "The tail received a success for work that threw." }
        assertEquals(
            InjectedWorkFailure::class.java,
            failure.javaClass,
            "T-23-07-06: the Result must cross the thread boundary carrying the ORIGINAL throwable. " +
                "ChatPanel.reportFailedToolCall keys its SC3 errorClass field off this class, so a " +
                "logger's failure arriving here would file every failed tool call under the wrong cause.",
        )
        assertEquals(WORK_FAILURE, failure.message, "The original failure's message must survive too.")
    }

    /**
     * The tail-handler sink, one level down — a different sink on the other side of the `try`.
     *
     * **The settle clause alone cannot carry this test, and that is measured rather than assumed.**
     * This `logError` sits INSIDE the `try`, so the `finally` runs whether or not it throws and the
     * settle record appears either way. A test asserting only "the observer fired" would pass against
     * the unwrapped sink — precisely the vacuity this phase has shipped repeatedly.
     *
     * What actually changes is where the throwable GOES: unwrapped it escapes the `invokeLater`
     * runnable into the AWT event pump, which has no handler for it and prints it. That escape is the
     * defect, so it is what the second clause reads. The probe that unwraps this sink comes back red on
     * exactly that clause.
     *
     * Kept as its own scenario rather than folded into [aThrowingErrorSinkDoesNotCostTheEdtTail]: the
     * two sinks sit on different sides of the `try` and one clause standing in for both would hide a
     * regression in either.
     */
    @Test
    fun aThrowingErrorSinkInTheTailDoesNotCostTheSettleRecord() {
        val settled = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { settled.countDown() }

        val escaped =
            capturingEventPumpOutput {
                assertTimeoutPreemptively(Duration.ofSeconds(30)) {
                    OffEdtDispatch.run(
                        threadName = PROBE_THREAD_NAME,
                        label = "failure-path-in-tail",
                        logError = { throw InjectedSinkFailure(SINK_FAILURE) },
                        work = { "the work itself succeeds; it is the TAIL that throws" },
                        onEdt = { throw InjectedTailFailure(TAIL_FAILURE) },
                    )
                    assertTrue(
                        settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS),
                        "The work must still record as settled when its tail threw — that is what the finally is for.",
                    )
                }
            }

        assertFalse(
            escaped.contains(SINK_FAILURE),
            "CR-04: a throwing error sink in the EDT tail must not escape into the AWT event pump, " +
                "which has no handler for it. Escaped output was:\n$escaped",
        )
    }

    /**
     * The settle observer itself, in the `finally` — the last sink on the path, and a test-installed one.
     *
     * Same structural point as the scenario above: the observer runs in the `finally`, so "did a
     * subsequent dispatch still settle?" is true either way — the AWT event pump survives an uncaught
     * throwable and keeps dispatching. Both clauses are therefore asserted, and only the second one
     * discriminates. The first is kept because it is the claim a maintainer will actually care about
     * (the helper was not left broken) and it fails loudly if the pump ever stops being forgiving.
     *
     * The observer records BEFORE it throws, so the record is written on the throwing path too and the
     * two-dispatch claim is about both tails rather than about the first one only.
     */
    @Test
    fun aThrowingSettleObserverDoesNotEscapeTheTail() {
        val seen = CopyOnWriteArrayList<String>()
        val bothSettled = CountDownLatch(2)
        OffEdtDispatch.registerSettledObserver { label ->
            seen.add(label)
            bothSettled.countDown()
            if (label == FIRST_LABEL) throw InjectedObserverFailure(OBSERVER_FAILURE)
        }

        val escaped =
            capturingEventPumpOutput {
                assertTimeoutPreemptively(Duration.ofSeconds(30)) {
                    OffEdtDispatch.run(
                        threadName = PROBE_THREAD_NAME,
                        label = FIRST_LABEL,
                        logError = { },
                        work = {
                            Thread.sleep(FIRST_WORK_DELAY_MS)
                            "first"
                        },
                        onEdt = { },
                    )
                    OffEdtDispatch.run(
                        threadName = PROBE_THREAD_NAME,
                        label = SECOND_LABEL,
                        logError = { },
                        work = { "second" },
                        onEdt = { },
                    )
                    assertTrue(
                        bothSettled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS),
                        "A throwing settle observer must not leave the helper unable to run more work. Settled: $seen",
                    )
                }
            }

        assertEquals(listOf(FIRST_LABEL, SECOND_LABEL), seen.toList(), "Both dispatches must settle, in dispatch order.")
        assertFalse(
            escaped.contains(OBSERVER_FAILURE),
            "CR-04: a throwing settle observer must not escape the finally into the AWT event pump. " +
                "Escaped output was:\n$escaped",
        )
    }

    /**
     * The NEGATIVE CONTROL, and the reason the three scenarios above are evidence of a targeted change
     * rather than of a blanket one.
     *
     * `dispatchedObserver` is invoked on the CALLING thread, as `run`'s first statement, before any
     * worker or tail exists. Nothing downstream depends on it, so a throw there is the caller's own bug
     * and must stay visible instead of being swallowed inside a helper. Without this test, all three
     * scenarios above would pass equally well against an edit that wrapped every callback in the file —
     * which would also have hidden that caller-side bug.
     *
     * The second clause pins the throw to the observer's position specifically: no worker is started,
     * so no tail can run.
     */
    @Test
    fun theDispatchObserverIsDeliberatelyNotGuarded() {
        val tailRan = AtomicReference<String?>(null)
        OffEdtDispatch.registerDispatchedObserver { throw InjectedObserverFailure(OBSERVER_FAILURE) }

        val thrown =
            assertThrows<InjectedObserverFailure> {
                OffEdtDispatch.run(
                    threadName = PROBE_THREAD_NAME,
                    label = "dispatch-observer-control",
                    logError = { },
                    work = { "never reached" },
                    onEdt = { result -> tailRan.set(result.getOrNull()) },
                )
            }

        assertEquals(OBSERVER_FAILURE, thrown.message, "The caller must receive its own failure, unaltered.")
        SwingUtilities.invokeAndWait { }
        assertNull(
            tailRan.get(),
            "The throw must come from the dispatch observer, before any worker exists — a tail that ran " +
                "would mean this control was measuring something else.",
        )
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────────────────

/**
 * Deadlock failsafe, in seconds.
 *
 * A bound on a hang, never a threshold the work is measured against — nothing in this file compares an
 * elapsed duration to it. Ten and not sixty because a red probe against the unwrapped tree pays it in
 * full, once per waiting scenario.
 */
private const val FAILSAFE_SECONDS = 10L

/** The worker thread name these scenarios dispatch under; distinct from production's so a thread dump is unambiguous. */
private const val PROBE_THREAD_NAME = "burp-ai-dispatch-probe"

/** The two labels [OffEdtDispatchFailurePathTest.aThrowingSettleObserverDoesNotEscapeTheTail] orders its claim by. */
private const val FIRST_LABEL = "settle-observer-throws"

private const val SECOND_LABEL = "settle-observer-recovers"

/**
 * Permanent delay in the first worker of [OffEdtDispatchFailurePathTest.aThrowingSettleObserverDoesNotEscapeTheTail], in milliseconds.
 *
 * It widens the first worker so that a test which assumed settles arrive in dispatch order fails on
 * every run instead of a few times in thousands (measured: 4 in 5000 quiet, 1 in 5000 under CPU
 * contention). Nothing compares an elapsed duration to it, consistent with this file's KDoc.
 */
private const val FIRST_WORK_DELAY_MS = 50L

/** Unique markers, so an assertion reading captured output cannot match something another test printed. */
private const val WORK_FAILURE = "CR-04 probe: the unit of work exploded"

private const val SINK_FAILURE = "CR-04 probe: the error sink exploded"

private const val TAIL_FAILURE = "CR-04 probe: the EDT tail exploded"

private const val OBSERVER_FAILURE = "CR-04 probe: the observer exploded"

/** The failure injected into the unit of work. Named so it can never be confused with a JUnit assertion failing for real. */
private class InjectedWorkFailure(
    message: String,
) : RuntimeException(message)

/** The failure injected into `logError` — the sink CR-04 says must not cost the tail. */
private class InjectedSinkFailure(
    message: String,
) : RuntimeException(message)

/** The failure injected into the EDT tail itself, so the tail-handler sink is reached. */
private class InjectedTailFailure(
    message: String,
) : RuntimeException(message)

/** The failure injected into a registered observer. */
private class InjectedObserverFailure(
    message: String,
) : RuntimeException(message)

/**
 * Runs [body] with `System.err` captured, and returns everything the AWT event pump printed.
 *
 * **This is the only surface on which "a throwable escaped the tail" is observable, and that is a
 * measured constraint rather than a stylistic choice.** `SwingUtilities.invokeLater` wraps its runnable
 * in an `InvocationEvent` constructed WITHOUT `catchThrowables`, so a throwable escaping the runnable
 * propagates into `EventDispatchThread`, which has no installed handler and prints it. The event pump
 * then carries on dispatching — which is exactly why the "a later dispatch still works" clause cannot
 * carry those tests on its own, and why this one has to exist.
 *
 * **The `invokeAndWait` drain is the happens-before that makes the read deterministic.** The pump
 * handles and prints the escaped throwable inline, while dispatching the offending event; an empty
 * runnable queued afterwards cannot run until that dispatch has completed. Without it the test thread
 * could read the buffer before the EDT had written to it.
 *
 * Safe to swap `System.err` globally: `build.gradle.kts` configures no parallel forks and no JUnit
 * parallel execution, so exactly one test runs at a time in this JVM.
 */
private fun capturingEventPumpOutput(body: () -> Unit): String {
    val buffer = ByteArrayOutputStream()
    val original = System.err
    System.setErr(PrintStream(buffer, true, StandardCharsets.UTF_8))
    try {
        body()
        SwingUtilities.invokeAndWait { }
    } finally {
        System.setErr(original)
    }
    return buffer.toString(StandardCharsets.UTF_8)
}
