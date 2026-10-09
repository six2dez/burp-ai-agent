package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.config.Defaults

/**
 * REL-07 / SC3 / SC4 — a bounded, monitor-guarded accumulator for a CLI subprocess's stdout.
 *
 * **Which threads race.** The daemon thread `burp-ai-agent-cli-reader` appends every line it reads
 * from the subprocess, while the caller thread reads the accumulated value on three paths: after the
 * timeout `readerThread.join(2000)`, after the non-zero-exit `join`, and on the success path. That
 * join is bounded at two seconds and the reader is a daemon that keeps appending if the join expires,
 * so the two threads genuinely overlap. Sharing a plain unsynchronised accumulator between them
 * establishes no happens-before edge, which means a read can observe a partially published state.
 * That is the hazard this class closes — every append and every read takes the one monitor below.
 * (The precise shape a partially published read would take is not asserted here: the ABSENCE of the
 * happens-before edge is what is documented, not a specific exception type.)
 *
 * **Retention is the HEAD, never the tail.** `String.take(n)` returns the FIRST n characters, so both
 * `CliBackend` error paths already show the head of the captured output — the local there is named
 * `tail` and so is `buildTimeoutMessage`'s parameter, but both carry the head. A tail-retaining
 * buffer would silently change what `buildTimeoutMessage` reports and would force a rewrite of
 * `CliTimeoutMessageTest` for no requirement.
 *
 * **The cap's derivation.** `MAX_CLI_OUTPUT_CHARS` in `Defaults` is 256 Ki UTF-16 characters — a
 * round power of two, chosen so the size is self-explanatory. For scale it is *approximately* eight
 * times `Defaults.LARGE_PROMPT_THRESHOLD` (which is 32 000, so the true ratio is 8.192: a clean
 * eightfold of 32 000 would be 256 000, whereas 262 144 is exactly eight times 32 768), and roughly
 * 131 times the 2000-character head the two CLI error paths take. It is bounded from ABOVE by memory
 * amplification: the success path feeds this value to `stripAnsiCodes`, whose four sequential
 * full-string regex passes each allocate a fresh full-size string, so peak transient heap is roughly
 * five times the cap. Those four passes use raw `Regex`, not the project's `SafeRegex` access
 * budget wrapper, so bounding the input is the only protection they have. That residual is named here
 * deliberately rather than left implicit.
 *
 * **Truncation is visible, and only when it happened.** When the cap is reached, [snapshot] appends
 * `Defaults.CLI_OUTPUT_TRUNCATION_MARKER` so the caller can tell. When it was not reached the marker
 * is absent, which is what lets a legitimate model answer round-trip byte-identically — the success
 * path's value IS the model's response, not a diagnostic tail, so an unconditional suffix would
 * corrupt every CLI backend's output.
 *
 * **Visibility:** `internal` so `CliOutputBufferTest` can drive it in pure JVM with no subprocess,
 * the same reason `buildTimeoutMessage` and `buildCopilotCommand` are `internal`. It is not part of
 * the backend's public surface.
 */
internal class CliOutputBuffer(
    private val maxChars: Int = Defaults.MAX_CLI_OUTPUT_CHARS,
) {
    init {
        require(maxChars > 0) { "maxChars must be > 0" }
    }

    private val lock = Any()
    private val retained = StringBuilder()
    private var truncatedFlag = false

    /** Appends [line] and one newline, stopping at the cap and flagging that it did. */
    fun appendLine(line: String) {
        synchronized(lock) {
            val room = maxChars - retained.length
            if (room <= 0) {
                truncatedFlag = true
                return
            }
            val incoming = line + "\n"
            if (incoming.length <= room) {
                retained.append(incoming)
                return
            }
            // A-EDGE-5: the cap counts UTF-16 chars, not code points, so a cut at exactly `room` can
            // land between the two halves of a surrogate pair and leave an unpaired high surrogate at
            // the end of the snapshot. When the last character that would survive is a high
            // surrogate, cut one character earlier instead.
            var cut = room
            if (incoming[cut - 1].isHighSurrogate()) cut -= 1
            retained.append(incoming, 0, cut)
            truncatedFlag = true
        }
    }

    /** The retained head, with the truncation marker appended only if the cap was actually reached. */
    fun snapshot(): String {
        synchronized(lock) {
            val head = retained.toString()
            return if (truncatedFlag) head + Defaults.CLI_OUTPUT_TRUNCATION_MARKER else head
        }
    }

    /** True once at least one character was dropped because the cap was reached. */
    val truncated: Boolean
        get() = synchronized(lock) { truncatedFlag }

    /** The number of retained characters, excluding any truncation marker. */
    val length: Int
        get() = synchronized(lock) { retained.length }
}
