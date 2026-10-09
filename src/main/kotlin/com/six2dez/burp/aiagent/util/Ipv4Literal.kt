package com.six2dez.burp.aiagent.util

/**
 * Pure, network-free parser for IPv4 literals written in any `inet_aton` notation (SEC-07).
 *
 * [parse] maps a host string to four big-endian address bytes, or to null when the string is not an
 * IPv4 literal. It accepts the classic `inet_aton` grammar: one to four dot-separated parts, each
 * part decimal, octal (leading `0`) or hexadecimal (leading `0x`/`0X`), with the last part absorbing
 * every byte the preceding parts did not supply.
 *
 * | parts | form      | per-part maxima                | assembled 32-bit value      |
 * |-------|-----------|--------------------------------|-----------------------------|
 * | 4     | `a.b.c.d` | a,b,c,d <= 255                 | `a<<24 | b<<16 | c<<8 | d`   |
 * | 3     | `a.b.c`   | a,b <= 255; c <= 65 535        | `a<<24 | b<<16 | c`         |
 * | 2     | `a.b`     | a <= 255; b <= 16 777 215      | `a<<24 | b`                 |
 * | 1     | `a`       | a <= 4 294 967 295             | `a`                         |
 *
 * ### Why this parser exists at all
 *
 * `java.net.InetAddress.getByName` is NOT an `inet_aton` parser. Measured on JDK 21 (2026-08-22),
 * `InetAddress.getByName("0177.0.0.1")` returns `/177.0.0.1` — it reads `0177` as decimal 177, not
 * as octal 127. Delegating the octal form to the JDK would classify a loopback address as a public
 * one. Do not "simplify" this file away in favour of the JDK call; the two disagree by design.
 *
 * ### Why the file references no `java.net` type
 *
 * "Performs no name resolution" is a property of this file's type signature rather than a promise in
 * prose: the file maps a `String` to a `ByteArray` and imports nothing that could touch the network.
 * Classification is the caller's job — see [SsrfGuard], which feeds these bytes to
 * `InetAddress.getByAddress`, an API that cannot resolve.
 *
 * There is deliberately no `Regex` here either, so the parser has no ReDoS surface and the repo's
 * `SafeRegex` access budget is never involved. Work is bounded to O(length) by [MAX_LITERAL_LENGTH].
 */
object Ipv4Literal {
    /**
     * Hard cap on the input length, so a pathological string cannot drive unbounded work.
     * Generous: the longest form anyone writes in practice (`0377.0377.0377.0377`) is 19 characters.
     *
     * Exposed as `internal` rather than `private` so that `Ipv4LiteralTest` can build its over-long
     * input from `MAX_LITERAL_LENGTH + 1` characters and track this constant instead of drifting
     * from it. Every other constant in this file is private.
     */
    internal const val MAX_LITERAL_LENGTH = 45

    private const val MAX_PARTS = 4
    private const val IPV4_BYTES = 4
    private const val BITS_PER_BYTE = 8
    private const val RADIX_HEX = 16
    private const val RADIX_OCTAL = 8
    private const val RADIX_DECIMAL = 10
    private const val MAX_OCTET = 255L
    private const val MAX_TWO_BYTE = 65_535L
    private const val MAX_THREE_BYTE = 16_777_215L
    private const val MAX_FOUR_BYTE = 4_294_967_295L

    private const val HEX_PREFIX = "0x"
    private const val HEX_DIGITS = "0123456789abcdefABCDEF"
    private const val OCTAL_DIGITS = "01234567"
    private const val DECIMAL_DIGITS = "0123456789"

    /**
     * Parses [host] as an IPv4 literal and returns its four big-endian address bytes, or null when
     * [host] is not an IPv4 literal in any accepted notation.
     *
     * Rejection is total and silent: a hostname, a malformed literal, an out-of-range part and an
     * over-long string all return null. No exception is thrown and no lookup is attempted.
     */
    fun parse(host: String): ByteArray? =
        host
            .takeIf { it.isNotEmpty() && it.length <= MAX_LITERAL_LENGTH }
            ?.split('.')
            ?.takeIf(::hasParsableShape)
            ?.let(::parseParts)

    /**
     * Rejecting empty parts is the single rule that also rejects a leading dot, a trailing dot and a
     * doubled dot, so none of those needs a special case.
     */
    private fun hasParsableShape(parts: List<String>): Boolean = parts.size <= MAX_PARTS && parts.none(String::isEmpty)

    private fun parseParts(parts: List<String>): ByteArray? {
        val values = parts.map { parsePart(it) }
        return if (values.contains(null)) null else combine(values.filterNotNull())?.let(::toBytes)
    }

    private fun parsePart(part: String): Long? {
        val radix = partRadix(part)
        val digits = if (radix == RADIX_HEX) part.substring(HEX_PREFIX.length) else part
        return digitsToLongOrNull(digits, radix)
    }

    private fun partRadix(part: String): Int =
        when {
            part.startsWith(HEX_PREFIX, ignoreCase = true) -> RADIX_HEX
            part.length > 1 && part[0] == '0' -> RADIX_OCTAL
            else -> RADIX_DECIMAL
        }

    /**
     * Validates every character against the radix alphabet BEFORE parsing. That check is also what
     * rejects a leading `+` or `-`, so signs need no special case, and it keeps the accepted digits
     * ASCII-only. [String.toLongOrNull] then returns null on overflow rather than wrapping, which is
     * how the 32-bit maxima below stay meaningful (A-25-08: every intermediate value is a `Long`).
     */
    private fun digitsToLongOrNull(
        digits: String,
        radix: Int,
    ): Long? {
        val alphabet =
            when (radix) {
                RADIX_HEX -> HEX_DIGITS
                RADIX_OCTAL -> OCTAL_DIGITS
                else -> DECIMAL_DIGITS
            }
        return if (digits.isEmpty() || digits.any { it !in alphabet }) null else digits.toLongOrNull(radix)
    }

    private fun combine(values: List<Long>): Long? =
        when {
            values.dropLast(1).any { it > MAX_OCTET } -> null
            values.last() > maxForTrailing(values.size) -> null
            else -> foldParts(values)
        }

    /**
     * Maximum value of the last part, which absorbs every byte the preceding parts did not supply.
     * The subject is the number of absorbed bytes beyond the first: 0 for a dotted quad, 3 for the
     * single-part form.
     */
    private fun maxForTrailing(parts: Int): Long =
        when (IPV4_BYTES - parts) {
            0 -> MAX_OCTET
            1 -> MAX_TWO_BYTE
            2 -> MAX_THREE_BYTE
            else -> MAX_FOUR_BYTE
        }

    private fun foldParts(values: List<Long>): Long =
        values.dropLast(1).foldIndexed(values.last()) { index, acc, value ->
            acc or (value shl (BITS_PER_BYTE * (IPV4_BYTES - 1 - index)))
        }

    private fun toBytes(value: Long): ByteArray =
        ByteArray(IPV4_BYTES) { index ->
            ((value shr (BITS_PER_BYTE * (IPV4_BYTES - 1 - index))) and MAX_OCTET).toByte()
        }
}
