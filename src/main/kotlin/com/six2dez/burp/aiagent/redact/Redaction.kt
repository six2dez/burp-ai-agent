package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.config.Defaults
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class RedactionPolicy(
    val stripCookies: Boolean,
    val redactTokens: Boolean,
    val anonymizeHosts: Boolean,
) {
    companion object {
        fun default() =
            RedactionPolicy(
                stripCookies = true,
                redactTokens = true,
                anonymizeHosts = true,
            )

        fun fromMode(mode: PrivacyMode): RedactionPolicy =
            when (mode) {
                PrivacyMode.STRICT ->
                    RedactionPolicy(
                        stripCookies = true,
                        redactTokens = true,
                        anonymizeHosts = true,
                    )
                PrivacyMode.BALANCED ->
                    RedactionPolicy(
                        stripCookies = true,
                        redactTokens = true,
                        anonymizeHosts = false,
                    )
                PrivacyMode.OFF ->
                    RedactionPolicy(
                        stripCookies = false,
                        redactTokens = false,
                        anonymizeHosts = false,
                    )
            }
    }
}

enum class PrivacyMode {
    STRICT,
    BALANCED,
    OFF,
    ;

    companion object {
        fun fromString(raw: String?): PrivacyMode = entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: BALANCED
    }
}

object Redaction {
    // (PRIV-05) 27-05 / D-27-12: WHY THIS RULE GOES THROUGH THE SHARED BOUNDARY COMPOSER.
    //
    // This rule carried the IDENTICAL defect the two cookie rules did — `(?im)^…:\s*.+$`, anchored
    // to a REAL line start — and so it could not fire on the MCP tool-RESULT shape, where the raw
    // HTTP message lives inside a JSON string and every CRLF is the two literal characters
    // backslash-r / backslash-n. MEASURED on the compiled shipped classes against that shape, salt
    // `probe-salt`:
    //
    //     STRICT   APIKEY  SURVIVES        BALANCED APIKEY  SURVIVES
    //     STRICT   BEARER  STRIPPED        BALANCED BEARER  STRIPPED
    //
    // `Authorization: Bearer …` survived only BY LUCK: the un-anchored bearerRegex below happened to
    // claim its VALUE while this rule missed the line entirely. A plain-token `X-API-Key` has no such
    // luck — it is not bearer-, basic- or JWT-shaped, and it is a header VALUE rather than a quoted
    // JSON key so jsonSecretKeyRegex cannot reach it either. It left the process VERBATIM under the
    // strongest privacy mode, and an API key is a longer-lived credential than a session cookie.
    //
    // ONLY THE BOUNDARY CHANGED. The name alternation below is the one that shipped, character for
    // character, all 16 names: this rule recognises exactly the headers it always claimed to. What
    // changed is what counts as the start of a line — see logicalLineHeaderRule and the fragment
    // rationale further down, which this rule now shares with cookieHeaderRegex and
    // setCookieHeaderRegex rather than restating.
    //
    // SHARING THE COMPOSER MEANS SHARING ITS COST, not only its fix: this rule now carries the
    // D-27-15 over-match bound too. A raw value that literally contains a backslash followed by `r`
    // or `n` — a Windows path, a regex in a body — is indistinguishable from an encoded newline, so
    // an `authorization:`-class run immediately after one is treated as a logical line start and its
    // value is replaced. Over-redaction, fail-safe in direction, and stated rather than discovered.
    //
    // WHAT THIS DOES NOT CLOSE. Token redaction is NOT complete. The alternation is an exact-name
    // list, and every vendor auth header outside it — `X-Shopify-Access-Token`, `X-Amz-Security-Token`
    // and their kind — is matched by NO rule here at all. That gap predates this change, is unchanged
    // by it, and stays recorded as an open item in CONCERNS.md. A reader who takes this comment as
    // "auth headers are handled" has read it wider than it is written.
    private val authHeaderRegex =
        logicalLineHeaderRule(
            "(" +
                "authorization|proxy-authorization|" +
                "x-api-key|api-key|x-api-secret|api-secret|x-client-secret|" +
                "x-auth-token|auth-token|x-access-token|access-token|" +
                "x-session-token|session-token|x-csrf-token|csrf-token|x-xsrf-token" +
                ")",
        )

    // The trailing =* captures base64/base64url padding on the token. The token char-class
    // excludes '=', so =* greedily consumes ANY run of '=' immediately after the token — including
    // '=' that merely follow the credential (WR-04). This is intentional and fail-safe: it
    // over-redacts trailing '=' rather than risk leaking part of a padded token. The whole
    // Authorization header is already replaced by authHeaderRegex; bearerRegex additionally covers
    // bearer tokens embedded in bodies/JSON/free text, where a few trailing '=' being swallowed is
    // a benign over-redaction, not a leak.
    private val bearerRegex = Regex("(?i)bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*")
    private val basicAuthRegex = Regex("(?i)basic\\s+[A-Za-z0-9\\+\\/=]+")

    // W-A: an RFC 9110 field-name is a token. Used as the "rest of the name" either side of the
    // literal "cookie".
    //
    // (PRIV-05) 27-10: this class was [A-Za-z0-9-]* until plan 27-10 — the value BEFORE the widening,
    // recorded here as history, not as what ships. '_' is a legal RFC 9110 tchar and names carrying it
    // occur (my_cookie, X_Cookie, session_cookie were all measured reaching an AI backend verbatim
    // under STRICT and BALANCED). THE WIDTH RULE, and the reason it points in this direction: this
    // class must be AT LEAST AS WIDE as whatever isCookieHeaderName admits, because one of that
    // predicate's three consumers — PassiveAiScannerFilters.sanitizeHeadersForPrompt — is an ADMITTER,
    // not a redactor. A name the predicate claims but this class cannot match is put on the outbound
    // prompt and then not removed. Widen this constant to close such a gap; never narrow the predicate.
    //
    // THE BOUND, so the next reader does not over-read the fix: this class is still NARROWER than the
    // full tchar set. The thirteen remaining tchars (! # $ % & ' * + . ^ ` | ~) are enumerated in
    // CookieHeaderNameWidthTest.NOT_COVERED_TCHARS and filed as AR-27-10.
    private const val COOKIE_NAME_PART = "[A-Za-z0-9_-]*"

    // (PRIV-05) D-27-01: the ONE lowercase literal that says what "a cookie header" is named. Both
    // regexes below and isCookieHeaderName are composed from it, so a rename is a compile-wide change
    // rather than three hand-kept copies that can drift apart — which is exactly how the v0.10.0
    // milestone audit found the tool-result path testing a narrower rule than the prompt path.
    private const val COOKIE_NAME_TOKEN = "cookie"

    // W-A: both rules key on a header whose NAME CONTAINS "cookie", not on the two exact names
    // "cookie"/"set-cookie". The phase verifier measured five real names — Cookie2, X-Cookie,
    // Set-Cookie2, X-Original-Cookie, X-Forwarded-Cookie — reaching an AI backend VERBATIM under
    // STRICT and BALANCED, because sanitizeHeadersForPrompt admits any header whose lowercased name
    // contains "cookie" while these two rules only removed the two canonical spellings. Matching the
    // same predicate the prompt builder admits on is what closes that gap, and it is bounded and
    // complete in a way the open-ended vendor auth-header list below is not.
    //
    // Over-redacting a benign header that merely contains "cookie" in its name is accepted
    // (T-21-WA3): any *cookie* header is cookie-bearing by convention, and only the VALUE is removed.
    //
    // The two regexes stay mutually exclusive rather than merely ordered: the negative lookahead
    // keeps "*set-cookie*" names out of cookieHeaderRegex, so a response header is still reported by
    // the set-cookie rule and never by the request-cookie one, whatever order apply() runs them in.
    //
    // ── (PRIV-05) 27-04 / D-27-06 · D-27-07 · D-27-08 · D-27-15: WHAT COUNTS AS A LINE START ──
    //
    // These rules recognise FOUR logical line starts (two at 27-04, a third at 27-11, a fourth at
    // 27-17 when AR-27-09 was closed by fix), because the MCP tool-RESULT path emits a raw HTTP
    // message with no real newline in it. All four are enumerated in the 27-11 / 27-17 block further
    // down, together with the shapes that are still not starts.
    // `mcp/schema/Serialization.kt` puts the whole raw
    // message into a JSON string (`request = request()?.toString()`), and `toolJson.encodeToString`
    // then escapes every CR and LF into the two literal characters backslash-r / backslash-n. The
    // shipped `(?im)^` anchor therefore never landed, and canonical `Cookie:` / `Set-Cookie:` values
    // reached the configured AI backend VERBATIM under STRICT and BALANCED through
    // `proxy_http_history`, `proxy_http_history_regex`, `site_map`, `site_map_regex` and
    // `scanner_issues`. Measured on the shipped compiled class: 1 match on multi-line input, 0 on the
    // JSON-encoded form of the same bytes.
    //
    // WHY TWO BRANCHES AND NOT ONE. The REAL-LINE branch keeps the value tail that shipped, character
    // for character (see REAL_LINE_HEADER_VALUE), so multi-line behaviour is unchanged BY CONSTRUCTION
    // rather than by hope; the anchor is not removed, which is what AR-27-01 / AR-27-02 were deferred
    // to avoid. 27-17 widened that branch's START from `^` to [REAL_LINE_START] and nothing else — a
    // PROVEN strict superset of `^`, so "unchanged by construction" still holds for every input the
    // shipped anchor matched. The double-quote value terminator the JSON shape needs lives on the ESCAPED branch
    // ONLY, because that branch's start boundary has already proved the match is inside a JSON
    // string. Hoisting the quote into a single shared tail is an UNDER-REDACTION regression on the
    // primary path: measured, `Cookie: a="q"; session=<value>` — a DQUOTE-wrapped value RFC 6265
    // permits — stops at the first quote and leaks the tail. No shipped RedactionTest fixture puts a
    // quote in a cookie value, so that regression would ship green.
    //
    // WHY THE ESCAPED TAIL CONSUMES ESCAPE PAIRS. Terminating on "a quote not preceded by a
    // backslash" emits INVALID JSON whenever the value ends in a backslash and the header is the last
    // content in the string: JSON encoding doubles backslashes, so the character before the closing
    // quote is a backslash for a value ending in ONE backslash and for one ending in TWO, the
    // lookbehind suppresses the terminator in both, and the match runs to end-of-input. Parity over a
    // backslash run is the real predicate and a one-character look-back cannot count it. Consuming
    // `\\.` as one atomic unit enforces parity by tokenization instead, so the tail can never come to
    // rest between a backslash and the character it escapes.
    //
    // STATED BOUND (D-27-15), which is a real cost and not a caveat: the escaped-newline boundary is
    // a fixed-width two-character lookbehind and cannot tell a JSON-encoded newline from a raw
    // message that literally contained a backslash followed by `r` or `n` — a Windows path, a regex
    // in a body. A `cookie:` run immediately after such a sequence is treated as a logical line start
    // and its value is stripped. That is OVER-redaction, fail-safe in direction, and cheaper to state
    // than to fix, since fixing it needs the same backslash-parity look-back declined above.
    //
    // SCOPE OF THE COMPOSER, deliberately, and MEASURED rather than assumed (27-04 + 27-05 / D-27-13).
    // Exactly THREE rules are built from `logicalLineHeaderRule`: `cookieHeaderRegex`,
    // `setCookieHeaderRegex` (plan 27-04) and `authHeaderRegex` (plan 27-05 / D-27-12, declared at the
    // top of this object with its own measured before-state). `LogicalLineBoundaryScopeTest` pins that
    // set, so a fourth rule adopting the composer, or one of these three dropping it, reads as a data
    // change rather than as a silent regex edit.
    //
    // `hostHeaderRegex` is the DELIBERATE EXCLUSION and stays on the real-line boundary only, so a
    // `Host:` header is still NOT anonymised on the serialized emission shape. Two measured reasons,
    // neither aesthetic: it rewrites through `anonymizeHost`, which records into a de-anonymisation
    // map that `RedactionHostMapBoundTest` exists to bound, and firing that on every raw message of
    // every `site_map` / `proxy_http_history` result is an unmeasured load change on that bound; and
    // `SiteMapEntry.url` (`mcp/schema/Serialization.kt:79`) carries the SAME host VERBATIM with no
    // `maybeAnonymizeUrl` in front of it, so anonymising the header alone would produce a JSON object
    // whose `request` field is anonymised and whose `url` field is not — a control that reads as
    // closed and is not. Recorded as open finding AR-27-04 for plan 27-06 with the probe output
    // quoted, not silently fixed and not silently dropped.
    //
    // ── (PRIV-05) 27-11 · THE THIRD START, AND THE FOURTH THAT IS STILL NOT ONE ──
    //
    // The recognised starts, in the order the composer offers them:
    //   1. a REAL line start      `(?im)^`        — the pattern that shipped
    //   2. a JSON-ESCAPED newline `(?<=\\[rn])`   — plan 27-04, the serialized emission shape
    //   3. a JSON STRING VALUE open `(?<=:")`     — plan 27-11, narrowed by 27-14, this one
    //
    // Start 3 exists because a header that is the FIRST content of a JSON string value has neither a
    // real `^` nor a preceding escaped newline, so the CANONICAL `Cookie:` header — not a variant,
    // not an underscore name, not a typed parameter — survived STRICT there. MEASURED on the shipped
    // classes in round 3, with the positive control firing in the SAME run, which is what makes it a
    // statement about the rule's REACH rather than a broken probe:
    //
    //   {"notes":"Cookie: a=SECRET1\r\nX: y"}  STRICT ->  unchanged            (the gap)
    //   {"notes":"X: y\r\nCookie: a=SECRET9"}  STRICT ->  Cookie: [STRIPPED]   (the control)
    //
    // Reachable through `HttpRequestResponse.notes`, which carries ANALYST annotations, so its first
    // characters are whatever the analyst typed. The `request` field always begins `GET / HTTP/1.1`,
    // which is why the fourteen pinned emission sites' PRIMARY payload was never affected — and why
    // this survived three rounds of verification unseen.
    //
    // THE TWO LOOKBEHINDS ARE SPELLED SEPARATELY and each is FIXED-WIDTH: width two on the escaped
    // newline, width two on the string VALUE open, grouped non-capturing. Collapsing them into ONE
    // lookbehind holding an alternation of differing widths is shorter and silently trades away the
    // 2.4x measured just below, because Java would then try two look-back widths at every position of
    // every serialized emission. If a fourth start is ever added, add a THIRD separate lookbehind.
    //
    // THE COST OF START 3, in BOTH directions, at the rigour D-27-15's paragraph above is written to
    // — because start 3's cost went unstated for one round and that omission is what shipped a
    // correctness regression on live 1.0.0 code.
    //
    // (a) WHAT THE BARE QUOTE COST, and it is a defect this round REPAIRED rather than history that
    // is still live. 27-11 spelled this start as a BARE double quote `(?<=")` while calling it a JSON
    // string open. A bare double quote is not a JSON string open, and all THREE composed rules
    // inherited the error. MEASURED on the shipped classes, five non-JSON carriers, identical under
    // STRICT and BALANCED — an HTML attribute value (`<div title="Cookie: …">`), a JS string literal
    // argument (`foo("cookie: …", KEEPME)`), a quoted CSV field (`1,"x-cookie: …",KEEPTAIL`), a
    // `Set-Cookie:` header NAMED in ordinary quoted prose, and the same in prose reaching
    // `authHeaderRegex` (`"authorization: Bearer required"`). All five had their tails replaced. On a
    // 1714-character `proxy_http_history`-shaped tool result the same start DESTROYED 1589 of 1714
    // characters and all forty content markers after the attribute, leaving JSON that still parsed —
    // so every shape assertion stayed green and the model read a truncated body. That is precisely
    // the functional regression `redactCookieSections`' comment below argues against, committed by
    // this file against its own stated standard.
    //
    // (b) WHAT THE NARROWING COSTS, and it is accepted rather than hidden. THE MECHANISM FIRST AND
    // THE FAMILIES SECOND — because the previous spelling of this paragraph named ONE family as
    // though it were the whole cost, and a severity was then derived from that short list
    // (27-REVIEW-3 CR-01, corrected here and in 26-SECURITY.md's AR-27-11 row together).
    //
    // THE MECHANISM, IN ONE SENTENCE: `:"` is the two LITERAL characters COLON then QUOTE, so ANY
    // shape that interposes a character BETWEEN the colon and the quote — a space, or the backslash
    // of an escaped quote — and any shape carrying NO colon before the quote at all, is not a
    // recognised start. FOUR families follow from that rule. All four MEASURED end-to-end through
    // [apply] on the shipped classes, byte-identical in and out under STRICT *and* BALANCED, with a
    // compact-shaped control STRIPPING in the same run, and all three composed rules
    // (`cookieHeaderRegex`, `setCookieHeaderRegex`, `authHeaderRegex`) losing the same four:
    //
    //   {"r":"…{\"k\":\"Cookie: a=S\"}"}  a NESTED / ESCAPED string value open. The two characters
    //                                    before the header are `\` and `"`, not `:` and `"`. THIS
    //                                    ONE SITS ON THE PRIMARY MCP EMISSION PATH: any tool result
    //                                    whose captured RESPONSE BODY is itself JSON.
    //   {"notes": "Cookie: a=S"}         WHITESPACE between `:` and `"` — pretty-printed JSON, which
    //                                    is routine in a target's response body and reaches [apply]
    //                                    verbatim through `redact_preview` and `ContextCollector`.
    //   "Cookie: a=S"                    a BARE TOP-LEVEL JSON string document.
    //   {"tags":["Cookie: a=S"]}         an ARRAY ELEMENT open, in the bracket-quote spelling and in
    //   ,"Cookie: a=S"                   the comma-quote spelling. The one family this paragraph
    //                                    used to name alone.
    //
    // THE BOUND ON ALL FOUR, RE-MEASURED rather than carried forward: ONLY a header that is the
    // FIRST CONTENT of its string escapes. A realistic raw HTTP message inside any of the four is
    // still stripped, because its header follows an escaped newline — which IS a recognised start.
    // Verified in all four families, both modes, with the controls firing in the same run.
    //
    // Filed as open finding AR-27-11 — ALL FOUR shapes under that ONE id — rather than absorbed, and
    // DELIBERATELY pinned by no test: a green assertion that a cookie value survives STRICT is the
    // artifact class the 26-SECURITY.md standing rule prohibits. Accepted at MEDIUM, RAISED from LOW
    // when the family list was corrected: the LOW rested on "no measured producer in this repository
    // puts a value on this shape", and for the first three families the producer is not in this
    // repository at all — it is the TARGET's response body, copied verbatim onto the default-posture
    // emission path, MEASURED surviving on the exact `HttpRequestResponse` emission shape. The
    // alternative is NOT re-widening: the bare quote is a high-severity correctness break on the
    // primary path (see (a)).
    //
    // THE FOURTH START, WHICH IS NOW RECOGNISED — AR-27-09, CLOSED BY FIX at 27-17, and kept written
    // here rather than deleted because the register entry and the source state have to move together.
    //
    // WHAT IT WAS. A header line preceded by LEADING HORIZONTAL WHITESPACE, including an RFC 7230
    // obs-folded continuation line, matched NONE of the three starts: the real-line branch anchored
    // `^` directly against the header name, and both lookbehinds saw a space rather than a newline or
    // a quote. MEASURED surviving under STRICT in round 3, RE-MEASURED against the compiled classes at
    // the end of round 4 as surviving BYTE-UNCHANGED under BOTH STRICT and BALANCED — one mode wider
    // than round 3 recorded — and RE-MEASURED a third time at 27-17 immediately before the fix, where
    // it reproduced exactly.
    //
    // WHAT IT IS NOW. The real-line branch starts at [REAL_LINE_START] — line start followed by a
    // possessive run of horizontal whitespace — so an indented header line and an obs-folded
    // continuation line are BOTH logical line starts, in STRICT and BALANCED, across all three
    // composed rules. Measured end-to-end through [apply] on freshly compiled classes:
    //
    //   GET / HTTP/1.1\r\n Cookie: a=SECRET5\r\n\r\n    STRICT/BALANCED  was unchanged, now [STRIPPED]
    //   HTTP/1.1 200 OK\r\n Set-Cookie: s=SECRET6…      STRICT/BALANCED  was unchanged, now [STRIPPED]
    //   GET / HTTP/1.1\r\n  X-Api-Key: SECRET8\r\n\r\n  STRICT/BALANCED  was unchanged, now [REDACTED]
    //   GET / HTTP/1.1\r\nX-Foo: bar\r\n Cookie: a=S…   STRICT/BALANCED  was unchanged, now [STRIPPED]
    //
    // The auth family is demonstrated with a PLAIN-TOKEN header on purpose. An indented
    // `Authorization: Bearer …` line was already losing its token before this fix — but to
    // `bearerRegex`, a VALUE-level rule, which rewrote it to `Authorization: Bearer [REDACTED]` while
    // this HEADER rule missed the line entirely. `X-Api-Key` has no such second rule behind it, so it
    // is the shape that isolates the boundary. Reading the `Authorization` case as "the auth family
    // was already covered" is exactly the masked-control error this phase keeps re-finding.
    //
    // The fix moves ONLY in the over-redacting direction, and that is proven rather than asserted:
    // `[ \t]*+` matches the empty string and no composed name pattern can begin with a space or a tab,
    // so wherever `^` matched the two spellings are position-identical. `IndentedLogicalLineStartTest`
    // carries the differential corpus gate and the byte-identity negatives.
    //
    // Nothing here makes redaction complete: the claim is bounded to the serialized emission path,
    // and to the cookie-header and exact-name auth-header classes.

    // The two literal characters kotlinx.serialization emits for a real CR or LF. FIXED-WIDTH on
    // purpose: an encoded CRLF is four characters ENDING in the encoded LF, so a two-character
    // look-back already covers CR, LF and CRLF. Measured output-identical to a variable-width
    // alternation over all nine fixtures and 2.4x cheaper, because Java need not try two look-back
    // widths at every position.
    private const val JSON_ESCAPED_NEWLINE = "\\\\[rn]"

    // The open of a JSON string VALUE — the THIRD logical line start (27-11, narrowed by 27-14).
    // The two characters COLON then DOUBLE QUOTE, so it is still FIXED-WIDTH — width two rather than
    // width one — and named as its own constant so the composer can carry it in a SECOND lookbehind
    // instead of widening the first one into a variable-width alternation.
    //
    // IT IS A COLON-QUOTE SEQUENCE AND NOT A BARE QUOTE, and this sentence is the whole of the
    // constant's correctness. 27-11 shipped a BARE double quote under this same name. A bare double
    // quote is not a JSON string open: it also opens HTML attribute values, JS string literals and
    // quoted CSV fields, and it occurs in ordinary prose — all of which reach [apply] through
    // `McpToolContext.redactIfNeeded`, `ContextCollector`, `McpToolExecutorImpl`'s `redact_preview`,
    // `BountyPromptTagResolver` and `PassiveAiScannerPrompts`. All THREE composed rules inherited it,
    // `authHeaderRegex` included.
    //
    // MEASURED on the shipped classes before the narrowing, on a 1714-character
    // `proxy_http_history`-shaped tool result whose first quote-preceded `cookie:` run sits inside a
    // `title=` HTML attribute: 1589 of 1714 characters DESTROYED, all forty occurrences of the
    // content marker after that point GONE, and the output still parsing as JSON with its sibling
    // `notes` field byte-identical — so every shape assertion in the suite stayed green while the
    // model silently received a truncated response body. THE MECHANISM, in one clause: an escaped
    // quote is consumed atomically by [JSON_ESCAPED_HEADER_VALUE]'s escape-pair alternative, so the
    // tail cannot terminate on ANY escaped quote and runs to the JSON string's real closing quote.
    //
    // THE COST OF THE NARROWING, stated rather than absorbed, and stated as the MECHANISM rather
    // than as one example: `:"` is COLON then QUOTE literally, so a character interposed between the
    // two — a space, or the backslash of an escaped quote — or the absence of the colon leaves the
    // header at a start this boundary does not recognise. FOUR MEASURED families, every one of them
    // byte-unchanged under STRICT and BALANCED while a compact-shaped control stripped in the same
    // run: a NESTED / ESCAPED value open (`\"k\":\"Cookie: …`, the primary MCP emission path when a
    // captured response body is itself JSON), PRETTY-PRINTED JSON (`"k": "Cookie: …`), a BARE
    // top-level JSON string (`"Cookie: …`), and an ARRAY ELEMENT (`["Cookie: …` and `,"Cookie: …`).
    // In all four, only a header that is the FIRST CONTENT of the string escapes; one that follows an
    // escaped newline is still stripped. Filed as open finding AR-27-11 — all four under one id — at
    // MEDIUM. The full statement is paragraph (b) of the rationale region above.
    //
    // DECLARED BELOW JSON_ESCAPED_NEWLINE ON PURPOSE, and this is load-bearing rather than stylistic:
    // `LogicalLineBoundaryScopeTest.rationaleRegionAboveFragments` walks back from the first line
    // beginning `private const val JSON_ESCAPED_NEWLINE` and stops at the first line of real code
    // above it, so a constant inserted ABOVE would truncate the rationale region and break that
    // file's line floor for a reason with nothing to do with the boundary.
    private const val JSON_STRING_OPEN = ":\""

    // The REAL-LINE branch's start boundary — the FOURTH logical line start, added by 27-17 when
    // AR-27-09 was CLOSED BY FIX rather than accepted at LOW. Line start, then any run of horizontal
    // whitespace, consumed POSSESSIVELY.
    //
    // WHAT IT BUYS, MEASURED end-to-end through [apply] on freshly compiled classes, STRICT and
    // BALANCED alike, with the un-indented control stripping in the same run:
    //
    //   GET / HTTP/1.1\r\n Cookie: a=SECRET5\r\n\r\n        was unchanged -> " Cookie: [STRIPPED]"
    //   HTTP/1.1 200 OK\r\n Set-Cookie: s=SECRET6; Path=/   was unchanged -> " Set-Cookie: [STRIPPED]"
    //   GET / HTTP/1.1\r\n  X-Api-Key: SECRET8\r\n\r\n      was unchanged -> "  X-Api-Key: [REDACTED]"
    //   GET / HTTP/1.1\r\nX-Foo: bar\r\n Cookie: a=SECRET9   was unchanged -> " Cookie: [STRIPPED]"
    //
    // The obs-folded continuation on the last line is the RFC 7230 shape; it is the same token that
    // buys it, because an obs-fold IS a line start followed by horizontal whitespace.
    //
    // WHY IT CONSUMES, WHEN THE COMPOSER'S KDoc SAYS THE MATCH MUST BEGIN AT THE HEADER NAME. It no
    // longer does on this branch, and that is a DELIBERATE, MEASURED relaxation rather than an
    // oversight. `^` is zero-width, so the match used to begin at the name and [apply]'s three
    // replacement lambdas rebuild the header with `m.value.substringBefore(":")`. With the indent
    // CONSUMED the match value is " Cookie: a=SECRET5", `substringBefore(":")` yields " Cookie", and
    // the lambda emits "$header: [STRIPPED]" — so the INDENT IS RE-EMITTED VERBATIM, tabs included.
    // Measured: " Cookie" and "\t\tCookie" both round-trip byte-exact into the replacement. No
    // name-matching PREDICATE sees the widened value — `isCookieHeaderName` is called on header names
    // Burp hands over, never on a match value — so nothing downstream receives a leading space.
    //
    // WHY NOT A LOOKBEHIND, which WOULD keep the match beginning at the name. `(?<=^[ \t]*)` is the
    // obvious zero-width spelling and the folklore says Java rejects a variable-width lookbehind.
    // MEASURED, that folklore is WRONG on this toolchain: Java 21 compiles `(?<=^[ \t]*)` AND matches
    // the indented shapes correctly, match beginning at the name. It is rejected here on COST, which
    // is the measurable reason rather than the repeated one. Over 2000 scans of a 60-line
    // pretty-printed document: `^` 158 ms, `^[ \t]*+` 155 ms, `^[ \t]*` 164 ms, `(?<=^[ \t]*)`
    // 34237 ms — roughly 221x, because an unbounded look-back is retried at EVERY position. These
    // header rules run in the header stage with NO per-pattern bound (see [bodyStage]'s budget,
    // which they are explicitly outside of), so a 221x multiplier on attacker-influenced input is a
    // denial-of-service surface, not a style question. The same cost model rejected a variable-width
    // [JSON_ESCAPED_NEWLINE] for a mere 2.4x.
    //
    // WHY POSSESSIVE, and why possessive is not a narrowing. `[ \t]*+` never gives whitespace back.
    // It cannot lose a match, because every alternative in every composed name pattern begins with
    // [COOKIE_NAME_PART], the literal `set-`/`cookie`, or a letter of the auth-name alternation —
    // none of which can match a space or a tab. So giving back could never enable a match that the
    // possessive form misses. It measurably helps: on a line of 4000 spaces followed by non-header
    // text, 200 scans cost 29 ms possessive against 63 ms non-possessive.
    //
    // DIRECTION OF THE CHANGE, PROVEN RATHER THAN ASSERTED. `[ \t]*+` matches the empty string, and
    // no composed name pattern can begin with a space or a tab, so wherever `^` matched there is no
    // leading whitespace to consume and the two spellings are position-identical. The new start is
    // therefore a STRICT SUPERSET of the shipped one: it can only ADD matches, i.e. it moves only in
    // the OVER-redacting direction. `IndentedLogicalLineStartTest` carries that as a differential
    // corpus gate plus byte-identity negatives over indented prose, pretty-printed JSON and indented
    // source, so a future widening that starts eating indented NON-header content turns red.
    private const val REAL_LINE_START = "^[ \\t]*+"

    // The SHIPPED value tail, character for character. Named rather than inlined so the byte-identity
    // claim is visible in source as "this branch uses the pattern that shipped".
    private const val REAL_LINE_HEADER_VALUE = ":\\s*.+$"

    // The value tail for the JSON-escaped branch: a reluctant run of either ONE atomic JSON escape
    // pair or any character that is neither a double quote nor a backslash, terminated by the next
    // escaped newline, end-of-input, or the closing double quote of the JSON string. The two
    // alternatives are disjoint on their first character, so the repetition is deterministic — no
    // nested quantifier and no backtracking surface on a rule that runs in the header stage with no
    // per-pattern bound. There is deliberately NO negative lookbehind on the quote.
    private const val JSON_ESCAPED_HEADER_VALUE =
        ":\\s*(?:\\\\.|[^\"\\\\])+?(?=" + JSON_ESCAPED_NEWLINE + "|\$|\")"

    /**
     * Builds the two-branch header rule described above for one header-NAME pattern.
     *
     * The name fragment appears on BOTH branches; that duplication is the design, not an oversight —
     * a single shared start boundary forces a single shared tail, and the measured consequence is the
     * quoted-cookie-value leak recorded in the comment above.
     *
     * The escaped branch's boundary is a LOOKBEHIND rather than a consuming group because [apply]'s
     * replacement lambdas call `substringBefore(":")` on the match value: on THAT branch the match
     * must still BEGIN at the header name, because what precedes it there is a JSON escape or a
     * colon-quote that the replacement does not reproduce.
     *
     * The REAL-LINE branch is the EXCEPTION, deliberately, since 27-17 closed AR-27-09: [REAL_LINE_START]
     * CONSUMES the leading horizontal whitespace, so the match begins at the indent and
     * `substringBefore(":")` returns the indent together with the name. That is safe on this branch and
     * only on this branch, because the lambdas re-emit exactly what they read — the indent round-trips
     * byte-exact into the replacement. The measured reason a zero-width lookbehind was NOT used instead
     * (it compiles and works on Java 21; it costs ~221x) is stated on [REAL_LINE_START].
     *
     * That branch carries TWO start boundaries as of 27-11 — [JSON_ESCAPED_NEWLINE] and
     * [JSON_STRING_OPEN] — written as two SEPARATE fixed-width lookbehinds in a non-capturing
     * alternation, never as one lookbehind holding differing-width alternatives. The rationale block
     * above states why that spelling is the cost model and not a formatting preference.
     *
     * This is a member of the `Redaction` object called from property initializers in that same
     * object. It is safe only because it reads `const val` compile-time constants and no other
     * property — keep it that way, or the object's initialization order becomes load-bearing.
     */
    private fun logicalLineHeaderRule(namePattern: String): Regex =
        Regex(
            "(?im)(?:" + REAL_LINE_START + namePattern + REAL_LINE_HEADER_VALUE +
                "|(?:(?<=" + JSON_ESCAPED_NEWLINE + ")|(?<=" + JSON_STRING_OPEN + "))" +
                namePattern + JSON_ESCAPED_HEADER_VALUE + ")",
        )

    private val cookieHeaderRegex =
        logicalLineHeaderRule(
            "(?!" + COOKIE_NAME_PART + "set-" + COOKIE_NAME_TOKEN + ")" +
                COOKIE_NAME_PART + COOKIE_NAME_TOKEN + COOKIE_NAME_PART,
        )
    private val setCookieHeaderRegex =
        logicalLineHeaderRule(COOKIE_NAME_PART + "set-" + COOKIE_NAME_TOKEN + COOKIE_NAME_PART)

    /**
     * The single cookie-header-name rule shared by the two redaction paths and the passive-scan
     * admitter: `mcp/tools/McpToolHelpers.sanitizeHeaders` (the MCP tool-RESULT redactor),
     * `scanner/PassiveAiScannerFilters.sanitizeHeadersForPrompt` (the passive-scan admitter) and the
     * two regexes above, which share this function's [COOKIE_NAME_TOKEN].
     *
     * That scope is MEASURED, not rhetorical, and must stay written down as the three sites it is.
     * Other cookie-header-name matchers survive elsewhere in `src/main/kotlin` — in
     * `PassiveAiScannerAnalysis`, `PassiveAiScannerHeuristics`, `ActiveAiScanner` and
     * `BountyPromptTagResolver` — and are individually classified as non-redacting by
     * `CookieHeaderRuleOwnershipTest`. Do not widen this sentence into a tree-wide singularity claim:
     * a record wider than the control it describes is the defect the v0.10.0 milestone audit found,
     * and restating it here would only relocate it into the artifact a maintainer reads first.
     *
     * WIDTH, AND WHY IT CANNOT BE STATED WITHOUT NAMING THE CONSUMER (PRIV-05, plan 27-10). This
     * predicate constrains nothing beyond containing the token, while the two regexes constrain the
     * characters either side of it to [COOKIE_NAME_PART]. Whether the predicate being WIDER is safe
     * depends entirely on WHICH consumer is reading it, and the three do not agree:
     *
     *  - `McpToolHelpers.sanitizeHeaders` — a REDACTOR. A true result REMOVES the value. Wider than
     *    the regexes over-redacts, which is fail-SAFE.
     *  - the two composed regexes inside [apply] — REDACTORS, for the same reason.
     *  - `PassiveAiScannerFilters.sanitizeHeadersForPrompt` — an ADMITTER. A true result PUTS the
     *    header into the outbound prompt. Wider than the regexes means a name this predicate claims
     *    is admitted onto the prompt and then NOT removed by [apply], which is fail-OPEN.
     *
     * This paragraph previously claimed fail-safety UNCONDITIONALLY, and named the cost as
     * over-redacting a benign `Cookie-Consent`-style header's VALUE (T-21-WA3, accepted). For the
     * admitting consumer the MEASURED cost was the opposite: `my_cookie`, `X_Cookie` and
     * `session_cookie` reached a third-party AI backend verbatim under STRICT — the strongest privacy
     * mode — and under BALANCED, because `_` is a legal RFC 9110 tchar that [COOKIE_NAME_PART] then
     * excluded. Any fail-safe claim here must stay scoped to a named REDACTING consumer; the
     * admitting one is explicitly excluded from it.
     *
     * THE CURRENT BOUND, with its next axis, so this is not read as "the predicate and the regexes
     * now agree". After plan 27-10 the regexes cover the alphanumeric, underscore and hyphen class,
     * so the difference set is empty THERE. The thirteen remaining RFC 9110 tchars are NOT covered:
     * they are enumerated in source as `CookieHeaderNameWidthTest.NOT_COVERED_TCHARS` and filed as
     * `AR-27-10`. A name built from one of those is still admitted here and still unmatched by both
     * regexes.
     *
     * Both header paths call THIS function rather than writing their own test, so a future widening
     * cannot be applied to one path and forgotten in the other. That forgetting is precisely what the
     * v0.10.0 milestone audit found: the prompt path matched name-contains-`cookie` while the
     * tool-result path still compared against the two canonical spellings, and `X-Cookie`,
     * `Cookie2`, `Set-Cookie2`, `X-Original-Cookie` and `X-Forwarded-Cookie` reached the model
     * verbatim through the MCP `request_parse` / `response_parse` tools.
     *
     * The `Locale.ROOT` argument is explicit for a MEASURED reason, and the measurement is not the
     * one the folklore gives. Kotlin's no-argument `String.lowercase()` is ALREADY locale-agnostic —
     * it compiles to `toLowerCase(Locale.ROOT)` — so with the JVM default locale set to `tr-TR`,
     * `"COOKIE".lowercase()` was measured on this toolchain to yield `cookie`, not the dotless-i
     * `cookıe`. The dotless-i hazard is real, but it belongs to the JAVA spelling: under that same
     * default, `"COOKIE".toLowerCase()` and `toLowerCase(Locale.getDefault())` were both measured to
     * yield `cookıe`, which would silently stop this control matching on such a host.
     *
     * So `Locale.ROOT` is stated rather than left implied, and the honest bound is worth writing
     * down: removing this argument does NOT change behaviour today, whereas replacing it with
     * `Locale.getDefault()`, or switching to Java's `toLowerCase()`, would break the control without
     * an error anywhere. The argument's job is to make that future edit read as the change it is.
     *
     * Cost is one `lowercase` plus one `contains` — no `Regex`, no compilation, no backtracking
     * surface — because this runs once per header on the MCP tool path.
     */
    fun isCookieHeaderName(name: String): Boolean = name.lowercase(Locale.ROOT).contains(COOKIE_NAME_TOKEN)

    /**
     * (PRIV-05) 27-07 / D-27-17 — is this Montoya parameter TYPE the cookie carrier?
     *
     * Burp parses the `Cookie:` header into `HttpParameterType.COOKIE` parameters, so
     * `HttpRequest.parameters()` hands back the SAME bytes that `isCookieHeaderName` guards one
     * field over. In `request_parse` the two carriers sit inside one JSON object: `headers` was
     * cookie-stripped while `parameters` returned the identical value verbatim. This predicate is
     * the type-side half of that pair.
     *
     * The key is the parameter TYPE — a value Burp gives us — never a rendered string. That is the
     * property the three prior rounds of this phase lacked: `cookieTypedParamRegex` is keyed to the
     * passive scanner's `name=value (COOKIE)` shape and is silently defeated by any producer that
     * renders the same data differently. Reformat either MCP tool's output and THIS control still
     * fires.
     *
     * Exact comparison, deliberately NOT the `contains` test `isCookieHeaderName` uses, and not
     * `COOKIE_NAME_TOKEN`. A header NAME is author-chosen, so `X-Cookie` and `Set-Cookie2` are real
     * spellings a substring test must reach. A parameter TYPE is a CLOSED Burp enum: a substring
     * test buys nothing there and would match a future constant that merely contains the token.
     * `Locale.ROOT` for the same measured reason recorded above `isCookieHeaderName`.
     *
     * Takes a `String` rather than the Montoya enum so this predicate stays callable from `redact/`,
     * which is deliberately Montoya-free at its API edge, and so it is unit-testable with no host API.
     *
     * TWO BOUNDS, stated here because deleting either re-opens a claim this phase has already been
     * refuted on three times:
     *
     * 1. This answers the TYPE question ONLY. A parameter whose NAME looks cookie-ish (`session_id`
     *    in a URL query) but whose type is URL or BODY is NOT matched here, and is not in PRIV-05's
     *    cookie wording — see [com.six2dez.burp.aiagent.mcp.tools.sanitizeParameters]'s KDoc and D-27-20.
     *
     * 2. This predicate owns the cookie-type question for the THREE producers plan 27-07 rewires —
     *    `McpToolExecutorImpl`, `McpToolLegacy` and `BountyPromptTagResolver`. It is NOT the only
     *    cookie-type test in `src/main/kotlin`. `scanner/InjectionPointExtractor.kt:29` writes its
     *    own `it.type().name == "COOKIE"` filter and is deliberately NOT converted (D-27-17): its
     *    value feeds `InjectionPoint.originalValue` and from there the issue-detail route, which
     *    plan 27-08 task 3 measures and plan 27-09 files. Swapping the predicate there would change
     *    nothing about that route's disclosure while making the route look addressed. Cookie-type
     *    PREDICATES in the tree therefore go from 1 to 2, not from N to 1.
     *
     * SUPERSEDED IN PART — 2026-08-27, phase 28 plan 28-02. Bound 2's paragraph above is KEPT
     * VERBATIM as the historical record: while the issue-detail route was uncontrolled, refusing the
     * conversion WAS the correct call, and deleting the reasoning would leave a later reader unable
     * to tell a considered deferral from an oversight.
     *
     * What changed: plan 28-01 controlled that route at its WRITE site
     * ([com.six2dez.burp.aiagent.scanner.ScannerIssueSupport] sanitises the injection-point value
     * before it reaches `AuditIssue` detail), so the objection Bound 2 records — that swapping the
     * predicate would make the route merely LOOK addressed — no longer holds. Plan 28-02 therefore
     * collected the conversion: `scanner/InjectionPointExtractor.kt` now calls this predicate.
     *
     * Two consequences a reader must not take from prose here:
     *
     * - The PREDICATE COUNT stated in Bound 2's last sentence is now false. It is deliberately NOT
     *   restated with a new number. A source-derivable count belongs in a test that re-derives it
     *   from the tree, not in a comment that goes stale silently; see
     *   `CookieRouteDispositionTest.exactlyOneCookieTypePredicateExistsInMainSource`.
     * - The conversion is an IDENTITY swap and NOT a behaviour change. `InjectionPointExtractor`
     *   still emits the RAW cookie value; its second consumer, `AdaptivePayloadEngine`, substitutes
     *   its own value marker and must not be redacted a second time by a foreign vocabulary.
     *   `CookieRouteDispositionTest` holds both halves.
     */
    fun isCookieParameterType(typeName: String): Boolean = typeName.trim().uppercase(Locale.ROOT) == COOKIE_PARAMETER_TYPE_NAME

    /**
     * The `HttpParameterType.COOKIE` constant NAME, owned here beside the predicate that compares
     * against it rather than written inline at the comparison. Same discipline as
     * [COOKIE_SECTION_HEADER]: the literal has one home, so a reader auditing "what does this
     * control key on" finds one answer.
     */
    private const val COOKIE_PARAMETER_TYPE_NAME = "COOKIE"

    /**
     * The passive scanner's dedicated cookie-section header.
     *
     * Public, and owned HERE in the redactor rather than in the emitter, because
     * scanner/PassiveAiScannerPrompts.kt imports this constant instead of writing the literal
     * inline. A future rename of the section is then a COMPILE ERROR rather than the silent
     * disabling of a security control — which is the standing objection to any section-scoped
     * redaction rule, converted into a compile-time coupling. The parity half of that coupling is
     * PassiveAiScannerPromptRedactionTest.emittedBlobContainsTheSectionConstant_parity, which turns
     * a silent format change AROUND the constant into a test failure.
     */
    const val COOKIE_SECTION_HEADER = "=== COOKIES ==="

    // (PRIV-05) SC1 / D-09: one name=value pair inside a cookie section. [^=\r\n]+ stops at the
    // FIRST '=', so a value that itself contains '=' (base64 padding) is consumed whole by the
    // trailing .* and cannot survive as a fragment.
    private val cookieSectionPairRegex = Regex("(?m)^([^=\\r\\n]+)=(.*)$")

    // (PRIV-05) SC1: the prefix that begins the NEXT prompt section, and now the only content
    // terminator of a cookie span. It replaces the previous (?m)^===  regex, which CR-03 dropped:
    // a regex search can scan to end-of-text on every occurrence of the header, whereas a
    // startsWith at an already-known line start is O(1) and cannot.
    private const val NEXT_SECTION_PREFIX = "=== "

    // (PRIV-05) CR-01 / T-21-21 / W-01: the maximum number of LINES one cookie section may span.
    //
    // UNDER-REDACTION FIRST, because that is the dangerous direction and the one the previous
    // wording omitted entirely. A section longer than this is redacted only up to line
    // MAX_COOKIE_SECTION_LINES and EVERY entry below it reaches the AI backend verbatim. Measured
    // on the shipped rule with a 20-entry section: ck0..ck15 come back [REDACTED] and
    // ck16, ck17, ck18, ck19 come back untouched. The emitter is bounded to COOKIES_MAX_COUNT
    // entries (scanner/PassiveAiScannerAnalysis.kt), which MUST stay at or below this value; it is
    // now derived from this constant and clamped to it, so raising the emitter's literal alone
    // cannot reopen the leak, and RedactionTest.cookieEmitterBoundStaysWithinTheRedactorBound goes
    // red the moment the two drift. The walk itself is guarded by
    // RedactionTest.everyEntryOfAMaximalCookieSectionIsRedacted.
    //
    // IT IS A LINE COUNT, NOT AN ENTRY COUNT, and the two differ whenever the input is not
    // emitter-shaped: cookieSectionEnd deliberately SKIPS blank lines without terminating (that is
    // the CR-01 fix), so a blank line inside a section consumes one of the budgeted lines. Measured:
    // 12 entries with one blank line between each leaves only ck0..ck7 inside the span and leaks
    // ck8..ck11 at this 16-line bound. That is why the emitter's bound must stay at or below HALF of
    // this one — one blank per entry is the worst shape the redactor still has to cover.
    //
    // OVER-REDACTION, the other direction: redactCookieSections also runs over arbitrary MCP tool
    // output through McpToolContext.redactIfNeeded, where ANY occurrence of the header is
    // attacker-planted, and this constant is what bounds the over-redaction blast radius of such a
    // plant to 16 lines where the rule previously ran on "to the next blank line". That trade is
    // NOT a pure tightening — see the ACCEPTED RESIDUAL note on redactCookieSections for the case
    // where it is a widening, and for why shrinking this constant was rejected.
    //
    // Named rather than inline because detekt's MagicNumber ignore list stops at 2 and QUAL-07
    // forbids growing detekt-baseline.xml. internal rather than private so the scanner package can
    // clamp its own bound to this one instead of restating the number in another file.
    internal const val MAX_COOKIE_SECTION_LINES = 16

    // (PRIV-06) CR-03 / D-02 / T-21-29 / W-05: the wall-clock budget for redactCookieSections.
    //
    // WHAT IT ACTUALLY BOUNDS, stated exactly, because the previous wording claimed a whole-call
    // ceiling spanning every occurrence and the code has never provided one. It is
    // SAMPLED ONCE PER OCCURRENCE, immediately after the next section header is found and before
    // that section is rewritten. A single occurrence's String.replace(cookieSectionPairRegex) is
    // therefore bounded by that section's own length, not by this budget: the last occurrence to
    // start before expiry runs to completion however long its section is. Overstating a guarantee
    // is the exact class of defect that let CR-02 ship twice, so D-08 REFINED applies to comments on
    // security controls as much as to the controls themselves — this one now claims only what it
    // does.
    //
    // WHY THAT IS NOT A DENIAL OF SERVICE. cookieSectionPairRegex is (?m)^([^=\r\n]+)=(.*)$ — one
    // negated character class, one dot-star, no alternation, no nested quantifier and no
    // backreference, and '.' excludes newline without DOTALL so every match is line-bounded. Its
    // worst case is linear in the section length, so an unbounded single occurrence costs
    // milliseconds per megabyte rather than the exponential blow-up SafeRegex exists to stop.
    //
    // DELIBERATELY NOT ROUTED THROUGH SafeRegex, and this is a decision rather than an oversight.
    // The .text of SafeRegex.replaceAllSafeReporting is the ORIGINAL input on timeout, so ASSIGNING
    // THAT TEXT WITHOUT BRANCHING ON timedOut would for THIS rule mean the unredacted cookie section
    // passed straight through — fail OPEN, in direct contradiction of D-02. Adopting SafeRegex here
    // therefore means branching on timedOut, and that is a behaviour change (what to drop, and how
    // much) outside this plan's surface.
    // RECORDED AS A RESIDUAL rather than claimed closed: a single cookie section is currently
    // rewritten with no per-match deadline at all, accepted on the linearity argument above.
    //
    // Sized so it is unreachable by any realistic input now that the rule is O(n) — reaching it
    // takes tens of megabytes, at which size bodyStage's own MAX_REDACTION_BUDGET_MS is already
    // dropping the tail — while still bounding the worst case on a pathological input. Before CR-03
    // this rule bypassed both SafeRegex and MAX_REDACTION_BUDGET_MS entirely: no budget, no marker,
    // no seam.
    private const val COOKIE_SECTION_BUDGET_MS = 250L

    // (PRIV-05) SC1 / D-09 / D-10: redacts the VALUE of every name=value pair inside EVERY
    // [COOKIE_SECTION_HEADER] span, preserving the names. The scanner splits the Cookie: header on
    // ';' into a dedicated section, dropping the prefix the two header rules above key on — that is
    // the PRIV-05 leak, and it is a pattern-reach problem, not a call-site problem.
    //
    // D-09 — EVERY value, not only sensitive-named ones. Cookies are near-universally
    // session-bearing, and name-based selectivity is precisely what produced PRIV-05. Names are
    // preserved deliberately: COOKIES_MAX_COUNT bounds the section to six lines, so this costs the
    // model at most six opaque values while keeping all six names, which is the analytically useful
    // part (ScanKnowledgeBase.recordAuthInfo already records authCookieNames separately for exactly
    // this reason). Full-line stripping in the style of the two header rules above would destroy
    // the names and is therefore wrong here.
    //
    // D-10 — EVERY occurrence of the header, never only the first. This is a SECURITY requirement
    // with a demonstrated exploit behind it, not a robustness nicety. ScanKnowledgeBase.recordTechStack
    // populates the technology list from the response's Server, X-Powered-By, X-AspNet-Version and
    // X-Generator headers — all attacker-controlled — and buildContextSummary emits that list into
    // the prior-knowledge block, which the emitter appends BEFORE the cookie section. A Server
    // header carrying the section header therefore plants a decoy section ahead of the real one,
    // and a first-occurrence-only indexOf was measured redacting the decoy while the genuine
    // JSESSIONID and abtest_bucket values leaked intact. The while loop below is that fix;
    // RedactionTest.cookieSectionDecoyDoesNotShieldRealSection is its named regression guard.
    //
    // ACCEPTED RESIDUAL (W-02, disposition: ACCEPT, argued below): an attacker who plants the
    // section header in a response header or body causes EXTRA redaction of their own response
    // content. That is over-redaction, never a leak.
    //
    // IT IS NOT A PURE TIGHTENING, and the earlier wording — "bounds that blast radius to 16 lines,
    // where it was previously to the next blank line" — stated only the half that is. Both
    // directions, measured:
    //  - For DENSE content with no blank lines it IS a tightening: the previous rule ran to the next
    //    blank line, which on such content meant to the end of the text.
    //  - For paginated HTML, log output or pretty-printed config, where blank lines occur every two
    //    or three lines, it is a WIDENING. It also converts a content-dependent bound into a
    //    deterministic 16-line primitive a target can rely on to hide a chosen region of its own
    //    response from the model. Measured: a planted header followed by name=value lines destroys
    //    exactly 16 of them and the seventeenth survives.
    // What is lost is not cosmetic. The lines a passive scanner most needs — debug=verbose stack
    // traces, sql=SELECT ... , internal=10.0.0.5 — are precisely the name=value shape this rule
    // strips. The same primitive has other reachable surfaces: formatParamLine emits
    // "name=value (TYPE)" into === PARAMETERS === with no sanitiser, and both header sections pass
    // attacker-controlled text into the blob. WR-01 was raised and fixed on exactly the ground that
    // removing analytically load-bearing content from a security prompt is a functional regression,
    // so the same standard is applied here consciously rather than by omission.
    //
    // ACCEPTED ANYWAY, because both proposed alternatives are worse, and both were MEASURED rather
    // than argued:
    //  - REQUIRE THE EMITTER'S FRAMING (header alone on its line, preceded by a blank line). This
    //    trades over-redaction for UNDER-redaction on every consumer that has no emitter. Applied
    //    verbatim from the review, three genuine cookie sections leaked their values: an MCP
    //    redact_preview payload whose header follows a caption line, a header not alone on its line,
    //    and joined tool output. The emitter-framed control still redacted, so the change is a pure
    //    loss for PRIV-05 — and the ENTIRE redact and scanner suite stayed green while those three
    //    leaked, which is what makes it a trap rather than a trade. Redaction.apply has six callers
    //    and only ONE of them is the scanner emitter: McpToolContext.redactIfNeeded (every MCP tool
    //    result and every tool's args JSON), McpToolExecutorImpl's redact_preview, ContextCollector
    //    and BountyPromptTagResolver all pass text with no framing guarantee whatsoever.
    //  - SHRINK THE BOUND to COOKIES_MAX_COUNT + 2. That directly worsens the under-redaction
    //    direction of MAX_COOKIE_SECTION_LINES. Measured at a bound of 8: the first leaking entry of
    //    a 20-entry section moves from index 16 down to index 8, and the leaking set triples from
    //    ck16..ck19 to ck8..ck19.
    // The residual's boundary is pinned by
    // RedactionTest.plantedCookieHeaderBlastRadiusIsBoundedToTheSectionBound_acceptedResidual, so a
    // future change to it is a visible test change rather than a silent one.
    //
    // CR-03 — ONE PASS, not one rebuild per occurrence. This loop previously rebuilt the entire
    // string on every occurrence of the header (substring + replaced + substring), an O(n) copy per
    // occurrence and therefore O(k*n) overall, with k attacker-controlled: buildScanMetadataText
    // emits response headers and body verbatim and McpToolContext.redactIfNeeded runs this rule
    // over raw MCP tool output. Measured 65 ms at 64 KB rising a clean 4x per doubling to 2 631 ms
    // at 512 KB, extrapolating to ~42 s at the MCP default maxBodyBytes of 2 MiB, on an
    // uninterruptible worker thread. It is now one StringBuilder and one monotone cursor.
    //
    // TERMINATION AND COMPLEXITY. bodyStart is strictly greater than the header index h, and
    // cookieSectionEnd clamps its result to at least bodyStart, so cursor advances by at least
    // COOKIE_SECTION_HEADER.length every iteration and the loop always terminates. The appended
    // spans are disjoint and cookieSectionEnd only ever reads FORWARD from the cursor, so no
    // character is examined twice: the pass is O(n) in the input length. That is the whole of CR-03,
    // and it is why the two independent terminator searches were replaced by a single line walk.
    //
    // FAIL CLOSED, NOT OPEN. On deadline expiry the remaining characters are DROPPED behind one
    // windowDroppedMarker rather than passed through. The alternative — capping the section count
    // and letting the remainder through — is fail-open, and that remainder can contain whole
    // unredacted cookie sections, which is the exact failure class this phase exists to remove.
    // Dropping the tail is the D-02 discipline the body stage already follows, and the marker is
    // reused verbatim rather than given a third shape: its four wording properties hold unchanged.
    //
    // (T-21-23) Every piece of per-call state below — builder, cursor, deadline — is a LOCAL.
    // Redaction is a stateless object called concurrently from scanner and MCP tool threads, and
    // this rule adds no object-level field.
    private fun redactCookieSections(
        text: String,
        budgetMs: Long = COOKIE_SECTION_BUDGET_MS,
    ): String {
        val sb = StringBuilder(text.length)
        val deadline = System.nanoTime() + budgetMs * NANOS_PER_MS
        var cursor = 0
        while (true) {
            // (PRIV-06) W-05: the search runs BEFORE the deadline check, deliberately. With the
            // check first, an expired budget replaced the ENTIRE remaining prompt — up to the MCP
            // default maxBodyBytes of 2 MiB — with one drop marker even when no further cookie
            // section existed anywhere in it. That fails closed, so it was never a leak; it was a
            // silent total loss of analytic context on a well-behaved input, triggered by nothing
            // the user did. The fail-closed price is now paid only when a section is genuinely
            // pending. D-10 is unchanged: this is still indexOf(COOKIE_SECTION_HEADER, cursor) in a
            // while loop with a monotonically advancing cursor, so EVERY occurrence is still
            // iterated. Guard: RedactionTest.cookieSectionBudgetExpiryWithNoSectionRemainingPreservesTheText,
            // with cookieSectionDeadlineFailsClosed pinning the opposite half of the same branch.
            val h = text.indexOf(COOKIE_SECTION_HEADER, cursor)
            if (h < 0) break
            // Subtraction rather than a direct comparison, so the check is immune to nanoTime
            // wraparound; ">= 0" rather than "> 0" so an injected budget of 0 ms is deterministically
            // expired on the first iteration even on a coarse clock. That determinism is what makes
            // the fail-closed path assertable without a tens-of-megabytes fixture.
            if (System.nanoTime() - deadline >= 0L) {
                val dropped = text.length - cursor
                sb.append(windowDroppedMarker(dropped))
                maybeLogTruncation(System.currentTimeMillis(), dropped.toLong())
                // Returns WITHOUT the remainder: the tail is dropped, never passed through.
                return sb.toString()
            }
            val bodyStart = h + COOKIE_SECTION_HEADER.length
            val end = cookieSectionEnd(text, bodyStart)
            sb.append(text, cursor, bodyStart)
            sb.append(
                text.substring(bodyStart, end).replace(cookieSectionPairRegex) { "${it.groupValues[1]}=[REDACTED]" },
            )
            cursor = end
        }
        sb.append(text, cursor, text.length)
        return sb.toString()
    }

    // (PRIV-05) CR-01 / SC1 / T-21-28: the end index of the cookie section whose header ends at
    // [bodyStart]. This function IS the CR-01 fix.
    //
    // THE DEFECT IT CLOSES. COOKIE_SECTION_HEADER carries no trailing newline while the emitter uses
    // appendLine, so [bodyStart] is the header line's OWN newline. The previous bound searched for
    // "\n\n" starting AT [bodyStart], so a blank FIRST cookie entry matched at [bodyStart] itself:
    // the span collapsed to the empty string and EVERY cookie value in the section reached the AI
    // backend unredacted. A blank entry further down truncated the span there instead, leaking every
    // cookie below it. The scanner really does produce blank entries — it splits the Cookie: header
    // on ';' with no blank filter — so this was a live leak, not a latent one. Starting the walk at
    // the line AFTER the header is what closes it.
    //
    // BLANK LINES ARE SKIPPED, NEVER TERMINATORS. That closes the mid-list half, which a fix that
    // merely moved the search start would leave leaking. It is safe precisely because a blank line
    // holds no name=value pair, so extending a span across one redacts nothing extra.
    //
    // WHY ONE FORWARD WALK, replacing the previous pair of independent searches ("\n\n" and the
    // (?m)^===  regex). Two searches were the second half of CR-03: EACH can scan to the end of the
    // text even when the other finds a near terminator, which kept the enclosing loop O(k*n) even
    // once the per-occurrence rebuild was removed. This walk is strictly monotone — it never
    // examines a character before the cursor — so total work across every occurrence is O(n). That
    // is the correctness argument behind the complexity claim; do not reintroduce the searches.
    @Suppress("ReturnCount")
    private fun cookieSectionEnd(
        text: String,
        bodyStart: Int,
    ): Int {
        val headerNewline = text.indexOf('\n', bodyStart)
        val scanFrom = if (headerNewline >= 0) headerNewline + 1 else bodyStart
        var p = scanFrom
        var lines = 0
        while (p < text.length && lines < MAX_COOKIE_SECTION_LINES) {
            if (text.startsWith(NEXT_SECTION_PREFIX, p)) return p
            val newline = text.indexOf('\n', p)
            if (newline < 0) return text.length
            // p == newline means this line is blank: advance past it WITHOUT terminating.
            p = newline + 1
            lines++
        }
        // Clamped so a span can never have negative length regardless of where the walk stopped.
        return maxOf(p, bodyStart)
    }

    // Internal test seam — runs the cookie-section rule under an INJECTED budget. Not part of the
    // public API; referenced only from the test source set, in the style of the
    // resetTruncationWindowForTest and testHkdfExtract seams.
    //
    // It exists because the deadline is otherwise reachable only with a tens-of-megabytes fixture,
    // which would make the fail-closed assertion slow and dependent on machine speed. The project's
    // established answer to that is an injected bound — the same reason maybeLogTruncation takes
    // nowMs as a parameter instead of reading the clock itself.
    internal fun testRedactCookieSections(
        text: String,
        budgetMs: Long,
    ): String = redactCookieSections(text, budgetMs)

    /**
     * (PRIV-05) CR-01 / T-21-32: makes cookie [entries] safe to emit inside a
     * [COOKIE_SECTION_HEADER] section.
     *
     * This closes the one CR-01 trigger the redactor cannot close on its own. A cookie element
     * shaped like `=== FOO ===` terminates the section span, and that is IN-BAND SIGNALLING: the
     * span terminator is necessarily derived from content sitting inside the region it protects, so
     * no redactor-side rule can distinguish a planted section header from a genuine one. Refusing
     * to terminate on `=== ` instead would hand an attacker the opposite primitive, where one
     * planted line swallows the remainder of the prompt.
     *
     * Exported from `redact/` rather than written in the scanner for the same reason
     * [COOKIE_SECTION_HEADER] is owned here: the redactor owns the invariant its own rule depends
     * on, so the coupling cannot be broken silently from another package.
     *
     * Applied per entry, in this order: an entry blank after trimming is dropped; every CR and LF
     * inside an entry becomes a single space, so one entry can never become two emitted lines; and
     * an entry still beginning with `===` receives a single leading space. That last step is the
     * point — a leading space makes the line unable to match `^=== `, and the value is PRESERVED
     * rather than dropped, so nothing analytically useful is lost.
     *
     * Removing the call in `PassiveAiScannerPrompts.buildScanMetadataText` re-opens PRIV-05; the
     * named guard is
     * `PassiveAiScannerPromptRedactionTest.poisonedCookieHeaderCannotTerminateTheCookieSection`.
     *
     * (W-07) SHIPPED CALL SITES — two of them, on the production path, in this order:
     *  1. `PassiveAiScannerPrompts.cookieSectionLines`, the PRODUCER, before `take(maxCount)`, so a
     *     blank element cannot consume one of the display slots. Guard:
     *     `PassiveAiScannerPromptRedactionTest.blankCookieElementsDoNotConsumeDisplaySlots`.
     *  2. `PassiveAiScannerPrompts.buildScanMetadataText`, the EMITTER, defence in depth and the only
     *     place a genuine `=== PARAMETERS ===` and a planted `=== FOO ===` are distinguishable.
     *     Guard: `PassiveAiScannerPromptRedactionTest.cookieSectionEntriesAreSanitizedAtTheEmitter`.
     *
     * Each site is mutation-guarded by a DIFFERENT named test, so removing either because the other
     * exists reopens a different half. Running twice is harmless because the operation is
     * idempotent: a space-prefixed `" === FOO ==="` no longer satisfies `startsWith("===")`. This
     * paragraph replaces an earlier sentence claiming plan 21-08 left this function uncalled, which
     * plan 21-10 made false at two call sites — a KDoc on a security control asserting that the
     * control is unused is actively misleading, and this codebase uses "the named guard is X"
     * comments as a load-bearing safety mechanism, so one wrong reference devalues every other.
     *
     * The function itself is guarded directly by
     * `RedactionTest.sanitizeCookieSectionEntriesNeutralisesEveryFramingPrimitive`, which is the only
     * test in the suite that reaches the CR/LF limb: both end-to-end guards above use the literal
     * `=== FOO ===` with no embedded newline.
     */
    fun sanitizeCookieSectionEntries(entries: List<String>): List<String> =
        entries
            .filter { it.isNotBlank() }
            .map { entry ->
                val flattened = entry.replace('\r', ' ').replace('\n', ' ')
                if (flattened.startsWith("===")) " $flattened" else flattened
            }

    // (PRIV-05) SC2 / D-09: a COOKIE-typed parameter line, AS THE PASSIVE SCANNER RENDERS ONE.
    //
    // (a) THE ONE RENDERED SHAPE THIS RULE MATCHES. `name=value (TYPE)`, where TYPE is the Montoya
    // HttpParameterType name. That string is built by `formatParamLine` in
    // scanner/PassiveAiScannerPrompts.kt, whose ONLY producer in src/main/kotlin is the
    // `formatParamLine(p.name(), value, p.type().name)` expression in
    // scanner/PassiveAiScannerAnalysis.kt. The text reaches this rule only because
    // PassiveAiScannerPrompts.redactScanMetadata calls Redaction.apply on the assembled metadata
    // blob. One shape, one producer, one path in.
    //
    // (b) THIS REPOSITORY OWNS THAT SHAPE, so this repository can disable this rule by editing it.
    // Change the separator, drop the space before the parenthesis, or lower-case the type label in
    // formatParamLine and the rule stops firing — with no compile error and no failure outside the
    // fixtures written for it. That is a property of a rendering-keyed rule, not a defect being
    // repaired here. The fixtures that DO fail if the shape moves are the prompt-path preservation
    // group in mcp/tools/ParameterCarrierRedactionTest.kt, including an RFC 6265 DQUOTE-wrapped
    // value.
    //
    // (c) THE PARAMETER CARRIER'S OTHER RENDERINGS ARE NOT REACHED BY THIS RULE, and are owned
    // elsewhere. The MCP tools render the same Burp-parsed COOKIE parameters two other ways — as
    // JSON in `request_parse`, and as `type=… name=… value=…` lines in `params_extract` — and
    // neither is this shape, nor does either pass through Redaction.apply at all. Their owner is
    // the TYPE-KEYED control added by phase 27 plan 27-07: `Redaction.isCookieParameterType` in
    // this file, applied by `McpToolHelpers.sanitizeParameters` at the producer. For the parameter
    // carrier outside the passive-scanner prompt, read that pair — not this rule.
    //
    // (d) CORRECTION, 2026-08-25, phase 27 plan 27-08. The previous text of this comment said the
    // rule was "reached through request.parameters()", and that keying on the type label made it
    // CONTEXT-FREE so it "works wherever the shape appears". The first is true of the DATA and
    // false of the RULE: request.parameters() also feeds the two MCP tools named in (c), which this
    // rule never sees. The second overstates "context-free": the rule is free of the SECTION
    // context, not of the requirement that the text arrive in this one rendering through
    // Redaction.apply. That gap between documented reach and actual reach is how two live MCP tools
    // emitted COOKIE parameter values verbatim across three rounds of this phase while this rule
    // sat measured-green at the site it was written for. The rule was correct throughout and its
    // pattern is byte-unchanged; only the claim about it was wrong.
    //
    // What survives that correction UNALTERED, because it is still true:
    //
    // The asymmetry with the section rule above is deliberate — that section has no discriminator
    // other than its header, whereas a parameter line carries one in its own text.
    //
    // The context-free "^name=value$" alternative was rejected on CAPABILITY, not merely on
    // over-redaction: the trailing type suffix defeats the end anchor, so it cannot satisfy SC2 at
    // all — and it additionally mangles x=1, DEBUG=true and AAAA== when they stand on their own
    // line. Group 3 is the suffix and is written back verbatim, so name and type label both survive.
    private val cookieTypedParamRegex = Regex("(?im)^([^=\\r\\n]+)=(.*?)(\\s\\(COOKIE\\))\\s*$")

    // very generic JWT-like pattern (not perfect by design)
    private val jwtRegex = Regex("\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b")

    // Sensitive parameter/key name vocabulary — shared by urlTokenParamRegex, formBodyParamRegex,
    // and jsonSecretKeyRegex so query-string and body coverage stay consistent (PRIV-02).
    // (PRIV-05) SC3 / D-11: the vocabulary is deliberately NOT widened. The 31-key SC3 must-redact
    // corpus is satisfied by the boundary rule below plus the vendor list, without adding a single
    // word; every extra word multiplies the false-positive surface across all THREE consumer
    // regexes at once (Pitfall 10). Add a word only with measured evidence in query-string,
    // form-body and JSON contexts.
    //
    // (PRIV-05) WR-01: 'key' and 'code' were REMOVED from this list and moved to BROAD_WORDS below.
    // That is the ONLY respect in which the vocabulary differs from the v0.6.0 value; every other
    // word is byte-identical. Read BROAD_WORDS for the measured reason and the accepted cost before
    // putting either word back.
    //
    // THE VOCABULARY IS COMPILED IN FIRST-LETTER-FACTORED FORM in SENSITIVE_KEY_WORDS below rather
    // than as this flat list. This constant is the READABLE SPECIFICATION and is the one to edit
    // when adding a word; RedactionTest.factoredKeyVocabularyMatchesItsReadableSpecification builds
    // a naive expression from the same three lists and asserts it classifies the whole corpus
    // identically, so a factoring slip fails a test instead of silently changing coverage.
    private const val SENSITIVE_WORDS =
        "access_token|api_key|apikey|auth|token|secret|password|pwd|session|sid"

    // (PRIV-05) WR-01: the two BROADEST words of the v0.6.0 vocabulary. Under D-11's whole-token
    // boundary they matched any key containing 'key' or 'code' as a token, which the Phase 21 code
    // review measured over a 32-name corpus: status_code, error_code, response_code, http_code,
    // statusCode, errorCode, zip_code, country_code, postal_code, currency_code, language_code,
    // product_code, promo_code, coupon_code, area_code, qr_code, primary_key, foreign_key,
    // sort_key, partition_key, cache_key, idempotency_key, row_key, public_key, sortKey, cacheKey
    // and zipCode were ALL redacted. That is a far larger class than the ten over-redactions the
    // tests recorded, and it is not cosmetic: {"statusCode": 401, "errorCode": "AUTH_FAILED"}
    // reached the analysis prompt as two [REDACTED] tokens while the model was being asked to find
    // an authentication flaw. For a passive vulnerability scanner that is a functional regression.
    //
    // They are therefore NOT part of the free-containment rule. They redact only when the key IS
    // exactly 'key' or 'code' (whole-key equality, which is what keeps the bare SC3 corpus entries
    // 'key' and 'code' red), or when a CREDENTIAL_PREFIXES token sits immediately in front of them.
    //
    // ACCEPTED COST, recorded rather than left implicit: a bespoke vendor-shaped name whose prefix
    // is not in the list below — stripe_key, encrypted_key, myapi_key — no longer redacts on this
    // path. Bespoke API-key names are already a documented accepted gap in
    // .planning/codebase/CONCERNS.md, and the 17-entry KNOWN_SESSION_KEYS list plus the enumerated
    // api_key / apikey / access_token literals still cover the enumerated ones. Dropping 'key' and
    // 'code' ENTIRELY was rejected for exactly this reason: api_key and access_code would then
    // depend wholly on enumeration, which is the brittleness the token-boundary rule exists to escape.
    private const val BROAD_WORDS = "key|code"

    // (PRIV-05) WR-01: the credential-bearing prefixes that qualify a BROAD_WORDS occurrence.
    // Maintainer-confirmed set, recorded verbatim — do NOT extend it without the same evidence the
    // narrowing itself required, because every added prefix re-widens all THREE consumers at once.
    // 'public' is deliberately absent: a public key is publishable by definition, which is why
    // public_key and publicKey are pinned in the must-not-redact corpus rather than here.
    // Like SENSITIVE_WORDS this is the READABLE SPECIFICATION, folded into SENSITIVE_KEY_WORDS in
    // factored form and held equivalent by the named test.
    private const val CREDENTIAL_PREFIXES = "api|access|secret|auth|private|signing|enc"

    // (PRIV-05) WR-01: the OPTIONAL single separator between the prefix and the broad word, so
    // api_key, api-key, api.key, apiKey and apikey are one rule rather than five. It is a single
    // optional character rather than a quantified class on purpose: '{0,64}' here would let an
    // arbitrary token sit between the prefix and the word and re-admit access_control_key_layout.
    private const val BROAD_WORD_SEP = "[_.\\-]?"

    // (PRIV-05) WR-01 / T-21-38: SENSITIVE_WORDS and the CREDENTIAL_PREFIXES + BROAD_WORDS rule,
    // compiled into ONE alternation factored by first letter. Read SENSITIVE_WORDS,
    // CREDENTIAL_PREFIXES and BROAD_WORDS above for the vocabulary; this constant is the compiled
    // form of exactly those three and adds no word of its own.
    //
    // WHY FACTORED — measured, not stylistic, and the measurement is why this shape is load-bearing.
    // On a 1 MB maximum-key-density JSON body, best of five, driving the live jsonSecretKeyRegex:
    //
    //     pre-WR-01 vocabulary, flat          50 ms   (the cost this file shipped with)
    //     WR-01 vocabulary, flat              58 ms   (+16%)
    //     WR-01, only the 7 prefixes factored 53 ms   (+6%)
    //     WR-01, factored by first letter     47 ms   (-6%)
    //
    // The flat forms lose because each branch is probed separately at every backtrack position of
    // the {0,64} padding; factoring probes the shared 'a', 's' and 'p' heads once. The +16% and +6%
    // shapes were both measured FAILING newlineFreeOversizeBodyIsScannedNotDestroyed — the 4 MB
    // newline-free fixture already spends ~1.9 s of the body stage's 2 s MAX_REDACTION_BUDGET_MS, so
    // a few per cent exhausts the budget and the window carrying the secret is dropped behind a
    // marker. That is fail-closed and never a leak, but it is the capability regression ADR-14
    // exists to prevent. Do NOT flatten this back out; add words to SENSITIVE_WORDS and re-factor.
    //
    // 'pi[_.\-]?(key|code)' subsumes the api_key and apikey literals, so they are not repeated here.
    // Both remain in SENSITIVE_WORDS because they are v0.6.0 vocabulary, and the equivalence test is
    // what licenses dropping the redundant branches from the compiled form.
    private const val SENSITIVE_KEY_WORDS =
        // a- : access_token, api_key, apikey, auth + api/access/auth prefixing a broad word.
        "a(?:ccess_token|ccess$BROAD_WORD_SEP(?:$BROAD_WORDS)|pi$BROAD_WORD_SEP(?:$BROAD_WORDS)|" +
            "uth$BROAD_WORD_SEP(?:$BROAD_WORDS)|uth)|" +
            // t- : token.
            "token|" +
            // s- : secret, session, sid + secret/signing prefixing a broad word.
            "s(?:ecret$BROAD_WORD_SEP(?:$BROAD_WORDS)|ecret|ession|id|" +
            "igning$BROAD_WORD_SEP(?:$BROAD_WORDS))|" +
            // p- : password, pwd + private prefixing a broad word.
            "p(?:assword|wd|rivate$BROAD_WORD_SEP(?:$BROAD_WORDS))|" +
            // e- : enc prefixing a broad word.
            "enc$BROAD_WORD_SEP(?:$BROAD_WORDS)"

    // (PRIV-05) SC3 / D-11: vendor and framework session-cookie names that NO morphological rule
    // can catch, because the sensitive word is concatenated without a separator (JSESSIONID,
    // PHPSESSID, csrftoken) or is absent from the name entirely (remember_me). Whole-key match;
    // case-insensitive via each consumer's leading (?i). Dots are escaped.
    private const val KNOWN_SESSION_KEYS =
        "jsessionid|phpsessid|asp\\.net_sessionid|\\.aspxauth|aspxauth|csrftoken|" +
            "remember_me|remember_token|laravel_session|ci_session|_session_id|sessionid|sessid|" +
            "cfid|cftoken|xsrf-token|_csrf"

    // (PRIV-05) SC3 / D-11: the character class a key name may be built from. '[' and ']' cover
    // PHP array parameters of the a[b] form; '.' covers connect.sid and ASP.NET_SessionId.
    private const val KEY_CHARS = "[A-Za-z0-9_.\\-\\[\\]]"

    // (PRIV-05) SC3 / D-13: the token-boundary constructs placed immediately before and after the
    // matched word. First alternative = the separator rule ('_', '-', '.', '[', ']' and the string
    // boundaries delimit a whole token). Second alternative = the camelCase rule, so authToken,
    // accessToken and userSessionId match.
    // NON-OBVIOUS BLOCKER: the camelCase half CANNOT be written inline under the consumers' (?i) —
    // case-insensitivity makes [A-Z] match lowercase too, so every position would qualify and the
    // boundary would degrade to a substring match. Java's inline flag-off group (?-i:...) is what
    // makes it work; verified on JDK 21.
    // REVERT POINT (one deletion each): removing the (?-i:...) alternative from WORD_BEFORE and
    // WORD_AFTER reverts D-13 entirely. That loses nothing SC3 requires and removes the accepted
    // over-redactions recorded below that the camelCase rule drives — tokenCount and tokenType.
    // It named codeName and keyName too until WR-01 narrowed the two broad words out of the
    // containment rule; those two now survive on their own and no longer depend on this revert.
    private const val WORD_BEFORE = "(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z0-9])(?=[A-Z])))"
    private const val WORD_AFTER = "(?:(?![A-Za-z0-9])|(?-i:(?<=[a-z0-9])(?=[A-Z])))"

    // (PRIV-05) SC3 / D-11: the shared sensitive-KEY expression consumed by urlTokenParamRegex,
    // formBodyParamRegex and jsonSecretKeyRegex. It replaces the old exact-word alternation, which
    // demanded the key be EXACTLY one of the twelve words — that is why auth_token missed (auth was
    // followed by '_', not '='), and why only a cookie literally named "session" was ever caught.
    //
    // (a) A key is sensitive when it IS a known vendor name, or when it CONTAINS one of the words
    //     as a whole token, treating '_', '-', '.', '[', ']', the string boundaries and
    //     lower-to-upper case transitions as delimiters. So auth_token, X-Session-Id and
    //     connect.sid match, while keyboard_layout, codename, sidebar and keychain do not.
    // (b) Prefix and suffix are BOUNDED at 64 characters: an unbounded '*' measured 2.3x slower on
    //     adversarial input (21 ms vs 9 ms on 1 MB) and reintroduces exactly the unbounded-
    //     quantifier adjacency this file already warns about above formBodyParamRegex.
    // (c) EVERY internal group is non-capturing, so the group numbering of all three consumers is
    //     unchanged and their existing replacement expressions still reproduce the key exactly
    //     (Pitfall 7).
    //
    // D-12: there is deliberately NO benign-key denylist. The recommendation proposed one;
    // measurement found nothing to guard against — all 21 must-not-redact keys pass on the
    // boundary rule alone. Do not add one: every entry in such a list is a place where a real
    // credential could be accidentally allowlisted.
    //
    // (d) (PRIV-05) WR-01: the two BROAD_WORDS do NOT take part in clause (a). They get their own
    //     two alternatives instead — a bare one, which the consumers' own anchors ('[?&]…=', '^…=',
    //     '"…":') turn into WHOLE-KEY EQUALITY with no code of its own, and a prefixed one that
    //     requires a CREDENTIAL_PREFIXES token immediately in front. So api_key, api-key, api.key,
    //     apiKey, access_code, private_key and signing_key still redact while status_code,
    //     error_code, statusCode, errorCode, primary_key, sort_key, cache_key and zip_code survive.
    //     The bare alternative carries NO KEY_CHARS padding, and that absence IS the whole-key
    //     rule — adding padding to it would silently restore the pre-WR-01 breadth.
    //
    // Two deliberate residuals:
    //   - PLURAL forms (codes, tokens, keys) are NOT handled. Adding 's?' to the vocabulary would
    //     catch them at the cost of a second widening axis; SC3 does not require it.
    //   - ACCEPTED over-redactions, all fail-safe and all analytically low-value. Under the
    //     separator rule: token_bucket_size, session_timeout_seconds, auth_provider, secret_santa,
    //     password_hint_enabled, and — measured by the Phase 21 code review and NOT closed by
    //     WR-01 — auth_type, auth_url, session_count, token_type. Under the camelCase rule (D-13):
    //     tokenCount, tokenType. Every one of these is driven by 'auth', 'session' or 'token', NOT
    //     by the two broad words, so the WR-01 narrowing does not reach them: it narrowed 'key' and
    //     'code' only. token_type / tokenType are the analytically painful pair — token_type:
    //     "Bearer" is benign OAuth metadata — and making them survive needs either a suffix
    //     denylist (which D-12 rejects on principle) or a narrowing of 'token' itself, which would
    //     put access-token and XSRF-TOKEN at risk. Both are maintainer decisions, not executor
    //     ones; the pair is asserted AS ACCEPTED in RedactionTest so it stays visible.
    //     WR-01 removed four names from this list — key_size and code_version under the separator
    //     rule, codeName and keyName under the camelCase rule — because all four are broad-word
    //     driven. auth_provider remains the only accepted case with real analytic value besides
    //     token_type, and redacting it is still the correct default for a key literally named auth_*.
    // (e) (PRIV-05) WR-01 / T-21-38: the prefixed broad-word rule shares clause (a)'s
    //     KEY_CHARS{0,64}...WORD_BEFORE / WORD_AFTER...KEY_CHARS{0,64} padding rather than being a
    //     top-level alternative with padding of its own. That is a MEASURED requirement, not
    //     tidiness. Written as its own padded alternative it doubled the leading {0,64} scan and
    //     cost +67% on the JSON rule. It is folded into SENSITIVE_KEY_WORDS for the same reason —
    //     see the measurement table there before changing either.
    private const val SENSITIVE_KEY_EXPR =
        "(?:(?:$KNOWN_SESSION_KEYS)|" +
            "$KEY_CHARS{0,64}$WORD_BEFORE(?:$SENSITIVE_KEY_WORDS)$WORD_AFTER$KEY_CHARS{0,64}|" +
            "(?:$BROAD_WORDS))"

    // Internal test seam — SENSITIVE_KEY_EXPR written in its READABLE, UNFACTORED form, built from
    // the SENSITIVE_WORDS / CREDENTIAL_PREFIXES / BROAD_WORDS specification constants directly
    // rather than from SENSITIVE_KEY_WORDS. Not part of the public API and reachable from no
    // production path, in the style of testHkdfExtract and testSplitPoint.
    //
    // This exists so the hand-written first-letter factoring above is CHECKED rather than trusted.
    // RedactionTest.factoredKeyVocabularyMatchesItsReadableSpecification drives this expression and
    // the shipped one over the whole key corpus and asserts they classify every name identically.
    // Building it here rather than restating the vocabulary in the test is the point: a word added
    // to SENSITIVE_WORDS and forgotten in SENSITIVE_KEY_WORDS fails that test, which is exactly the
    // mistake the factoring makes easy. Keep the two in sync by editing the readable constants
    // first, then re-factoring.
    //
    // (PRIV-05) IN-01 — WHY THIS IS A FUNCTION AND NOT A const val. It was
    // `internal const val NAIVE_KEY_EXPR_FOR_TEST`, and Kotlin compiles an internal const val in an
    // object to a PUBLIC STATIC FINAL FIELD: `javap -p Redaction.class` listed
    // `public static final java.lang.String NAIVE_KEY_EXPR_FOR_TEST`, so a 495-character test seam
    // was an API-surface field of the shipped Custom-AI-Agent JAR, reachable by any code on the
    // classpath. An internal fun is name-mangled instead (testSplitPoint ships as
    // `testSplitPoint$burp_ai_agent`) and emits no field at all, which is how the file's other four
    // seams already behave. It is inert either way; the BApp Store review surface is why it was
    // worth spending two lines on.
    //
    // THE PROPERTY THAT MATTERS IS *WHERE THE REFERENCE IS BUILT*, NOT WHETHER IT IS A CONSTANT.
    // Restating the vocabulary in the test source set would also have removed the field and would
    // have destroyed the whole point: the reference has to be assembled HERE, in production, from
    // the same readable constants the factored form claims to compile, so that a word added to
    // SENSITIVE_WORDS and forgotten in SENSITIVE_KEY_WORDS still fails the equivalence test. The
    // conversion preserves the value byte for byte (SHA-256 f67e9b1d078a4ae42dc2f521e4ad69024e10368d
    // 9ef9d3502cf94bdf03feaff3, length 495, measured before and after).
    internal fun naiveKeyExprForTest(): String =
        "(?:(?:$KNOWN_SESSION_KEYS)|" +
            "$KEY_CHARS{0,64}$WORD_BEFORE" +
            "(?:(?:$SENSITIVE_WORDS)|(?:$CREDENTIAL_PREFIXES)$BROAD_WORD_SEP(?:$BROAD_WORDS))" +
            "$WORD_AFTER$KEY_CHARS{0,64}|" +
            "(?:$BROAD_WORDS))"

    // (PRIV-05) W-06: the ONE definition of the replacement string apply() pairs with
    // urlTokenParamRegex in the header stage. Its value is byte-identical to the literal that used
    // to sit at that call site; naming it is what lets testKeyRules() below report the replacement
    // the pipeline ACTUALLY applies instead of a retyped copy of it. The two body rules already had
    // a single home for their replacements in bodyRules(); this is the header stage's equivalent,
    // and the same argument applies — a seam that reported a string the pipeline does not use would
    // turn the Pitfall 7 group-count assertion into a statement about the seam.
    private const val URL_TOKEN_REPLACEMENT = "\$1[REDACTED]"

    // Tokens/secrets in URL query strings, e.g. ?access_token=xyz or &api_key=xyz
    // (PRIV-05) SC3: the key side is the shared key expression, so compound and vendor keys
    // (auth_token, api-key, X-Session-Id, JSESSIONID) are caught here too. Group 1 is still the
    // whole "[?&]key=" prefix, so the "$1[REDACTED]" replacement in apply() is unchanged.
    private val urlTokenParamRegex =
        Regex(
            "(?i)([?&](?:$SENSITIVE_KEY_EXPR)=)[^&\\s\"'<>]+",
        )

    // (PRIV-02) x-www-form-urlencoded field ANYWHERE in a body, INCLUDING the leading field.
    // The (^|[?&]) anchor closes the documented gap: the old [?&]-only urlTokenParamRegex
    // missed "apikey=sk-abc123&user=bob" (no leading ? or &). (?im) = multiline+case-insensitive.
    // The value charclass [^&\s"'<>]+ is bounded — no trailing anchor that would backtrack (Pitfall 3).
    // (PRIV-05) SC3: group 1 is still the ^/?/& prefix and group 2 is still the WHOLE key, so the
    // "$1$2=[REDACTED]" lambda in apply() reproduces compound keys such as auth_token exactly.
    private val formBodyParamRegex =
        Regex(
            "(?im)(^|[?&])($SENSITIVE_KEY_EXPR)=[^&\\s\"'<>]+",
        )

    // (PRIV-02) JSON values for known-sensitive key names.
    // Key-scoped: only a value following a matching key name is redacted; "name":"alice" is untouched.
    // The value side (group 2) covers a quoted string OR an unquoted JSON scalar (boolean, null, or
    // number) so numeric/boolean secrets such as {"token":12345,"pin":123456} are not missed (WR-03).
    // Whatever the original value type, it is replaced with the quoted token "[REDACTED]", which keeps
    // the output valid JSON.
    // Limitation: a value containing an escaped quote (e.g. "token":"ab\"cd") will be partially
    // matched (stops at the backslash). This is an accepted limitation — real API tokens are
    // [A-Za-z0-9._-] and do not contain embedded quotes; use a JSON parser if full coverage is needed.
    // (PRIV-05) SC3: the key side is the shared key expression, which is already (?:...)-wrapped —
    // do not wrap it again here. Group 1 is still "key": including whitespace and group 2 is still
    // the value, so the "$1\"[REDACTED]\"" lambda in apply() is unchanged.
    private val jsonSecretKeyRegex =
        Regex(
            "(?i)(\"$SENSITIVE_KEY_EXPR\"\\s*:\\s*)(\"[^\"]*\"|true|false|null|-?\\d+(?:\\.\\d+)?)",
        )

    // (PRIV-05) W-06 / T-21-57 / T-21-58 — internal test seam: the THREE shipped consumers of
    // SENSITIVE_KEY_EXPR, each paired with the replacement string the pipeline actually applies to
    // it. NOT part of the public API; referenced only from the test source set, in the style of
    // testWindowedBodyStage and testSplitPoint below.
    //
    // WHY IT EXISTS — this round's finding, not a generality. Before it,
    // RedactionTest.factoredKeyVocabularyMatchesItsReadableSpecification compared ONE naive rule
    // against redactWith(doc, STRICT), i.e. against the WHOLE pipeline. authHeaderRegex,
    // bearerRegex, basicAuthRegex, jwtRegex, the other two key consumers, both cookie rules and any
    // custom pattern all run in there, and ANY of them firing marks the input "redacted" and MASKS
    // an under-match in the factored form: eight other rules could answer for the one under test.
    // The only way to compare like with like is for the test to reach the shipped rule itself, and
    // that is what this seam hands it. The old test also exercised ONE consumer — the same
    // expression is embedded behind three different anchors, so a factoring error can be invisible
    // in the JSON rule and live in the form rule.
    //
    // THE REPLACEMENT STRINGS ARE READ FROM THE SHIPPED CALL SITES, NOT RETYPED. The two body rules
    // come out of bodyRules(builtinsEnabled = true) — the one list bodyStage applies, looked up by
    // pattern, for the same reason testWindowedBodyStage reads it rather than assembling its own —
    // and the URL rule's replacement is the single URL_TOKEN_REPLACEMENT constant apply() passes.
    //
    // The compiled Regex is returned rather than a Pattern or a bare pattern string so the test can
    // also pin each consumer's capturing-group count (Pitfall 7) without needing a second seam.
    //
    // READ-ONLY: this seam observes the three consumers and changes nothing about them.
    internal fun testKeyRules(): List<Triple<String, Regex, String>> {
        val shippedBodyRules = bodyRules(builtinsEnabled = true)

        // first {} rather than firstOrNull {} with a fallback: a lookup that silently substituted a
        // replacement when it missed would be a vacuity hazard dressed up as a convenience. If the
        // body rule list ever stops carrying one of these, this seam must fail loudly.
        fun replacementFor(rule: Regex): String = shippedBodyRules.first { it.first.pattern() == rule.pattern }.second

        return listOf(
            Triple("urlTokenParamRegex", urlTokenParamRegex, URL_TOKEN_REPLACEMENT),
            Triple("formBodyParamRegex", formBodyParamRegex, replacementFor(formBodyParamRegex)),
            Triple("jsonSecretKeyRegex", jsonSecretKeyRegex, replacementFor(jsonSecretKeyRegex)),
        )
    }

    // (PRIV-02) Custom user patterns compiled by setCustomPatterns. The writer is the settings worker
    // (`burp-ai-settings-save`); the readers are the MCP tool workers and the scanner threads. Volatile
    // so a write is immediately visible to those readers without full synchronization, and so the
    // whole compiled list publishes at once — a reader sees the previous list or the new one, never a
    // partially compiled one.
    @Volatile
    private var compiledCustomPatterns: List<Pattern> = emptyList()

    /**
     * Sets the list of user-supplied custom redaction patterns. Each string is compiled as a
     * java.util.regex.Pattern; entries that fail to compile (PatternSyntaxException) are silently
     * dropped. Passing an empty list clears all custom patterns.
     *
     * Call this from applyAndSaveSettingsBody after the persisted list has been validated by
     * SafeRegex.isPatternSafe so the patterns in this list are already known-safe.
     */
    fun setCustomPatterns(patterns: List<String>) {
        compiledCustomPatterns =
            patterns.mapNotNull { raw ->
                try {
                    Pattern.compile(raw)
                } catch (_: PatternSyntaxException) {
                    null // silently skip uncompilable patterns
                }
            }
    }

    /**
     * (PRIV-06) D-03: optional sink for the truncation notice.
     *
     * Wired in App.initialize to api.logging()::logToOutput, beside the other diagnostics sinks, and
     * UNWIRED in App.shutdown() beside Redaction.clearMappings() (WR-04). It is null in tests and in
     * headless contexts and the redaction pipeline never depends on it — a missing sink costs the
     * user visibility, never correctness, and since WR-04 the same is true of a sink that THROWS
     * (see [maybeLogTruncation]'s runCatching).
     *
     * @Volatile because the write happens on the EDT at startup while the reads happen on scanner
     * threads and MCP tool threads. Modelled on backends/BackendDiagnostics.output, which is the
     * house idiom for a settable diagnostic sink on an otherwise stateless object.
     *
     * This callback is why `redact/` gains NO new dependency for D-03. Routing the notice through
     * the project's audit log was ruled out on two counts: this package is deliberately
     * dependency-light and free of any UI toolkit import, and audit logging is off by default here,
     * so an audit-only signal would be invisible to the very user it exists to warn.
     */
    @Volatile
    var truncationLogger: ((String) -> Unit)? = null

    // (PRIV-06) D-03: rate-limiter state for [maybeLogTruncation]. Two AtomicLongs rather than a
    // lock, so the read-then-CAS below stays allocation-free on the redaction hot path. These are
    // the ONLY object-level fields this phase adds — all window-loop state is local (T-21-23).
    private val lastTruncationLogMs = AtomicLong(0L)

    private val suppressedTruncations = AtomicLong(0L)

    // (PRIV-06) D-03: the notice window, the same length as PassiveAiScannerAnalysis's
    // BACKOFF_LOG_INTERVAL_MS so the two Output-tab limiters cannot drift apart.
    private const val TRUNCATION_LOG_INTERVAL_MS = 10_000L

    /**
     * (PRIV-06) D-03: emits at most one truncation notice per [TRUNCATION_LOG_INTERVAL_MS] window,
     * reporting how many further notices were suppressed since the previous one.
     *
     * [nowMs] is a PARAMETER and the system clock is never read inside, which is the convention
     * established by `PassiveAiScannerAnalysis.maybeLogBackoff(nowMs, untilMs)`: it makes the window
     * assertable without sleeping. That limiter is the model here, deliberately and not
     * `CliBackend.availabilityLogged`, whose semantics are once-ever rather than windowed.
     *
     * [droppedChars] is a count, never the dropped text. The emitted line carries counts only and
     * can therefore never echo attacker-controlled content into the Output tab (T-21-22).
     *
     * (PRIV-06) WR-04 / W-08 / T-21-65 — A FAILING SINK COSTS VISIBILITY, NEVER CORRECTNESS. The
     * [truncationLogger] KDoc already promises that of a MISSING sink; the runCatching below makes
     * it true of a THROWING one. The concrete failure mode is not hypothetical: App.initialize sets
     * the sink to a lambda that captures `api`, and `api.logging()` on a torn-down extension throws.
     * Without the wrap that throw propagates out through redactCookieSections -> apply -> the
     * caller, so a lost diagnostic line becomes a failed redaction on a scanner or MCP tool thread.
     * App.shutdown() nulls the sink, but a pass already in flight can still be between the teardown
     * and that assignment — the wrap is what makes the race harmless, and it holds even if the
     * shutdown step is ever removed.
     *
     * THE WRAP ENCLOSES THE SINK INVOCATION AND NOTHING ELSE, deliberately. The limiter read, the
     * compareAndSet and the getAndSet stay OUTSIDE it: a wrap one line wider would swallow the
     * window bookkeeping along with the sink, so a throwing sink would leave the window permanently
     * closed and every later notice would emit unsuppressed. Guard:
     * RedactionTest.truncationLoggerThatThrowsDoesNotAbortRedaction asserts both halves — the pass
     * completes AND the suppression accounting is intact.
     */
    internal fun maybeLogTruncation(
        nowMs: Long,
        droppedChars: Long,
    ) {
        val prev = lastTruncationLogMs.get()
        // Short-circuits so the CAS is only attempted once the window has actually elapsed. Losing
        // the CAS means a concurrent thread emitted for this window, so this call is a suppression.
        if (nowMs - prev < TRUNCATION_LOG_INTERVAL_MS || !lastTruncationLogMs.compareAndSet(prev, nowMs)) {
            suppressedTruncations.incrementAndGet()
            return
        }
        val suppressed = suppressedTruncations.getAndSet(0L)
        runCatching { truncationLogger?.invoke(truncationLine(droppedChars, suppressed)) }
    }

    // (PRIV-06) D-03: the notice text. A constant sentence plus counts — no dropped content, and
    // no literal window duration that could drift away from TRUNCATION_LOG_INTERVAL_MS.
    private fun truncationLine(
        droppedChars: Long,
        suppressed: Long,
    ): String {
        val line = "[Redaction] Body redaction dropped $droppedChars characters; that content was NOT sent to the AI backend."
        return if (suppressed > 0L) "$line Further notices suppressed since the previous line: $suppressed." else line
    }

    // Internal test seam — clears the D-03 limiter window. NOT part of the public API; only
    // referenced from the test source set, in the style of the testHkdfExtract seam below. It
    // exists because Redaction is a singleton object, so the limiter state otherwise bleeds across
    // tests sharing a JVM and makes an injected-clock assertion order-dependent.
    internal fun resetTruncationWindowForTest() {
        lastTruncationLogMs.set(0L)
        suppressedTruncations.set(0L)
    }

    // (PRIV-06) D-02: nanoseconds per millisecond, now used only by the stage and cookie-section
    // wall-clock budgets. A named constant because detekt's MagicNumber rule
    // ignores only -1/0/1/2 and QUAL-07 forbids growing detekt-baseline.xml.
    private const val NANOS_PER_MS = 1_000_000L

    // (PRIV-06) D-01 / CR-04 / T-21-06 / T-21-08: how many times a window that exhausted its access
    // budget may be halved and retried before it is dropped. The ladder no longer paces benign
    // content: the built-in rules never exhaust their length-proportional budget (see
    // SafeRegex.ACCESS_BUDGET_PER_CHAR), on any machine. It remains the recovery path for a
    // super-linear custom pattern, whose cost per char grows with the window, so a smaller piece
    // can complete where the whole window could not.
    //
    // RAISED FROM 2 TO 4 BY CR-04, because two levels only reach quarters. A newline-free body is ONE
    // window at any size - windowEnd gives an over-width line its own window, and such a body is a
    // single line - so once a rule exhausts on it the ladder is the only way to scan any of it. Four
    // levels reach sixteenths.
    //
    // BOTH BOUNDS, stated so neither is mistaken for the other:
    //   - the real ceiling on retry WORK is Defaults.MAX_REDACTION_BUDGET_MS, not this depth. Every
    //     retry runs under the same stage clock, checked between rules, so the ladder cannot outlive
    //     the total budget by more than one rule call's own access budget, however deep it goes.
    //   - the depth is capped at 4 rather than higher because of Pitfall 8: a wholly-unscannable
    //     window emits up to 2^depth markers, so 16 per window is the deliberate ceiling on the
    //     marker bloat that would otherwise inflate the very prompt this stage exists to bound.
    private const val WINDOW_RETRY_MAX_DEPTH = 4

    // (PRIV-06) CR-04 / T-21-34: how far past the midpoint [splitPoint] may look for a boundary that
    // no built-in body rule's match can span, when a window has no line boundary at all.
    //
    // WHY IT IS BOUNDED. The search is a linear scan, so an unbounded one would make the fallback
    // O(n) in the window length on content that happens to contain no terminator — a 4 MB window
    // walked end to end before giving up. A fixed cap keeps it O(1) in the window size, and giving
    // up costs almost nothing, because the fallback is the exact midpoint rather than the drop this
    // whole branch exists to replace.
    //
    // WHY 1 024. The terminator set below appears every few characters in any minified JSON or
    // form-encoded payload, which is the shape this branch serves. A whole kilobyte without one
    // means the content is not that shape, and the midpoint is then as defensible a cut as any.
    // detekt's MagicNumber ignore list stops at 2, so this is a named constant, not a literal.
    private const val SAFE_CUT_SEARCH_CHARS = 1_024

    // (PRIV-06) CR-04: the non-whitespace half of the value-terminating set. Kept as a string rather
    // than a five-way boolean chain so the set reads as data and stays adjacent to its bound above.
    // See [safeCutPoint] for the derivation of each character from a rule's own value class.
    private const val SAFE_CUT_TERMINATORS = "&,}]"

    // (PRIV-06) CR-02 / T-21-08: how many following lines the JSON boundary-safety rule in
    // [windowEnd] may pull into a window. The extension exists because jsonSecretKeyRegex's \s* can
    // span newlines; capping it is what stops the fix trading a leak for a denial of service, since
    // an unbounded "keep extending until the pair closes" loop lets a crafted run of colon- or
    // quote-terminated lines grow a single window without limit. Eight covers every pretty-printer
    // shape this phase measured — key, colon and value on separate lines, with blank lines between
    // them — with room to spare.
    //
    // Reaching the cap is a DOCUMENTED RESIDUAL, not a closure: a jsonSecretKeyRegex pair spread
    // over more than this many lines can still straddle a cut and be missed. T-21-31 accepts it and
    // ADR-14 and .planning/codebase/CONCERNS.md record it, rather than pretending it away.
    //
    // 21-REVIEW-2 CR-01 — read this residual as THE CAP ONLY, and do not read it as the whole class
    // of window-boundary misses. It was previously the sole recorded residual for this rule, and
    // that framing actively hid a live leak: a pair whose quoted value straddled the cut was missed
    // WITHOUT EVER REACHING THIS CAP, because the risk predicate did not model the open-quoted-value
    // state and so never started a lookahead. That is now closed by endsInsideOpenQuotedValue and is
    // no longer a residual of any kind. What remains here is only the case where an extension DOES
    // start and runs out of budget at this many lines. A future widening of the same kind — a state
    // the predicate cannot see — would again not be bounded by this number, so raising it is not a
    // response to that class of defect.
    //
    // The cap is nonetheless not a fail-OPEN in D-02's sense, and the distinction is worth stating
    // because the two are easy to conflate. This lookahead only ever MOVES a boundary: every byte
    // still lands in exactly one window and is still scanned, nothing is skipped and nothing is
    // emitted unscanned. Any window the extension grows past what will scan in time is still
    // dropped behind a marker by scanWindow/dropOrRetry. What remains at the cap is a rule
    // FALSE NEGATIVE across a cut — the same class as the custom-pattern residual below, not the
    // class of defect PRIV-06 exists to remove. Dropping the window at the cap instead was
    // considered and rejected: the trigger is a content heuristic that ordinary multi-line HTML
    // attributes and nested YAML both satisfy, so it would destroy up to a megabyte of analytic
    // context (T-21-06) on entirely benign input.
    //
    // detekt's MagicNumber ignore list stops at 2, so this is a named constant, not a literal.
    private const val MAX_JSON_BOUNDARY_LOOKAHEAD_LINES = 8

    // (PRIV-06) D-03 / T-21-05: the marker left in the payload when the total budget is spent and
    // the remaining tail is dropped. Exactly ONE of these is emitted per call, never one per
    // window — a 200 MB input would otherwise produce ~200 markers and bloat the very prompt this
    // stage exists to bound.
    //
    // The wording is load-bearing in four ways and must keep all four:
    //   - it says the content was REMOVED, not passed through. A "TRUNCATED / NOT SCRUBBED" phrasing
    //     reads as "what follows is unfiltered", the opposite of what actually happened.
    //   - it is distinguishable from [REDACTED], so a reader can tell "removed for size" from
    //     "removed for secrecy" — the same reason [JWT_REDACTED] and [STRIPPED] are distinct today.
    //   - it is a constant shape plus one integer, so it carries ZERO attacker-controlled substring
    //     and is not a prompt-injection vector.
    //   - it is not phrased as an instruction to the model.
    // ASCII hyphen, never an em dash: the marker is prompt content that gets hashed into
    // sha256Hex(singlePrompt) and round-trips through backend transports.
    private fun budgetExceededMarker(droppedChars: Int): String = "[REDACTION BUDGET EXCEEDED - $droppedChars CHARS DROPPED AND NOT SENT]"

    // (PRIV-06) D-02 / D-03: the marker left in place of a single window that could not be fully
    // scanned inside its access budget. Same four wording properties as the budget marker above; a
    // distinct token so "the budget ran out" and "this window would not scan" stay tellable apart
    // in a prompt.
    private fun windowDroppedMarker(droppedChars: Int): String = "[REDACTION INCOMPLETE - $droppedChars CHARS DROPPED AND NOT SENT]"

    // (PRIV-06) D-01 AMENDED / D-02 / D-04 / D-05 / D-14: the body-redaction stage.
    //
    // Before Phase 21 this was an `if (out.length <= MAX_REDACTION_BODY_CHARS)` guard INSIDE the
    // redactTokens branch: an input above the cap had the form, JSON and custom-pattern rules
    // skipped entirely and the original passed through untouched. That is redaction failing open on
    // exactly the inputs most likely to carry a secret (T-21-02), and removing it is PRIV-06.
    //
    // D-01 AMENDED — the input is cut into windows at LINE BOUNDARIES and every window is scanned;
    // nothing is skipped. A line is never split: every built-in body rule is line-anchored or
    // line-local, so a mid-line cut is the only thing that can change their semantics, and it was
    // measured doing so in BOTH directions (creating a match at an artificial line start, and
    // truncating a match that spans the cut). The original decision's OVERLAP clause is
    // deliberately dropped rather than implemented: the value side of every built-in is
    // length-unbounded (measured single matches of 200 006 characters) and user patterns are
    // unbounded by construction, so no finite overlap constant is defensible.
    // Matcher.region() has the right semantics but replaceAll() silently resets the region, so
    // region-scoped replacement is not available at all.
    //
    // WHAT LINE-BOUNDARY CUTTING ACTUALLY BUYS, stated as it ships rather than as it was first
    // claimed: it preserves the LINE-ANCHORED SEMANTICS of the built-in body rules — no (?m)^ anchor
    // is created at an artificial line start and none is destroyed mid-line — and for the one
    // built-in whose match can span newlines, jsonSecretKeyRegex, windowEnd's risk predicate models
    // BOTH states that rule can be in at a cut: in the whitespace around the colon, and inside an
    // unterminated quoted value (see endsInsideOpenQuotedValue). When either fires, the window is
    // extended, and that extension is bounded by MAX_JSON_BOUNDARY_LOOKAHEAD_LINES. Byte-identity
    // with whole-document processing is NOT claimed in general: a pair spread over more lines than
    // that bound, and any user custom pattern spanning a cut, can still be missed. Both residuals
    // are recorded in ADR-14 and in .planning/codebase/CONCERNS.md.
    //
    // CR-02 / D-08 REFINED — why the previous wording is gone, recorded so it reads as a deliberate
    // retirement rather than something lost in an edit: this paragraph used to state that
    // line-boundary cutting had been proven equivalent, byte for byte, to whole-document
    // processing. That was FALSE as implemented, and it was falsified by a reproduction rather than
    // by argument — a three-line JSON pair straddling the cut leaked on the windowed path while the
    // single-pass path redacted it. The original claim was established without ever sweeping a
    // fixture across the cut, which is exactly why it survived review. The claim now lives in a
    // named test, windowedScanRedactsJsonPairAcrossEveryBoundaryAlignment, so the assertion and its
    // evidence cannot drift apart again. A record claims only what ships.
    //
    // 21-REVIEW-2 CR-01 / D-08 REFINED — a SECOND retirement in the same paragraph, recorded for the
    // same reason. The replacement wording above used to present jsonSecretKeyRegex as fully handled
    // by windowEnd's capped lookahead — deliberately paraphrased here rather than quoted, so the
    // falsified sentence is not left verbatim in the file for a later reader to lift back out of its
    // retirement. That asserted coverage this code did not have. The risk predicate saw only the
    // whitespace around the colon, so a pair whose quoted value carried a raw newline across the cut
    // never started a lookahead at all and the cap was never reached — the recorded residual
    // described a bound that the failing shape never touched. Falsified by a reproduction over the
    // COMPILED SHIPPED CLASSES, not by argument: 6 of 40 alignments of a 1 MB body leaked with
    // dropMarker=false while the single-pass path redacted the identical content, and this repository
    // reproduced the same class at 8 of 40 alignments once the fixture geometry was corrected (see
    // windowedScanRedactsJsonPairWhoseValueStraddlesTheCut). It survived the first review because the
    // fixture family behind both committed sweeps could not produce the shape — every line of those
    // fixtures ends on ':' or '"', which is the state the old predicate already detected. The guard
    // is now windowedScanRedactsJsonPairWhoseValueStraddlesTheCut. The lesson is narrower and worse
    // than "the claim was too broad": a claim can be falsified by the ABSENCE of a fixture family,
    // so a coverage sentence is only as strong as the shapes its tests can construct.
    //
    // The bounded lookahead is NOT the overlap clause reinstated under another name. That clause
    // stays dropped on the measured grounds above; this mechanism moves the BOUNDARY, so windows
    // remain disjoint and line-aligned and no region is ever duplicated into two windows.
    //
    // D-02 / D-14 — fail CLOSED, at EVERY size. Every rule, on both the single-pass path and the
    // windowed path, runs through SafeRegex.replaceAllSafeReporting, and a timedOut flag is never
    // ignored: above the window width the affected window is DROPPED behind a marker, and at or
    // below it the partial result is discarded and the whole input is re-scanned through the
    // windowed path. Assigning the .text of replaceAllSafeReporting anywhere in this stage WITHOUT
    // branching on timedOut would be fail-OPEN at exactly the moment D-02 demands fail-closed,
    // because on timeout that text is the input unchanged — byte-identical to "the pattern matched
    // nothing" (T-21-03). WR-03 deleted the String-returning façade that made that mistake a
    // one-word autocomplete, so it now takes a deliberate discard of the flag. There is therefore no
    // size at which a body rule can time out and its unscanned bytes still be emitted.
    @Suppress("ReturnCount")
    private fun bodyStage(
        input: String,
        builtinsEnabled: Boolean,
    ): String {
        val rules = bodyRules(builtinsEnabled)

        // OFF with no custom patterns must be a byte-identical passthrough, so this check comes
        // BEFORE any windowing. Any marker, normalisation or trailing-newline difference introduced
        // here fails offModePreservesBodies and offModePreservesAllTokens.
        if (rules.isEmpty()) return input

        // PRIV-06 / D-04: at or below the window width this is a single pass whose cost and
        // behaviour match the pre-Phase-21 implementation for the overwhelming majority of
        // payloads — when no rule times out, the loop below is byte-identical to a plain
        // replace-each-rule chain. One genuine change even on this path: the two built-in body
        // rules previously ran with NO bound at all (only custom patterns went through
        // SafeRegex) and now all of them do.
        //
        // (PRIV-06) D-02 / D-14: that new bound must not smuggle a fail-OPEN back in.
        // SafeRegex.replaceAllSafeReporting yields its input UNCHANGED as .text on timeout,
        // byte-identical to "the pattern matched nothing", so assigning that text here WITHOUT
        // branching on timedOut would silently skip an overrunning rule and emit unredacted content
        // on the common path — the exact failure mode this phase exists to remove, reintroduced one
        // size class lower. The timedOut flag is the only signal that tells the two cases apart, so
        // it is what is branched on. WR-03 deleted the String-returning façade that once offered the
        // fail-open form by autocomplete; making that mistake now requires dropping the flag on
        // purpose.
        //
        // On timeout the PARTIAL result is discarded and the ORIGINAL input is handed to
        // windowedScan, which already fails closed (halve-and-retry to WINDOW_RETRY_MAX_DEPTH, then
        // drop behind a visible marker). Restarting from the original rather than continuing from
        // the partially-processed string avoids double-marking and any partial-application ordering
        // artifact, and it reuses that machinery instead of duplicating it here.
        //
        // BUDGET CEILING - stated rather than assumed: this composition CAN exceed
        // Defaults.MAX_REDACTION_BUDGET_MS, because windowedScan starts its own budget clock. The worst
        // case is the rules already completed, plus one exhausted SafeRegex.accessBudgetFor(length),
        // plus the stage budget, plus at most one rule-call overrun - finite, and only reachable by a
        // pathological custom pattern, whose depth-0 window in windowedScan then re-exhausts: a known,
        // bounded waste of one budget. Threading one shared deadline into windowedScan was rejected:
        // the fallthrough would routinely arrive with the budget already spent and drop the ENTIRE
        // body behind one marker, fail-closed but destroying all analytic context (T-21-06) on an
        // input small enough to scan properly.
        if (input.length <= Defaults.MAX_REDACTION_BODY_CHARS) {
            var out = input
            for ((pattern, replacement) in rules) {
                val result = SafeRegex.replaceAllSafeReporting(out, pattern, replacement)
                if (result.timedOut) return windowedScan(input, rules)
                out = result.text
            }
            return out
        }

        return windowedScan(input, rules)
    }

    // (PRIV-06) D-05 / W-04: the ordered rule list [bodyStage] applies, extracted so that stage and
    // the testWindowedBodyStage seam below build the IDENTICAL list from ONE place. A seam that
    // assembled its own list would be free to drift from the shipped one, and an assertion carried
    // by a drifted seam proves nothing about what ships — which is the whole reason the seam is
    // allowed to exist at all.
    //
    // D-05 — THE CUSTOM-PATTERN LOOP SITS OUTSIDE THE redactTokens BRANCH, deliberately, and that is
    // what this list's shape encodes: a user's custom list applies in EVERY privacy mode, including
    // OFF, because it is a "never send this, ever" list and is independent of the privacy mode. OFF
    // means "no built-in redaction", not "no redaction at all". The comment travels with the list
    // rather than with its caller, because it explains the list.
    private fun bodyRules(builtinsEnabled: Boolean): List<Pair<Pattern, String>> =
        buildList {
            if (builtinsEnabled) {
                // The $n replacement strings are byte-for-byte equivalent to the Kotlin lambdas
                // they replace (verified); SafeRegex takes a String replacement, not a lambda.
                add(formBodyParamRegex.toPattern() to "\$1\$2=[REDACTED]")
                add(jsonSecretKeyRegex.toPattern() to "\$1\"[REDACTED]\"")
            }
            compiledCustomPatterns.forEach { add(it to "[REDACTED]") }
        }

    // (PRIV-06) D-01 AMENDED / D-02: the windowed loop used above the window width. Windows are
    // processed IN ORDER, and each one is either fully scanned and appended or dropped behind a
    // marker. Once the total budget is spent, ALL remaining characters are coalesced into exactly
    // one tail marker and the loop breaks. Every piece of loop state is a local: apply() runs
    // concurrently on scanner threads and MCP tool threads, so object-level window state would
    // corrupt output across them (T-21-23).
    //
    // (PRIV-06) W-04 / T-21-56 - [budgetMs] AND [accessBudget] ARE TEST SEAMS AND THEIR DEFAULTS
    // ARE LOAD-BEARING. budgetMs defaults to Defaults.MAX_REDACTION_BUDGET_MS and accessBudget to
    // SafeRegex::accessBudgetFor, exactly what this function used before either parameter existed,
    // so EVERY production call site is byte-identical in behaviour: bodyStage's two calls pass
    // neither and get the shipped 2 s and the shipped per-rule budget. Stated here because a default
    // that silently changes production behaviour is exactly the seam that turns a test aid into a
    // defect. Neither shipped value is a dial (see Defaults.MAX_REDACTION_BUDGET_MS and
    // SafeRegex.ACCESS_BUDGET_PER_CHAR), and nothing in the test source set may change them.
    private fun windowedScan(
        input: String,
        rules: List<Pair<Pattern, String>>,
        budgetMs: Long = Defaults.MAX_REDACTION_BUDGET_MS,
        accessBudget: (Int) -> Long = SafeRegex::accessBudgetFor,
    ): String {
        val budgetDeadlineNanos = System.nanoTime() + budgetMs * NANOS_PER_MS
        val sink = StringBuilder(input.length)
        var index = 0
        while (index < input.length) {
            if (remainingBudgetMs(budgetDeadlineNanos) <= 0L) {
                val dropped = input.length - index
                sink.append(budgetExceededMarker(dropped))
                maybeLogTruncation(System.currentTimeMillis(), dropped.toLong())
                break
            }
            val end = windowEnd(input, index, Defaults.MAX_REDACTION_BODY_CHARS)
            scanWindow(input.substring(index, end), rules, budgetDeadlineNanos, 0, sink, accessBudget)
            index = end
        }
        return sink.toString()
    }

    // (PRIV-06) D-02: milliseconds left in the total body-stage budget; zero or negative once spent.
    private fun remainingBudgetMs(budgetDeadlineNanos: Long): Long = (budgetDeadlineNanos - System.nanoTime()) / NANOS_PER_MS

    // (PRIV-06) D-02 / D-14: applies every rule to one window; appends ONLY a fully scanned result.
    //
    // Each rule gets accessBudget(current.length), a deterministic bound that reads no clock. The
    // stage clock is checked BETWEEN rules only, so a rule that starts just before the deadline can
    // overrun the 2 s by at most its own budget (about 0.6 s per MB on a pathological pattern).
    // The .text of replaceAllSafeReporting is never taken here without first branching on timedOut - on
    // timeout that text is the input unchanged, indistinguishable from "no matches". WR-03 removed
    // the String-returning façade that used to hide that hazard behind a plain return type.
    private fun scanWindow(
        window: String,
        rules: List<Pair<Pattern, String>>,
        budgetDeadlineNanos: Long,
        depth: Int,
        sink: StringBuilder,
        accessBudget: (Int) -> Long,
    ) {
        var current = window
        for ((pattern, replacement) in rules) {
            val remainingMs = remainingBudgetMs(budgetDeadlineNanos)
            if (remainingMs <= 0L) {
                dropOrRetry(window, rules, budgetDeadlineNanos, depth, sink, accessBudget)
                return
            }
            val result = SafeRegex.replaceAllSafeReporting(current, pattern, replacement, accessBudget(current.length))
            if (result.timedOut) {
                dropOrRetry(window, rules, budgetDeadlineNanos, depth, sink, accessBudget)
                return
            }
            current = result.text
        }
        sink.append(current)
    }

    // (PRIV-06) D-01 / CR-04 / T-21-06: halve-and-retry before dropping. A window that did not scan
    // in time is split — at a LINE boundary whenever it has one, and otherwise at a bounded safe cut
    // (see [splitPoint]) - and each half is retried, to WINDOW_RETRY_MAX_DEPTH levels, so a
    // super-linear pattern loses as little content as possible instead of the whole window.
    //
    // The window is dropped behind exactly one marker when the retry depth is exhausted, when the
    // budget is already spent, or when the window is too short to split at all — fail closed, so its
    // unscanned bytes never reach a backend.
    //
    // CR-04 — the third condition used to read "when the window has no interior line boundary to
    // split on", and that made the drop the ONLY reachable outcome for a newline-free body of ANY
    // size, which is the normal shape of a minified-JSON API response. It is now a window of one
    // character or less, so the ladder engages on the payload shape it was always meant to pace.
    //
    // TERMINATION, stated because the recursion is not obviously finite: each half is strictly
    // shorter than the window, because splitPoint returns either 0 or an index strictly inside it;
    // depth is bounded by WINDOW_RETRY_MAX_DEPTH; and the total budget bounds the work regardless of
    // both.
    private fun dropOrRetry(
        window: String,
        rules: List<Pair<Pattern, String>>,
        budgetDeadlineNanos: Long,
        depth: Int,
        sink: StringBuilder,
        accessBudget: (Int) -> Long,
    ) {
        val retryable = depth < WINDOW_RETRY_MAX_DEPTH && remainingBudgetMs(budgetDeadlineNanos) > 0L
        val cut = if (retryable) splitPoint(window) else 0
        if (cut <= 0 || cut >= window.length) {
            sink.append(windowDroppedMarker(window.length))
            maybeLogTruncation(System.currentTimeMillis(), window.length.toLong())
            return
        }
        scanWindow(window.substring(0, cut), rules, budgetDeadlineNanos, depth + 1, sink, accessBudget)
        scanWindow(window.substring(cut), rules, budgetDeadlineNanos, depth + 1, sink, accessBudget)
    }

    // (PRIV-06) D-01 / CR-04: where to cut [window] in half so each half can be retried.
    //
    // A LINE BOUNDARY IS ALWAYS PREFERRED, and wherever one exists nothing here has changed: the
    // returned index is just past a '\n', so both halves stay line-aligned and (?m)^ keeps its
    // meaning inside each of them. splitPointStillCutsAtALineBoundaryWhenOneExists is the guard on
    // that, and it is green before and after this change by design.
    //
    // CR-04 — THE ONE DOCUMENTED EXCEPTION. When the window contains no newline anywhere, this used
    // to return 0, and dropOrRetry's `if (cut <= 0 …)` turned that into a total drop: the entire
    // window replaced by a marker. That is the normal shape of an API response —
    // McpToolContext.redactIfNeeded receives serialized tool output up to maxBodyBytes (2 MiB by
    // default) and toolJson.encodeToString(...) emits MINIFIED, newline-free output — so the retry
    // ladder was structurally inapplicable to the most common oversized payload there is, and a
    // default-configuration 2 MiB tool response reached the model as one drop marker and nothing
    // else.
    //
    // WHY THAT IS NOT THE (?m)^ TRAP REOPENED. Mid-line cutting is unsafe in general, and
    // 21-RESEARCH.md "Decision 3" proved it in both directions: a cut can create a match at an
    // artificial line start, and can truncate a match that spans it. Three properties of THIS BRANCH
    // — not of good intentions — make the exception safe:
    //   1. This branch is reached only where there is no USABLE INTERIOR newline, and the cut
    //      position is therefore the only artificial line start it can create — one position in the
    //      whole window, rather than one per line.
    //      IN-02 — the premise is stated about the CUT rather than about the window's line count,
    //      because the earlier wording ("a window with no interior newline has no interior line
    //      anchors to corrupt") is FALSE of the branch it justifies. The branch is taken whenever
    //      `backward <= 0 && (forward < 0 || forward + 1 >= window.length)`, which admits windows
    //      that do contain a newline, at index 0 or at the final position. Measured against the
    //      shipped testSplitPoint seam rather than argued: splitPoint("\n" + "x".repeat(10))
    //      returns 5, cutting mid-line in an 11-character window that has TWO lines, and the
    //      trailing-newline case splitPoint("x".repeat(10) + "\n") returns 5 as well. The
    //      CONCLUSION is unchanged and points 2 and 3 below still carry the argument — but this is
    //      the premise licensing an artificial (?m)^ anchor, so a false statement inside it is not
    //      cosmetic.
    //   2. That artificial anchor can only OVER-redact, never leak. formBodyParamRegex's (^|[?&])
    //      matching at the head of the second half yields a false positive, and a false positive
    //      here is fail-safe — it removes content that did not need removing, which is the direction
    //      this file errs in everywhere else too.
    //   3. This branch is reachable ONLY from dropOrRetry — that is, only after a rule has already
    //      exhausted its access budget and the alternative is dropping the whole window behind a marker.
    //      A match truncated by the cut is a false negative, but the content it sits in is otherwise
    //      not scanned AND NOT EMITTED AT ALL, so there is strictly nothing to lose.
    //
    // NOT A LICENCE TO CUT MID-LINE ANYWHERE ELSE. Point 3 is what makes points 1 and 2 acceptable,
    // and it holds nowhere else in this file. Everywhere a line boundary exists this function still
    // uses it, and windowEnd still gives an over-width line its own window rather than splitting it.
    //
    // NOT OVERLAP EITHER. The two halves are disjoint and no region is processed twice. D-01
    // AMENDED's overlap clause stays dropped on its measured ground — single matches of the built-in
    // rules reach 200 006 characters and user patterns are unbounded by construction, so no finite
    // overlap constant is defensible. What the cut leaves is a bounded straddle residual, recorded
    // in ADR-14 and in .planning/codebase/CONCERNS.md rather than pretended away.
    private fun splitPoint(window: String): Int {
        val mid = window.length / 2
        val backward = window.lastIndexOf('\n', mid)
        if (backward > 0) return backward + 1
        val forward = window.indexOf('\n', mid)
        return if (forward >= 0 && forward + 1 < window.length) forward + 1 else safeCutPoint(window, mid)
    }

    // (PRIV-06) CR-04 / T-21-34: the newline-free fallback used by [splitPoint], and only by it.
    //
    // From [mid], scan forward at most SAFE_CUT_SEARCH_CHARS characters for the first character that
    // terminates every built-in body rule's match and cut just after it; fall back to the exact
    // midpoint when none is found, and to 0 — which dropOrRetry reads as "drop" — when the window is
    // too short to split at all, so the recursion always terminates.
    //
    // THE TERMINATOR SET IS DERIVED FROM THE RULES THEMSELVES, not asserted:
    //   - formBodyParamRegex and urlTokenParamRegex both have the value class [^&\s"'<>]+, so
    //     neither match can span an '&' or any whitespace character;
    //   - jsonSecretKeyRegex's value is either a '"'-delimited string or an unquoted scalar, and in
    //     well-formed JSON both are immediately followed by ',', '}' or ']'.
    // Cutting just after one of ',', '}', ']', '&' or whitespace therefore lands OUTSIDE any
    // built-in match for minified JSON and for form-encoded bodies, which is precisely the shape
    // CR-04 is about. splitPointPrefersASafeCutBoundaryInMinifiedJson is the guard.
    //
    // RESIDUAL, unchanged and already recorded: a USER custom pattern can still span the cut. There
    // is no principled bound on a user regex's match length, so no choice of cut position closes it.
    private fun safeCutPoint(
        window: String,
        mid: Int,
    ): Int {
        if (window.length <= 1) return 0
        // Never past window.length - 1, so the returned index is strictly inside the window and
        // dropOrRetry cannot read it as "cannot split" on either limb of its guard.
        val limit = minOf(mid + SAFE_CUT_SEARCH_CHARS, window.length - 1)
        var i = mid
        while (i < limit && !isSafeCutTerminator(window[i])) i++
        return if (i < limit) i + 1 else mid
    }

    // (PRIV-06) CR-04: true for a character no built-in body rule's match can span. See
    // [safeCutPoint] for the derivation from each rule's value class.
    private fun isSafeCutTerminator(c: Char): Boolean = c in SAFE_CUT_TERMINATORS || c.isWhitespace()

    // (PRIV-06) W-04 / T-21-52 — internal test seam: the WINDOWED BODY STAGE under an INJECTED
    // budget. NOT part of the public API; referenced only from the test source set, in the style of
    // resetTruncationWindowForTest, testRedactCookieSections and testSplitPoint.
    //
    // WHY IT EXISTS, with this round's evidence rather than a general appeal to flakiness. The
    // end-to-end path to the behaviour it carries - a newline-free body above the window width being
    // scanned in pieces instead of destroyed - spent 97-101 % of the shipped 2 s budget under the
    // former wall-clock per-rule bound (measured 2.19-2.35 s with the JaCoCo agent attached), and the
    // reviewer bisected the break point at roughly a 1 000 ms effective budget, i.e. a runner about
    // twice as slow as an M-series Mac. That is the ordinary speed of a GitHub-hosted runner for
    // single-threaded regex work. An assertion sitting on that margin is a RACE, not a proof, and a
    // security test that flakes invites the next contributor to disable it.
    //
    // BOTH CAUSES, and why both are now injected. That test went red for two reasons: the total
    // budget, and the per-rule bound against the size of the deepest piece dropOrRetry can produce
    // (fixture divided by 2^WINDOW_RETRY_MAX_DEPTH). The per-rule bound was a wall clock, so whether
    // the ladder engaged at all, and whether its pieces then scanned, depended on the machine. It is
    // now a deterministic access budget, and [accessBudget] injects it per piece length, so a test
    // forces exactly which ladder depths exhaust and which scan, identically on any hardware.
    //
    // WHAT IS INJECTED, because the distinction is the whole design:
    //   - the TOTAL budget. The mechanism under test is the WIRING - windowEnd making a
    //     newline-free body exactly one window, scanWindow exhausting on it, dropOrRetry reaching
    //     splitPoint, and the retry ladder producing pieces that do scan. None of that needs the
    //     total budget to be tight; a tight total budget only decides how much of the body is
    //     reached before the tail is dropped, which is a different property with its own tests.
    //   - the PER-RULE access budget, as a function of the piece length. The built-in rules never
    //     exhaust their shipped budget, so without this injection scanWindow would never call
    //     dropOrRetry and the ladder would go untested. It defaults to SafeRegex::accessBudgetFor.
    //
    // The deterministic ARITHMETIC half of CR-04 — splitPoint returning 0 on a newline-free window —
    // is asserted separately and hardware-independently by
    // splitPointCutsNewlineFreeWindowsInsteadOfRefusing. This seam covers the half that arithmetic
    // cannot: that the pieces are actually wired back through the rules and appended.
    //
    // Same reasoning, and the same answer, as the injected budget on testRedactCookieSections.
    internal fun testWindowedBodyStage(
        input: String,
        budgetMs: Long,
        accessBudget: (Int) -> Long = SafeRegex::accessBudgetFor,
    ): String = windowedScan(input, bodyRules(builtinsEnabled = true), budgetMs, accessBudget)

    // Internal test seam — [splitPoint] as the pure function it is. NOT part of the public API; only
    // referenced from the test source set, in the style of resetTruncationWindowForTest and
    // testRedactCookieSections above.
    //
    // It exists because the end-to-end path to splitPoint runs only once a rule has exhausted its
    // access budget, which the built-in rules never do, so it needs a pathological custom pattern or
    // an injected budget plus a multi-megabyte fixture. The
    // defect CR-04 records — splitPoint returning 0 on a newline-free window — is a pure function of
    // one string, so it can be asserted deterministically and identically on any hardware. Same
    // reasoning, and the same answer, as the injected budget on testRedactCookieSections.
    internal fun testSplitPoint(window: String): Int = splitPoint(window)

    // (PRIV-06) CR-02 / IN-03 / T-21-54 — internal test seam: [windowEnd] as the pure function it is.
    // NOT part of the public API; referenced only from the test source set, in the style of
    // testSplitPoint above.
    //
    // It exists for the same reason testSplitPoint does. Reaching MAX_JSON_BOUNDARY_LOOKAHEAD_LINES
    // through Redaction.apply needs a multi-megabyte fixture, slow to build and to scan, while the
    // property under test is not about scanning at all: WHERE THE LOOKAHEAD LOOP STOPS is a pure function of one string, three integers
    // and the cap, and it can be asserted identically on any hardware.
    //
    // The cap is the one part of the boundary machinery with no assertion on it. Its own comment
    // records reaching it as a deliberate residual, and this round WIDENED the predicate it bounds
    // (endsInsideOpenQuotedValue), so a change to either the cap or the continuation predicate would
    // move the boundary silently. Guarded by windowEndStopsAtTheJsonBoundaryLookaheadCap.
    //
    // READ-ONLY: this seam observes windowEnd and changes nothing about it. Plan 21-13 owns the three
    // predicates it consults.
    internal fun testWindowEnd(
        s: String,
        start: Int,
        width: Int,
    ): Int = windowEnd(s, start, width)

    // (PRIV-06) D-01 AMENDED: the end of the window starting at [start] — the index just past the
    // last newline at or before [start] + [width]. A single line longer than [width] becomes its own
    // oversized window rather than being split; the per-rule access budget, proportional to the
    // window, already bounds what that costs, and a mid-line cut is the only thing that can change a line-anchored rule's semantics.
    //
    // JSON boundary safety: jsonSecretKeyRegex can span newlines in TWO places — its whitespace
    // class between key and value (it matches a pretty-printed key/colon/value spread over four
    // lines), and its "[^"]*" value, since [^"] matches a newline too. Either way a pair split
    // exactly across a window boundary would be missed. When the last line of the prospective window
    // ends with a colon or a double quote after a trailing-whitespace strip, OR ends inside an
    // unterminated quoted string (isJsonPairBoundaryRisk / endsInsideOpenQuotedValue), following
    // lines are pulled in ONE AT A TIME, re-checking each newly included line, until a line that
    // cannot continue a pair is reached or MAX_JSON_BOUNDARY_LOOKAHEAD_LINES lines have been taken.
    //
    // CR-02 — the defect this loop replaces, recorded because the comment above it was already
    // correct and the code still did not follow it: the previous form pulled in exactly ONE line and
    // NEVER RE-CHECKED, so the "key on one line, colon on the next, value on the third" case this
    // very comment cites was unhandled. The boundary landed after the key line, the risk check
    // fired, the colon line was pulled in, and the window stopped there — leaving the value to start
    // the next window, where the rule could no longer match across the cut. The reviewer reproduced
    // a divergence at shift 7: the windowed path LEAKED a value the single-pass path redacts, which
    // is a redaction bypass keyed only on payload size. Response bodies are attacker-controlled and
    // window boundaries are deterministic given a known prefix length, so that alignment is
    // craftable. Guarded by windowedScanRedactsJsonPairAcrossEveryBoundaryAlignment, which sweeps a
    // full pad-line period rather than testing one alignment.
    //
    // The initial test and the loop test are deliberately DIFFERENT predicates, and the asymmetry is
    // the point. A blank line does NOT start an extension (isJsonPairBoundaryRisk): every window
    // that happens to end on a blank line would otherwise spend lookahead for nothing. A blank line
    // DOES continue one already in flight (isJsonPairBoundaryContinuation), because
    // "key" / ':' / blank / "value" is a shape jsonSecretKeyRegex's \s* genuinely matches — verified
    // against the real pattern — and it would otherwise still slip through even with the loop.
    //
    // formBodyParamRegex and urlTokenParamRegex cannot span newlines (their value classes exclude
    // \s) and need nothing.
    //
    // 21-REVIEW-2 CR-01 — the second shape, and why the loop alone was not enough. The loop above
    // fixed how FAR an extension runs; it did not fix WHEN one starts. A pair whose quoted value
    // carried a raw newline across the cut left the window's last line ending on an ordinary value
    // character, so no extension started at all and the cap was never reached. Reproduced at 6 of 40
    // alignments with dropMarker=false — a leak, not a drop — while the single-pass path redacted
    // the same bytes. Closed by widening the predicate rather than the bound; guarded by
    // windowedScanRedactsJsonPairWhoseValueStraddlesTheCut.
    //
    // ACCEPTED RESIDUAL: a CUSTOM pattern whose match straddles a window boundary can still be
    // missed. There is no principled bound on a user regex's match length, so no window scheme can
    // close this; it is recorded rather than pretended away. A built-in JSON pair spread over more
    // than MAX_JSON_BOUNDARY_LOOKAHEAD_LINES lines falls in the same category — narrowed by the
    // loop, not eliminated by it.
    @Suppress("ReturnCount")
    private fun windowEnd(
        s: String,
        start: Int,
        width: Int,
    ): Int {
        // Written this way rather than as start + width so the sum cannot overflow on a huge input.
        val hard = if (width >= s.length - start) s.length else start + width
        if (hard == s.length) return hard
        val lastNewline = s.lastIndexOf('\n', hard)
        if (lastNewline <= start) {
            // The line starting at [start] is longer than the window: keep that line whole.
            val next = s.indexOf('\n', start)
            return if (next < 0) s.length else next + 1
        }
        var end = lastNewline + 1
        // The line immediately BEFORE the prospective boundary. lineStart/lineEnd are carried
        // through the loop rather than recomputed with lastIndexOf, so each extension step is O(1)
        // in the window size and the whole lookahead stays linear in the lines it pulls.
        var lineStart = maxOf(start, s.lastIndexOf('\n', lastNewline - 1) + 1)
        var lineEnd = lastNewline
        // The INITIAL test looks BACKWARD (see pairMayBeInFlightAt); every line pulled in afterwards
        // is tested with the forward continuation predicate, which treats a blank line as risky.
        var risky = pairMayBeInFlightAt(s, start, lineStart, lineEnd)
        var pulled = 0
        while (risky && pulled < MAX_JSON_BOUNDARY_LOOKAHEAD_LINES) {
            val following = s.indexOf('\n', end)
            // No further newline exists, so there is no next line to pull: the remainder of the
            // input becomes this window rather than being cut inside a possible pair. Every byte is
            // still scanned, and scanWindow/dropOrRetry still fail closed if it will not scan in
            // time.
            if (following < 0) return s.length
            lineStart = end
            lineEnd = following
            end = following + 1
            pulled++
            risky = isJsonPairBoundaryContinuation(s.substring(lineStart, lineEnd))
        }
        // At the cap the window is line-aligned exactly as in every other branch; only the boundary
        // moved. See MAX_JSON_BOUNDARY_LOOKAHEAD_LINES for why stopping here is a recorded residual.
        return end
    }

    // (PRIV-06) CR-02: true when a jsonSecretKeyRegex pair may be IN FLIGHT at a window boundary
    // whose last line is [lineStart, lineEnd). This is the predicate that decides whether to START
    // an extension at all.
    //
    // It has to look BACKWARD, and that is not an embellishment — it was forced by a reproduction.
    // The boundary can land ON a blank line that is itself inside a pair, i.e.
    // "key" / ':' / blank / <cut> / "value". Testing only the immediately preceding line refuses to
    // extend there, because a blank line is deliberately not a risk on its own, so the very shape
    // the loop exists to catch would still be cut in half. That is exactly what
    // jsonPairWithBlankLineBetweenKeyAndValueIsRedacted reproduced at shift 0, with the forward loop
    // already in place.
    //
    // So: walk back over blank lines, bounded by the same cap that bounds the forward extension, and
    // let the nearest line that actually carries content decide. A blank run with nothing risky
    // behind it still starts nothing, which is the property the risk/continuation asymmetry existed
    // to protect — windows that merely happen to end on a blank line do not spend forward lookahead.
    private fun pairMayBeInFlightAt(
        s: String,
        start: Int,
        lineStart: Int,
        lineEnd: Int,
    ): Boolean {
        var probeStart = lineStart
        var probeEnd = lineEnd
        var lookedBack = 0
        var line = s.substring(probeStart, probeEnd)
        // Skip back over blank lines only. Stopping at [start] keeps this window's decision
        // independent of earlier windows, and the cap keeps a run of blank lines from turning a
        // boundary decision into an unbounded backward scan.
        while (line.isBlank() && probeStart > start && lookedBack < MAX_JSON_BOUNDARY_LOOKAHEAD_LINES) {
            probeEnd = probeStart - 1
            probeStart = maxOf(start, s.lastIndexOf('\n', probeEnd - 1) + 1)
            lookedBack++
            line = s.substring(probeStart, probeEnd)
        }
        // Whichever way the walk ended, the line in hand decides. If it is still blank — the run hit
        // [start] or the cap with nothing behind it — isJsonPairBoundaryRisk is false, so a blank
        // region on its own still starts no extension.
        return isJsonPairBoundaryRisk(line)
    }

    // (PRIV-06) CR-02 / 21-REVIEW-2 CR-01: true when [line] ends INSIDE an unterminated quoted
    // string. This is not a heuristic about punctuation; it is the second of the two states
    // jsonSecretKeyRegex can genuinely be in at a cut.
    //
    // The rule's value alternative is "[^"]*", and [^"] matches a NEWLINE. So a line carrying an odd
    // number of unescaped double quotes has left that value OPEN across the newline: the match is
    // still in flight even though the line ends with an ordinary value character rather than with
    // ':' or '"'. A backslash escapes whatever follows it, so the character after a '\' is skipped
    // and never counted as a quote — the same convention jsonSecretKeyRegex's own documented
    // escaped-quote limitation describes.
    //
    // This is exactly what the previous two-clause predicate could not see. It tested only the
    // whitespace AROUND THE COLON, so on a "key": "value-start / value-end" pair the risk check
    // returned false, no extension was ever started, and MAX_JSON_BOUNDARY_LOOKAHEAD_LINES was
    // irrelevant to the shape because the lookahead never began. That is why the cap was NOT the
    // residual it was recorded as, and why the leak survived a fix plus three mutations: it was a
    // missing STATE, not an insufficient bound. Reproduced over the compiled shipped classes at 6 of
    // 40 alignments of a 1 MB body with dropMarker=false — a leak, not a fail-closed drop — while
    // the single-pass control redacted the identical content.
    //
    // It costs one pass over a line already in hand: no parser, no dependency, and the hand-curated
    // regex constraint is untouched.
    private fun endsInsideOpenQuotedValue(line: String): Boolean {
        var quotes = 0
        var i = 0
        while (i < line.length) {
            when (line[i]) {
                '\\' -> i++ // the escaped character cannot be a value-terminating quote
                '"' -> quotes++
            }
            i++
        }
        return quotes % 2 == 1
    }

    // (PRIV-06) D-01: true when [line] ends where jsonSecretKeyRegex's match could still be in
    // flight — either in the newline-spanning whitespace class between a key and its value, or
    // inside the value's own quoted string. Content-only: a blank line is handled by
    // pairMayBeInFlightAt going backward and by isJsonPairBoundaryContinuation going forward.
    //
    // The third clause reads the UNTRIMMED line. Trailing whitespace cannot change a quote count, so
    // this is not a correctness difference; it keeps the two concerns separate — one clause is about
    // what the line ends WITH, the other about what state the line ends IN — and avoids a second
    // allocation. pairMayBeInFlightAt and isJsonPairBoundaryContinuation both delegate here, so both
    // inherit the widened predicate with no change of their own.
    private fun isJsonPairBoundaryRisk(line: String): Boolean {
        val trimmed = line.trimEnd()
        return trimmed.endsWith(":") || trimmed.endsWith("\"") || endsInsideOpenQuotedValue(line)
    }

    // (PRIV-06) CR-02: true when [line] can CONTINUE an extension that is already in flight. A
    // whitespace-only line qualifies: jsonSecretKeyRegex's \s* spans it, so "key" / ':' / blank /
    // "value" is one match, and a loop that stopped on the blank line would cut that shape in half
    // exactly as the pre-CR-02 single-line pull did. See windowEnd for why this is deliberately
    // wider than isJsonPairBoundaryRisk rather than the same predicate reused.
    private fun isJsonPairBoundaryContinuation(line: String): Boolean = line.isBlank() || isJsonPairBoundaryRisk(line)

    private val hostHeaderRegex = Regex("(?im)^host:\\s*([^\\s]+)\\s*$")

    // REL-02/SC5b: cap for the inner per-salt LRU maps. A few thousand entries (4096) is large
    // enough that a normal pentest session never evicts, but small enough to bound memory over
    // a long session (DoS mitigation). Forward/reverse eviction skew is benign: if forward evicts
    // host→anon but reverse still holds anon→host, de-anonymization still works (reverse is the
    // lookup path). Re-anonymizing an evicted host is deterministic (HKDF is pure, so the same
    // host+salt always produces the same anon value) and merely re-populates the forward entry.
    private const val HOST_MAP_CAP = 4096

    // Creates a bounded LRU map (synchronized, access-ordered LinkedHashMap with eldest-entry
    // eviction). Used for INNER per-salt maps only; the OUTER ConcurrentHashMap stays unbounded.
    private fun <K, V> boundedLru(maxEntries: Int): MutableMap<K, V> =
        java.util.Collections.synchronizedMap(
            // accessOrder = true (access-ordered LRU)
            object : LinkedHashMap<K, V>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: Map.Entry<K, V>): Boolean = size > maxEntries
            },
        )

    private val hostForwardMap = ConcurrentHashMap<String, MutableMap<String, String>>()
    private val hostReverseMap = ConcurrentHashMap<String, MutableMap<String, String>>()

    // HKDF constants (RFC 5869, https://www.rfc-editor.org/rfc/rfc5869).
    // App-specific context label binds the derivation to this use case (host anonymization).
    // L = 6 bytes → 12 hex chars, preserving the exact host-<12hex>.local output format.
    private const val HKDF_INFO = "burp-ai-agent:host"
    private const val HKDF_OKM_LEN = 6

    // RFC 5869 HMAC-SHA256 primitive.
    // If [key] is empty a single zero byte is substituted — SecretKeySpec rejects a 0-length key
    // (Pitfall 1: RFC 5869 allows an absent/all-zero salt but JCA requires >= 1 key byte).
    private fun hmacSha256(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val keySpec = SecretKeySpec(if (key.isEmpty()) ByteArray(1) else key, "HmacSHA256")
        mac.init(keySpec)
        return mac.doFinal(data)
    }

    // RFC 5869 HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
    private fun hkdfExtract(
        salt: ByteArray,
        ikm: ByteArray,
    ): ByteArray = hmacSha256(salt, ikm)

    // RFC 5869 HKDF-Expand: OKM = first [length] octets of T(1)|T(2)|...
    // T(i) = HMAC(PRK, T(i-1) | info | counter_byte), T(0) = empty.
    private fun hkdfExpand(
        prk: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    // Internal test seams — expose the HKDF helpers for RFC 5869 vector assertion in
    // RedactionTest.hkdfMatchesRfc5869Vector. NOT part of the public API; only referenced
    // from the test source set.
    internal fun testHkdfExtract(
        salt: ByteArray,
        ikm: ByteArray,
    ): ByteArray = hkdfExtract(salt, ikm)

    internal fun testHkdfExpand(
        prk: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray = hkdfExpand(prk, info, length)

    // Header regexes are recursive in the JDK matcher. Handing them a whole fat body
    // (CF challenge, checkout POST) overflows the thread stack. Windows stay under that depth.
    private const val HEADER_REGEX_WINDOW = 2_048

    private fun replaceBounded(
        input: String,
        regex: Regex,
        transform: (MatchResult) -> CharSequence,
    ): String {
        if (input.length <= HEADER_REGEX_WINDOW) return tryReplace(input, regex, transform)
        val sink = StringBuilder(input.length)
        var index = 0
        while (index < input.length) {
            val end = minOf(index + HEADER_REGEX_WINDOW, input.length)
            sink.append(tryReplace(input.substring(index, end), regex, transform))
            index = end
        }
        return sink.toString()
    }

    private fun tryReplace(
        input: String,
        regex: Regex,
        transform: (MatchResult) -> CharSequence,
    ): String =
        try {
            input.replace(regex, transform)
        } catch (_: StackOverflowError) {
            input
        }

    fun apply(
        raw: String,
        policy: RedactionPolicy,
        stableHostSalt: String,
        recordMapping: Boolean = true,
    ): String {
        return try {
            applyInner(raw, policy, stableHostSalt, recordMapping)
        } catch (_: StackOverflowError) {
            // Header-stage Regex.replace runs unbounded on the whole payload (see the note above
            // bodyStage). A fat body blows Java's recursive matcher before any timeout can fire,
            // and that Error used to kill the MCP history tool. Keep a short prefix so the tool
            // returns instead of dying.
            raw.take(2_000) + "\n[redaction skipped: regex stack overflow]"
        }
    }

    private fun applyInner(
        raw: String,
        policy: RedactionPolicy,
        stableHostSalt: String,
        recordMapping: Boolean,
    ): String {
        var out = raw

        if (policy.stripCookies) {
            // W-A: name-PRESERVING replacements, mirroring authHeaderRegex below. These were fixed
            // strings ("Cookie: [STRIPPED]"), which was harmless only while the match was pinned to
            // the two canonical names. Now that the match is name-contains-"cookie", a fixed string
            // would rewrite "X-Cookie: v" into "Cookie: [STRIPPED]" and silently rename a header in
            // the analyst's view of the traffic (T-21-WA2). "Cookie" and "Set-Cookie" still render
            // exactly as before — substringBefore(":") returns them unchanged — which is what keeps
            // RedactionTest.strictModeStripsCookiesTokensAndHosts and the BountyPromptTagResolver
            // assertion green WITHOUT edits.
            out =
                replaceBounded(out, cookieHeaderRegex) { m ->
                    val header = m.value.substringBefore(":")
                    "$header: [STRIPPED]"
                }
            out =
                replaceBounded(out, setCookieHeaderRegex) { m ->
                    val header = m.value.substringBefore(":")
                    "$header: [STRIPPED]"
                }
            // (PRIV-05) SC1: the passive scanner re-emits cookies as bare name=value lines in a
            // dedicated section, stripped of the prefix the two header rules above key on.
            out = redactCookieSections(out)
            // (PRIV-05) SC2: the same values leak a second time as typed parameter lines. Only the
            // value is replaced; the name and the trailing type label are written back verbatim.
            // Both rules run BEFORE the body stage and are idempotent under it — re-matching
            // NAME=[REDACTED] reproduces NAME=[REDACTED] — so no ordering hazard exists.
            out =
                replaceBounded(out, cookieTypedParamRegex) { m ->
                    // Destructured rather than groupValues[3]: detekt's MagicNumber rule ignores
                    // only -1/0/1/2, and a named binding reads better than a bare group index.
                    val (name, _, typeSuffix) = m.destructured
                    "$name=[REDACTED]$typeSuffix"
                }
        }

        if (policy.redactTokens) {
            out =
                replaceBounded(out, authHeaderRegex) { m ->
                    val header = m.value.substringBefore(":")
                    "$header: [REDACTED]"
                }
            out = replaceBounded(out, bearerRegex) { "Bearer [REDACTED]" }
            out = replaceBounded(out, basicAuthRegex) { "Basic [REDACTED]" }
            out = replaceBounded(out, jwtRegex) { "[JWT_REDACTED]" }
            out = replaceBounded(out, urlTokenParamRegex) { m ->
                m.groupValues[1] + "[REDACTED]"
            }
        }

        // (PRIV-06) D-01 AMENDED / D-02 / D-05: body-level redaction (form + JSON + custom
        // patterns), invoked UNCONDITIONALLY rather than from inside the redactTokens branch above.
        // The built-in body rules still follow policy.redactTokens, but the custom-pattern loop no
        // longer does — that move is the whole of D-05, and it is what lets a user's "never send
        // this, ever" list apply under PrivacyMode.OFF as well.
        //
        // The eight header-stage rules above deliberately stay OUTSIDE this budget: they run
        // unbounded on the full input exactly as they did before this phase. That is a pre-existing
        // condition outside D-01/D-02's scope, recorded rather than silently claimed as fixed.
        out = bodyStage(out, builtinsEnabled = policy.redactTokens)

        if (policy.anonymizeHosts) {
            out =
                replaceBounded(out, hostHeaderRegex) { m ->
                    val host = m.groupValues[1]
                    val anon = anonymizeHost(host, stableHostSalt, recordMapping)
                    "Host: $anon"
                }
        }

        return out
    }

    // Anonymizes [host] using RFC 5869 HKDF (HMAC-SHA256 extract-then-expand).
    // Signature and output format (host-<12hex>.local) are preserved from the previous
    // SHA-256 implementation so all ~10 call sites remain unchanged (Pitfall 6).
    // salt → HKDF extract salt; host → IKM (input keying material).
    fun anonymizeHost(
        host: String,
        salt: String,
        recordMapping: Boolean = true,
    ): String {
        val prk =
            hkdfExtract(
                salt.toByteArray(StandardCharsets.UTF_8),
                host.toByteArray(StandardCharsets.UTF_8),
            )
        val okm =
            hkdfExpand(
                prk,
                HKDF_INFO.toByteArray(StandardCharsets.UTF_8),
                HKDF_OKM_LEN,
            )
        val short = okm.joinToString("") { "%02x".format(it) } // 6 bytes → 12 hex chars
        val anon = "host-$short.local"
        if (recordMapping) {
            // REL-02/SC5b: inner map is bounded LRU (cap HOST_MAP_CAP); outer map + computeIfAbsent/
            // remove are unchanged so clearMappings() keeps working (Pitfall 5).
            hostForwardMap.computeIfAbsent(salt) { boundedLru(HOST_MAP_CAP) }[host] = anon
            hostReverseMap.computeIfAbsent(salt) { boundedLru(HOST_MAP_CAP) }[anon] = host
        }
        return anon
    }

    fun deAnonymizeHost(
        host: String,
        salt: String,
    ): String? = hostReverseMap[salt]?.get(host)

    fun clearMappings(salt: String? = null) {
        if (salt == null) {
            hostForwardMap.clear()
            hostReverseMap.clear()
            return
        }
        hostForwardMap.remove(salt)
        hostReverseMap.remove(salt)
    }
}
