package com.six2dez.burp.aiagent.config

object Defaults {
    val DEFAULT_EXCLUDED_EXTENSIONS = setOf(
        "css", "jpg", "jpeg", "png", "gif", "svg", "ico",
        "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "mp3", "avi", "mov", "webm", "webp",
        "pdf", "zip", "gz", "tar", "rar", "7z",
        "map", "bmp", "tif", "tiff"
    )
    val DEFAULT_EXCLUDED_EXTENSIONS_CSV = DEFAULT_EXCLUDED_EXTENSIONS.joinToString(",")

    const val FINDINGS_BUFFER_SIZE = 50
    const val MAX_HISTORY_MESSAGES = 20
    const val MAX_HISTORY_TOTAL_CHARS = 40_000
    const val LARGE_PROMPT_THRESHOLD = 32_000
    const val CLI_PROCESS_TIMEOUT_SECONDS = 120
    const val PASSIVE_SCAN_TIMEOUT_MS = 90_000L
    const val HEALTH_CHECK_INTERVAL_MS = 2_000L
    const val BACKEND_STARTUP_DELAY_MS = 2_000L
    const val DEDUP_WINDOW_MS = 3_600_000L
    const val ACTIVE_SCAN_MAX_QUEUE_SIZE = 2_000
    const val MAX_CONTEXT_TOTAL_CHARS = 40_000
    const val OPENCODE_IDLE_TIMEOUT_MS = 30_000L
    const val CHAT_MAX_OUTPUT_TOKENS = 4096
    const val SCANNER_MAX_OUTPUT_TOKENS = 2048
    const val SCANNER_BATCH_MAX_OUTPUT_TOKENS = 4096
    const val PAYLOAD_MAX_OUTPUT_TOKENS = 1024
}
