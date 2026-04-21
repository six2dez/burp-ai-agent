package com.six2dez.burp.aiagent.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CustomPromptFilterTest {
    private val http =
        CustomPromptDefinition(
            id = "1",
            title = "HTTP only",
            promptText = "a",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
        )
    private val issue =
        CustomPromptDefinition(
            id = "2",
            title = "Issue only",
            promptText = "b",
            tags = setOf(CustomPromptTag.SCANNER_ISSUE),
        )
    private val dual =
        CustomPromptDefinition(
            id = "3",
            title = "Both",
            promptText = "c",
            tags = setOf(CustomPromptTag.HTTP_SELECTION, CustomPromptTag.SCANNER_ISSUE),
        )
    private val hiddenHttp =
        CustomPromptDefinition(
            id = "4",
            title = "Hidden",
            promptText = "d",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            showInContextMenu = false,
        )

    @Test
    fun httpTagReturnsHttpAndDualOrdered() {
        val result =
            CustomPromptDefinition.filterForMenu(
                listOf(http, issue, dual, hiddenHttp),
                CustomPromptTag.HTTP_SELECTION,
            )
        assertEquals(listOf(http, dual), result)
    }

    @Test
    fun issueTagReturnsIssueAndDual() {
        val result =
            CustomPromptDefinition.filterForMenu(
                listOf(http, issue, dual, hiddenHttp),
                CustomPromptTag.SCANNER_ISSUE,
            )
        assertEquals(listOf(issue, dual), result)
    }

    @Test
    fun hiddenEntriesExcluded() {
        val result =
            CustomPromptDefinition.filterForMenu(
                listOf(hiddenHttp),
                CustomPromptTag.HTTP_SELECTION,
            )
        assertEquals(emptyList<CustomPromptDefinition>(), result)
    }

    @Test
    fun emptyLibraryReturnsEmpty() {
        val result = CustomPromptDefinition.filterForMenu(emptyList(), CustomPromptTag.HTTP_SELECTION)
        assertEquals(emptyList<CustomPromptDefinition>(), result)
    }

    @Test
    fun preservesLibraryOrder() {
        val ordered = listOf(dual, http, issue)
        val result = CustomPromptDefinition.filterForMenu(ordered, CustomPromptTag.HTTP_SELECTION)
        assertEquals(listOf(dual, http), result)
    }

    @Test
    fun invalidEntryFlaggedAsInvalid() {
        val bad = CustomPromptDefinition(id = "", title = "", promptText = "", tags = emptySet())
        assertEquals(false, bad.isValid())
    }

    @Test
    fun validEntryRecognizedAsValid() {
        assertEquals(true, http.isValid())
    }
}
