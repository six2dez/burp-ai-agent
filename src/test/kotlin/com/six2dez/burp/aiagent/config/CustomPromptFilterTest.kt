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

    @Test
    fun searchFilterEmptyQueryReturnsLibraryUnchanged() {
        val library = listOf(http, issue, dual)
        assertEquals(library, CustomPromptDefinition.searchFilter(library, ""))
        assertEquals(library, CustomPromptDefinition.searchFilter(library, "   "))
    }

    @Test
    fun searchFilterMatchesByTitleCaseInsensitive() {
        val library = listOf(http, issue, dual)
        val result = CustomPromptDefinition.searchFilter(library, "ONLY")
        assertEquals(listOf(http, issue), result)
    }

    @Test
    fun searchFilterMatchesByPromptTextSubstring() {
        val withTextHaystack =
            CustomPromptDefinition(
                id = "haystack",
                title = "Generic title",
                promptText = "find-the-needle inside this prompt",
                tags = setOf(CustomPromptTag.HTTP_SELECTION),
            )
        val library = listOf(http, issue, dual, withTextHaystack)
        // Substring lives only inside the prompt text; should match exactly one entry.
        val result = CustomPromptDefinition.searchFilter(library, "needle")
        assertEquals(listOf(withTextHaystack), result)
    }

    @Test
    fun searchFilterReturnsEmptyWhenNoMatch() {
        val library = listOf(http, issue, dual)
        assertEquals(emptyList<CustomPromptDefinition>(), CustomPromptDefinition.searchFilter(library, "nothing-here"))
    }

    @Test
    fun sortFavoritesFirstPreservesOrderWithinGroups() {
        val a = http.copy(id = "a", title = "A", isFavorite = false)
        val b = http.copy(id = "b", title = "B", isFavorite = true)
        val c = http.copy(id = "c", title = "C", isFavorite = false)
        val d = http.copy(id = "d", title = "D", isFavorite = true)
        val sorted = CustomPromptDefinition.sortFavoritesFirst(listOf(a, b, c, d))
        // Favorites in original order, then non-favorites in original order.
        assertEquals(listOf(b, d, a, c), sorted)
    }

    @Test
    fun sortFavoritesFirstNoFavoritesReturnsLibraryUnchanged() {
        val library = listOf(http, issue, dual)
        assertEquals(library, CustomPromptDefinition.sortFavoritesFirst(library))
    }

    @Test
    fun sortFavoritesFirstAllFavoritesReturnsLibraryUnchanged() {
        val library = listOf(http, issue, dual).map { it.copy(isFavorite = true) }
        assertEquals(library, CustomPromptDefinition.sortFavoritesFirst(library))
    }
}
