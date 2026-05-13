package com.six2dez.burp.aiagent.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CustomPromptLibraryJsonTest {
    private val f1 =
        CustomPromptDefinition(
            id = "f1",
            title = "Fav 1",
            promptText = "fav prompt 1",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = true,
        )
    private val f2 =
        CustomPromptDefinition(
            id = "f2",
            title = "Fav 2",
            promptText = "fav prompt 2",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = true,
        )
    private val f3 =
        CustomPromptDefinition(
            id = "f3",
            title = "Fav 3",
            promptText = "fav prompt 3",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = true,
        )
    private val n1 =
        CustomPromptDefinition(
            id = "n1",
            title = "Non 1",
            promptText = "non prompt 1",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = false,
        )
    private val n2 =
        CustomPromptDefinition(
            id = "n2",
            title = "Non 2",
            promptText = "non prompt 2",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = false,
        )
    private val n3 =
        CustomPromptDefinition(
            id = "n3",
            title = "Non 3",
            promptText = "non prompt 3",
            tags = setOf(CustomPromptTag.HTTP_SELECTION),
            isFavorite = false,
        )

    /** Generates the same pretty-printed JSON that handleExport writes to disk. */
    private val exportMapper =
        ObjectMapper()
            .registerKotlinModule()
            .enable(SerializationFeature.INDENT_OUTPUT)

    // ── GROUP 1: parseLibraryJson (PROM-03) ──────────────────────────────────

    @Test
    fun parseLibraryJsonParsesPrettyPrintedExport() {
        val entries = listOf(f1, n1)
        val json = exportMapper.writeValueAsString(entries)
        val parsed = CustomPromptDefinition.parseLibraryJson(json)
        assertEquals(entries, parsed)
    }

    @Test
    fun parseLibraryJsonReturnsEmptyOnMalformedInput() {
        assertEquals(emptyList<CustomPromptDefinition>(), CustomPromptDefinition.parseLibraryJson("not json"))
        assertEquals(emptyList<CustomPromptDefinition>(), CustomPromptDefinition.parseLibraryJson(""))
        assertEquals(emptyList<CustomPromptDefinition>(), CustomPromptDefinition.parseLibraryJson("   "))
    }

    // ── GROUP 2: mergeById (PROM-04) ─────────────────────────────────────────

    @Test
    fun mergeByIdReplacesMatchingIdsAndAppendsNewIds() {
        val existing = listOf(f1, f2, n1)
        val bPrime = f2.copy(title = "Fav 2 updated")
        val incoming = listOf(bPrime, n2)
        val result = CustomPromptDefinition.mergeById(existing, incoming)
        // f2 replaced in-place; n2 appended; f1 and n1 preserved.
        assertEquals(listOf(f1, bPrime, n1, n2), result)
    }

    @Test
    fun mergeByIdDeduplicatesInputUsingLastOccurrenceWins() {
        // Locks the INTENTIONAL BEHAVIOUR CHANGE: associateBy last-wins vs. prior distinctBy first-wins.
        val existing = listOf(f1, n1)
        val aPrime = f1.copy(title = "Fav 1 v2")
        val aDoublePrime = f1.copy(title = "Fav 1 v3")
        // incoming = [A', A'', C]; two entries with id "f1", then new id "n2".
        val incoming = listOf(aPrime, aDoublePrime, n2)
        val result = CustomPromptDefinition.mergeById(existing, incoming)
        // A'' (last occurrence) replaces f1; n1 preserved; n2 appended.
        assertEquals(listOf(aDoublePrime, n1, n2), result)
    }

    @Test
    fun mergeByIdWithEmptyExistingAppendsDedupedIncoming() {
        val aPrime = f1.copy(title = "Fav 1 v2")
        // incoming = [A, A', B]; two entries with id "f1".
        val incoming = listOf(f1, aPrime, n1)
        val result = CustomPromptDefinition.mergeById(emptyList(), incoming)
        // Dedup picks last A (aPrime); n1 appended.
        assertEquals(listOf(aPrime, n1), result)
    }

    // ── GROUP 3: applyMove (PROM-05) ─────────────────────────────────────────

    @Test
    fun applyMoveSwapsAdjacentEntriesWithinFavoritesGroup() {
        val library = listOf(f1, f2, f3, n1, n2, n3)
        val result = CustomPromptDefinition.applyMove(library, 0, 1)
        assertEquals(listOf(f2, f1, f3, n1, n2, n3), result)
    }

    @Test
    fun applyMoveSwapsAdjacentEntriesWithinNonFavoritesGroup() {
        val library = listOf(f1, f2, f3, n1, n2, n3)
        val result = CustomPromptDefinition.applyMove(library, 3, 1)
        assertEquals(listOf(f1, f2, f3, n2, n1, n3), result)
    }

    @Test
    fun applyMoveReturnsOriginalWhenLastFavoriteMovesDown() {
        val library = listOf(f1, f2, f3, n1, n2, n3)
        // f3 (last favorite, index 2) tries to move down to n1's position (index 3) — boundary cross.
        val result = CustomPromptDefinition.applyMove(library, 2, 1)
        assertEquals(library, result)
    }

    @Test
    fun applyMoveReturnsOriginalWhenFirstNonFavoriteMovesUp() {
        val library = listOf(f1, f2, f3, n1, n2, n3)
        // n1 (first non-favorite, index 3) tries to move up to f3's position (index 2) — boundary cross.
        val result = CustomPromptDefinition.applyMove(library, 3, -1)
        assertEquals(library, result)
    }

    @Test
    fun applyMoveReturnsOriginalWhenIndexOutOfBounds() {
        val library = listOf(f1, f2, f3, n1, n2, n3)
        // index 5 + delta 1 = 6, out of bounds (size is 6, valid indices 0-5).
        val result = CustomPromptDefinition.applyMove(library, 5, 1)
        assertEquals(library, result)
    }
}
