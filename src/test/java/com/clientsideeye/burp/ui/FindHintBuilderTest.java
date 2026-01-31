package com.clientsideeye.burp.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindHintBuilderTest {

    @Test
    void buildsSelectorHintsForId() {
        String evidence = "<button id=\"save\" disabled>Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("[id=\"save\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.contains("document.querySelector(\"[id=\\\"save\\\"]\")")));
        assertTrue(result.revealSnippet.contains("document.querySelector(\"[id=\\\"save\\\"]\")"));
    }

    @Test
    void parsesUnquotedHrefForSelector() {
        String evidence = "<a href=/admin/delete>Delete</a>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("a[href=\"/admin/delete\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.contains("Elements/Inspector search (Chrome/Firefox): a[href=\"/admin/delete\"]")));
    }
}
