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

    @Test
    void buildsSelectorFromDataTestIdAndRevealCanDropDisabledState() {
        String evidence = "<button data-testid=\"localization-tab-save\" aria-disabled=\"true\" class=\"pf-v5-c-button pf-m-primary pf-m-disabled\" disabled=\"\" type=\"submit\">Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("[data-testid=\"localization-tab-save\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.contains("document.querySelector(\"[data-testid=\\\"localization-tab-save\\\"]\")")));
        assertTrue(result.hints.stream().anyMatch(h ->
                h.contains("Inspector text: data-testid=\"localization-tab-save\"")));
        assertTrue(result.revealSnippet.contains("el.removeAttribute('aria-disabled')"));
        assertTrue(result.revealSnippet.contains("el.removeAttribute('disabled')"));
        assertTrue(result.revealSnippet.contains("el.classList.remove('pf-m-disabled'"));
    }
}
