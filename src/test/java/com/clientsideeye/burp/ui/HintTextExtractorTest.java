package com.clientsideeye.burp.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HintTextExtractorTest {
    @Test
    void extractsExecutableTextFromHintLabelWithNestedColon() {
        String item = "Locate (high confidence: data-testid): (() => { return 1; })()";

        assertEquals("(() => { return 1; })()", HintTextExtractor.extractExecutableText(item));
    }

    @Test
    void leavesPlainSnippetUntouched() {
        String item = "(() => document.querySelector('button'))()";

        assertEquals(item, HintTextExtractor.extractExecutableText(item));
    }
}
