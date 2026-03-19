package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseAnalyzerTest {
    @Test
    void returnsNoFindingsForPlainText() {
        assertTrue(ResponseAnalyzer.analyze("https://example.com/readme.txt", "just text").isEmpty());
    }

    @Test
    void analyzesJavaScriptAssets() {
        assertFalse(ResponseAnalyzer.analyze(
            "https://example.com/app.js",
            "window.addEventListener('message', function(event) { console.log(event.origin); });"
        ).isEmpty());
    }
}
