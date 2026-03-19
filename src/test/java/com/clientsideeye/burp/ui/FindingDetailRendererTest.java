package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import static com.clientsideeye.burp.core.Finding.Severity.HIGH;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingDetailRendererTest {
    @Test
    void rendersExpectedSections() {
        Finding finding = new Finding(
            "DOM_XSS_SINK",
            HIGH,
            90,
            "https://example.com/admin",
            "example.com",
            "Dangerous sink",
            "summary text",
            "evidence text",
            "recommendation text",
            "identity"
        );

        String rendered = FindingDetailRenderer.render(finding, true, "/admin");

        assertTrue(rendered.contains("Title: Dangerous sink"));
        assertTrue(rendered.contains("Severity: HIGH (90)"));
        assertTrue(rendered.contains("False positive: yes"));
        assertTrue(rendered.contains("Area: /admin"));
        assertTrue(rendered.contains("Evidence\n--------\nevidence text"));
        assertTrue(rendered.contains("Summary\n-------\nsummary text"));
        assertTrue(rendered.contains("DevTools Usage"));
        assertTrue(rendered.contains("Recommendation\n--------------\nrecommendation text"));
    }
}
