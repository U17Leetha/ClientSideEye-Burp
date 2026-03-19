package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import static com.clientsideeye.burp.core.Finding.Severity.HIGH;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingDetailRendererTest {
    @Test
    void rendersExpectedSectionsForDomFinding() {
        Finding finding = new Finding(
            "HIDDEN_OR_DISABLED_CONTROL",
            HIGH,
            90,
            "https://example.com/admin",
            "example.com",
            "Dangerous sink",
            "summary text",
            "<button data-testid=\"save\" disabled>Save</button>",
            "recommendation text",
            "identity"
        );

        String rendered = FindingDetailRenderer.render(finding, true, "/admin");

        assertTrue(rendered.contains("Title: Dangerous sink"));
        assertTrue(rendered.contains("Severity: HIGH (90)"));
        assertTrue(rendered.contains("False positive: yes"));
        assertTrue(rendered.contains("Area: /admin"));
        assertTrue(rendered.contains("Evidence\n--------\n<button data-testid=\"save\" disabled>Save</button>"));
        assertTrue(rendered.contains("Summary\n-------\nsummary text"));
        assertTrue(rendered.contains("DevTools Usage"));
        assertTrue(rendered.contains("Reveal / unhide snippet"));
        assertTrue(rendered.contains("Recommendation\n--------------\nrecommendation text"));
    }
}
