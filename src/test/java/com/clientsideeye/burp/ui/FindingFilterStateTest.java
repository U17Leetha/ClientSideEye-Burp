package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static com.clientsideeye.burp.core.Finding.Severity.HIGH;
import static com.clientsideeye.burp.core.Finding.Severity.MEDIUM;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingFilterStateTest {
    @Test
    void matchesFindingWhenAllCriteriaPass() {
        FindingFilterState state = new FindingFilterState(
            "example.com",
            "admin",
            true,
            true,
            false,
            false,
            false,
            Set.of("RUNTIME_NETWORK_REFERENCE")
        );
        Finding finding = finding("RUNTIME_NETWORK_REFERENCE", HIGH, "https://example.com/admin", "admin request");

        assertTrue(state.matches(finding, false, "/admin"));
    }

    @Test
    void rejectsFalsePositivesWhenHidden() {
        FindingFilterState state = new FindingFilterState(
            "",
            "",
            true,
            true,
            true,
            true,
            false,
            Set.of("RUNTIME_NETWORK_REFERENCE")
        );

        assertFalse(state.matches(finding("RUNTIME_NETWORK_REFERENCE", MEDIUM, "https://example.com/api", "runtime"), true, "/api"));
    }

    @Test
    void rejectsWrongTypeAndSearch() {
        FindingFilterState state = new FindingFilterState(
            "example.com",
            "graphql",
            true,
            true,
            true,
            true,
            true,
            Set.of("POSTMESSAGE_HANDLER")
        );

        assertFalse(state.matches(finding("RUNTIME_NETWORK_REFERENCE", MEDIUM, "https://example.com/api", "runtime"), false, "/api"));
    }

    private static Finding finding(String type, com.clientsideeye.burp.core.Finding.Severity severity, String url, String title) {
        return new Finding(type, severity, 80, url, "example.com", title, "summary", "evidence", "recommendation", "identity");
    }
}
