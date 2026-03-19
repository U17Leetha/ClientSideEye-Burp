package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import static com.clientsideeye.burp.core.Finding.Severity.MEDIUM;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingTypeGuidanceTest {
    @Test
    void domFindingUsesDomWorkflow() {
        Finding finding = new Finding(
            "HIDDEN_OR_DISABLED_CONTROL",
            MEDIUM,
            70,
            "https://example.com/app",
            "example.com",
            "Hidden control",
            "summary",
            "<button data-testid=\"save\" disabled>Save</button>",
            "recommendation",
            "identity"
        );

        assertTrue(FindingTypeGuidance.supportsDomWorkflows(finding));
        assertTrue(FindingTypeGuidance.guidanceText(finding, FindHintBuilder.build(finding.evidence())).contains("Reveal / unhide snippet"));
    }

    @Test
    void runtimeNetworkFindingUsesInvestigationWorkflow() {
        Finding finding = new Finding(
            "RUNTIME_NETWORK_REFERENCE",
            MEDIUM,
            82,
            "https://example.com/app",
            "example.com",
            "Runtime endpoint observed in browser",
            "summary",
            "xmlhttprequest -> https://example.com/graphql",
            "recommendation",
            "identity"
        );

        assertFalse(FindingTypeGuidance.supportsDomWorkflows(finding));
        String guidance = FindingTypeGuidance.guidanceText(finding, FindHintBuilder.build(finding.evidence()));
        assertTrue(guidance.contains("attack-surface discovery"));
        assertTrue(guidance.contains("Replay the request directly"));
    }
}
