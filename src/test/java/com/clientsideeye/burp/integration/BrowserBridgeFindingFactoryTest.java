package com.clientsideeye.burp.integration;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BrowserBridgeFindingFactoryTest {
    @Test
    void buildsFindingFromForm() {
        Finding finding = BrowserBridgeFindingFactory.fromForm(Map.of(
            "url", "https://example.com/admin",
            "type", "runtime_network_reference",
            "severity", "high",
            "confidence", "91",
            "title", "Observed admin request",
            "summary", "Runtime hook saw an admin call",
            "evidence", "GET -> https://example.com/admin",
            "recommendation", "Review authorization",
            "identity", "runtime-hook|admin"
        ));

        assertEquals("RUNTIME_NETWORK_REFERENCE", finding.type());
        assertEquals(Finding.Severity.HIGH, finding.severity());
        assertEquals(91, finding.confidence());
        assertEquals("example.com", finding.host());
        assertEquals("runtime-hook|admin", finding.identity());
    }

    @Test
    void rejectsMissingUrl() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> BrowserBridgeFindingFactory.fromForm(Map.of())
        );
        assertEquals("url is required", error.getMessage());
    }
}
