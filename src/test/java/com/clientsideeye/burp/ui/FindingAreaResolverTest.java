package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import org.junit.jupiter.api.Test;

import static com.clientsideeye.burp.core.Finding.Severity.MEDIUM;
import static org.junit.jupiter.api.Assertions.assertEquals;

class FindingAreaResolverTest {
    @Test
    void normalizesDynamicApiSegments() {
        Finding finding = finding(
            "RUNTIME_NETWORK_REFERENCE",
            "https://example.com/api/users/123456/orders/9f8d550c-67a4-4b46-9a88-d8cc77b1ceaa",
            "identity"
        );

        assertEquals("/api/users/:id", FindingAreaResolver.resolve(finding));
    }

    @Test
    void prefersEndpointFromIdentityWhenPresent() {
        Finding finding = finding(
            "JAVASCRIPT_ENDPOINT_REFERENCE",
            "https://example.com/app.js",
            "script|https://example.com/graphql/users/list|fetch"
        );

        assertEquals("/graphql/users/list", FindingAreaResolver.resolve(finding));
    }

    @Test
    void fallsBackToIdentityKeywordWhenUrlPathIsMissing() {
        Finding finding = finding(
            "POSTMESSAGE_HANDLER",
            "https://example.com",
            "listener|graphql operation|message"
        );

        assertEquals("/graphql", FindingAreaResolver.resolve(finding));
    }

    private static Finding finding(String type, String url, String identity) {
        return new Finding(type, MEDIUM, 70, url, "example.com", "title", "summary", "evidence", "recommendation", identity);
    }
}
