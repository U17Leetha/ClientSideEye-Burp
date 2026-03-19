package com.clientsideeye.burp.integration;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BrowserBridgeServerTest {
    @Test
    void rejectsMissingToken() {
        assertEquals(401, BrowserBridgeServer.validateFindingRequest("expected", "", 10));
    }

    @Test
    void rejectsOversizedBody() {
        assertEquals(413, BrowserBridgeServer.validateFindingRequest("expected", "expected", 70 * 1024));
    }

    @Test
    void acceptsAuthorizedBoundedRequest() {
        assertEquals(200, BrowserBridgeServer.validateFindingRequest("expected", "expected", 1024));
    }

    @Test
    void parsesFormEncodedValues() {
        Map<String, String> form = BrowserBridgeServer.parseFormEncodedForTest(
            "url=https%3A%2F%2Fexample.com%2Fapi&type=runtime_network_reference"
        );
        assertEquals("https://example.com/api", form.get("url"));
        assertEquals("runtime_network_reference", form.get("type"));
    }
}
