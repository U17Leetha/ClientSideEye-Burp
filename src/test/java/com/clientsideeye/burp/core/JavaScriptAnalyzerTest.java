package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JavaScriptAnalyzerTest {

    @Test
    void detectsEndpointReferences() {
        String js = "fetch('/api/admin/users'); axios.get('/graphql');";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name())));
    }

    @Test
    void detectsDomXssSinks() {
        String js = "element.innerHTML = location.hash; eval(payload);";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name())));
    }

    @Test
    void detectsPostMessageUsage() {
        String js = "window.addEventListener('message', function(event){ doThing(event.data); });";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.POSTMESSAGE_HANDLER.name())));
    }
}
