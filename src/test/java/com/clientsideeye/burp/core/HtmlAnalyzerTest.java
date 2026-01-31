package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlAnalyzerTest {

    @Test
    void detectsPasswordValueRegardlessOfAttributeOrder() {
        String html = "<input value=secret123 type=password>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/login", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.PASSWORD_VALUE_IN_DOM.name())));
    }

    @Test
    void detectsHiddenDisabledControlsAcrossCommonTags() {
        String html = "<div role=\"button\" style=\"display:none\" onclick=\"doDelete()\">Delete</div>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/admin", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name())));
    }

    @Test
    void detectsRolePermissionHints() {
        String html = "<script>const role = 'admin';</script>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.ROLE_PERMISSION_HINT.name())));
    }

    @Test
    void detectsInlineScriptSecretishValues() {
        String html = "<script>const apiKey=\"ABCDEF1234567890ABCDEF1234567890\";</script>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.INLINE_SCRIPT_SECRETISH.name())));
    }

    @Test
    void detectsDevtoolsBlockingLogicInInlineScript() {
        String html = "<script>setInterval(function(){debugger;},1000); if(window.outerWidth-window.innerWidth>100){}</script>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.DEVTOOLS_BLOCKING.name())));
    }
}
