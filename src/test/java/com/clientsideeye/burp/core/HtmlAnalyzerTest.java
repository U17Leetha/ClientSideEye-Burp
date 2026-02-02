package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
        String html = "<div role=\"admin\">Admin Section</div>";
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
    void ignoresA11yOnlyHiddenElements() {
        String html = "<span class=\"sr-only\">Hidden for a11y</span>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertFalse(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name())));
    }

    @Test
    void ignoresImportMapLikeScriptsForSecretish() {
        String html = "<script type=\"importmap\">{ \"imports\": { \"rfc4648\": \"/resources/rfc4648.js\" } }</script>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertFalse(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.INLINE_SCRIPT_SECRETISH.name())));
    }

    @Test
    void ignoresLongRandomStringsWithoutKeyword() {
        String html = "<script>const x = \"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD\";</script>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/app", html);
        assertFalse(findings.stream().anyMatch(f ->
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
