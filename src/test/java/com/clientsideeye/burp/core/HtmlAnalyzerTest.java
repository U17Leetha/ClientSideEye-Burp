package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
    void detectsDisabledSaveSubmitButtonAsActionable() {
        String html = "<button data-testid=\"localization-tab-save\" aria-disabled=\"true\" class=\"pf-v5-c-button pf-m-primary pf-m-disabled\" disabled=\"\" type=\"submit\">Save</button>";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/settings", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name())
                        && f.severity() != Finding.Severity.INFO
                        && f.confidence() >= 60));
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

    @Test
    void skipsSourcemapPayloadAsNonHtml() {
        String body = "{\"version\":3,\"sources\":[\"a.js\"],\"names\":[],\"mappings\":\"\"}";
        assertFalse(HtmlAnalyzer.looksLikeHtmlForAnalysis("https://example.test/assets/app.js.map", body));
    }

    @Test
    void parsesControlsInsideMalformedHtmlWithJsoup() {
        String html = "<div><button hidden onclick='go()'>Delete";
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/admin", html);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name())
                        && f.identity().contains("button")));
    }

    @Test
    void stableKeysDifferForDistinctControlsOnSamePage() {
        String html = """
                <button hidden data-testid="delete-user">Delete</button>
                <button hidden data-testid="delete-team">Delete</button>
                """;
        List<Finding> findings = HtmlAnalyzer.analyzeHtml("https://example.test/admin", html);
        Finding first = findings.stream()
                .filter(f -> f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name()))
                .findFirst()
                .orElseThrow();
        Finding second = findings.stream()
                .filter(f -> f.type().equals(FindingType.HIDDEN_OR_DISABLED_CONTROL.name()) && !f.identity().equals(first.identity()))
                .findFirst()
                .orElseThrow();
        assertNotEquals(first.stableKey(), second.stableKey());
    }
}
