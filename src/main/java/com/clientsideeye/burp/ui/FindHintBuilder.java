package com.clientsideeye.burp.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FindHintBuilder {
    private FindHintBuilder() {
    }

    static final class Result {
        final String bestSelector;
        final List<String> hints;
        final String highlightSnippet;
        final String revealSnippet;

        Result(String bestSelector, List<String> hints, String highlightSnippet, String revealSnippet) {
            this.bestSelector = bestSelector == null ? "" : bestSelector;
            this.hints = hints == null ? List.of() : hints;
            this.highlightSnippet = highlightSnippet == null ? "" : highlightSnippet;
            this.revealSnippet = revealSnippet == null ? "" : revealSnippet;
        }
    }

    static Result build(String evidence) {
        FindHintEvidence parsed = FindHintEvidence.from(evidence);
        List<SelectorHintBuilder.SelectorCandidate> selectors = SelectorHintBuilder.rankedSelectors(parsed);
        String bestSelector = selectors.isEmpty() ? "" : selectors.get(0).selector();
        List<String> hints = buildHints(evidence, parsed, selectors, bestSelector);
        return new Result(
            bestSelector,
            hints,
            FindHintSnippetBuilder.highlightSnippet(bestSelector, parsed),
            FindHintSnippetBuilder.revealSnippet(bestSelector, parsed)
        );
    }

    private static List<String> buildHints(
        String originalEvidence,
        FindHintEvidence evidence,
        List<SelectorHintBuilder.SelectorCandidate> selectors,
        String bestSelector
    ) {
        List<String> hints = new ArrayList<>();
        for (SelectorHintBuilder.SelectorCandidate candidate : selectors) {
            hints.add(candidate.label() + ": " + FindHintSnippetBuilder.locateSnippet(candidate.selector()));
        }
        if (!evidence.text.isBlank()) {
            hints.add("Locate by text (exact): " + FindHintSnippetBuilder.locateByTextSnippet(evidence));
        }
        if (!evidence.text.isBlank() || !bestSelector.isBlank()) {
            hints.add("Locate across iframes/shadow roots: " + FindHintSnippetBuilder.deepLocateSnippet(bestSelector, evidence));
        }
        hints.addAll(SelectorHintBuilder.inspectorHints(evidence, originalEvidence, bestSelector));
        return hints;
    }

    static String extractAttr(String text, String attr) {
        if (text == null) {
            return "";
        }
        Pattern pattern = Pattern.compile("(?i)\\b" + Pattern.quote(attr) + "\\s*=\\s*(?:([\"'])(.*?)\\1|([^\\s>]+))");
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            return "";
        }
        String quoted = matcher.group(2);
        if (quoted != null) {
            return quoted;
        }
        String unquoted = matcher.group(3);
        return unquoted == null ? "" : unquoted;
    }

    static String bestEvidenceSearchTerm(String evidence) {
        if (evidence == null) {
            return "";
        }
        String dataTestId = extractAttr(evidence, "data-testid");
        if (!dataTestId.isBlank()) {
            return "data-testid=\"" + dataTestId + "\"";
        }
        String href = extractAttr(evidence, "href");
        if (!href.isBlank()) {
            return "href=\"" + href + "\"";
        }
        String src = extractAttr(evidence, "src");
        if (!src.isBlank()) {
            return "src=\"" + src + "\"";
        }
        String action = extractAttr(evidence, "action");
        if (!action.isBlank()) {
            return "action=\"" + action + "\"";
        }
        String normalized = evidence.replaceAll("\\s+", " ").trim();
        return normalized.length() > 80 ? normalized.substring(0, 80) : normalized;
    }

    static String extractInnerText(String evidence) {
        if (evidence == null || evidence.isBlank()) {
            return "";
        }
        String normalized = evidence.replaceAll("(?is)<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        return normalized.length() > 80 ? normalized.substring(0, 80) : normalized;
    }

    static String jsSingleQuoteEscape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("'", "\\'");
    }

    static String jsDoubleQuoteEscape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static String cssEscape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
