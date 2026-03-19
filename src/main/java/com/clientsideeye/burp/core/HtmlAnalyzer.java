package com.clientsideeye.burp.core;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class HtmlAnalyzer {
    private HtmlAnalyzer() {
    }

    public static boolean looksLikeHtmlForAnalysis(String url, String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        String lowerUrl = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (lowerUrl.matches(".*\\.(map|js|mjs|css|json|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(\\?.*)?$")) {
            return false;
        }

        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            String lower = trimmed.toLowerCase(Locale.ROOT);
            if (lower.contains("\"version\"") && lower.contains("\"sources\"")) {
                return false;
            }
            if (lower.contains("\"openapi\"") || lower.contains("\"swagger\"")) {
                return false;
            }
        }

        String lower = trimmed.toLowerCase(Locale.ROOT);
        return lower.contains("<html")
            || lower.contains("<body")
            || lower.contains("<form")
            || lower.contains("<input")
            || lower.contains("<button")
            || lower.contains("<select")
            || lower.contains("<textarea")
            || lower.contains("<script")
            || lower.contains("<div")
            || lower.contains("<span");
    }

    public static List<Finding> analyzeHtml(String url, String html) {
        if (html == null || html.isBlank() || !looksLikeHtmlForAnalysis(url, html)) {
            return List.of();
        }

        Document document = Jsoup.parse(html, url);
        String host = HtmlAnalysisSupport.hostFromUrl(url);
        List<Finding> findings = new ArrayList<>();
        findings.addAll(HtmlControlAnalyzer.analyze(document, url, host));
        findings.addAll(HtmlMetadataAnalyzer.analyze(document, html, url, host));
        return findings;
    }
}
