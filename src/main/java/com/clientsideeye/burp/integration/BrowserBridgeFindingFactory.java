package com.clientsideeye.burp.integration;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;

import java.net.URI;
import java.util.Locale;
import java.util.Map;

final class BrowserBridgeFindingFactory {
    private BrowserBridgeFindingFactory() {
    }

    static Finding fromForm(Map<String, String> form) {
        String url = requiredValue(form.get("url"), "url is required");
        String type = normalizeType(form.get("type"));
        Finding.Severity severity = parseSeverity(form.get("severity"));
        int confidence = parseInt(form.get("confidence"), 55);
        String title = defaultIfBlank(form.get("title"), "Browser-reported client-side control finding");
        String summary = defaultIfBlank(
            form.get("summary"),
            "A browser extension submitted a client-side control signal for review."
        );
        String evidence = defaultIfBlank(form.get("evidence"), "(no evidence)");
        String recommendation = defaultIfBlank(
            form.get("recommendation"),
            "Validate server-side authorization for this action. Do not rely on client-side disabled/hidden states."
        );
        String identity = defaultIfBlank(form.get("identity"), type + "|" + Integer.toHexString(evidence.hashCode()));
        return new Finding(type, severity, confidence, url, hostFromUrl(url), title, summary, evidence, recommendation, identity);
    }

    private static String requiredValue(String value, String message) {
        String normalized = safe(value).trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return normalized;
    }

    static String normalizeType(String type) {
        String normalized = safe(type).trim();
        if (normalized.isBlank()) {
            return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
        }
        for (FindingType findingType : FindingType.values()) {
            if (findingType.name().equalsIgnoreCase(normalized)) {
                return findingType.name();
            }
        }
        return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
    }

    static Finding.Severity parseSeverity(String value) {
        String normalized = safe(value).trim().toUpperCase(Locale.ROOT);
        try {
            return Finding.Severity.valueOf(normalized);
        } catch (Exception ignored) {
            return Finding.Severity.MEDIUM;
        }
    }

    static int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(safe(value).trim());
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    static String defaultIfBlank(String value, String defaultValue) {
        String normalized = safe(value).trim();
        return normalized.isBlank() ? defaultValue : normalized;
    }

    static String safe(String value) {
        return value == null ? "" : value;
    }

    static String hostFromUrl(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? "" : uri.getHost();
        } catch (Exception ignored) {
            return "";
        }
    }
}
