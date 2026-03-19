package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

final class FindingAreaResolver {
    private static final Pattern NUMERIC_SEGMENT = Pattern.compile("^\\d{2,}$");
    private static final Pattern UUID_SEGMENT = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern LONG_HEX_SEGMENT = Pattern.compile("^[0-9a-f]{12,}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern HASHLIKE_SEGMENT = Pattern.compile("^[A-Za-z0-9_-]{16,}$");

    private FindingAreaResolver() {
    }

    static String resolve(Finding finding) {
        if (finding == null) {
            return "general";
        }

        String endpointArea = endpointAreaFromIdentity(finding.identity());
        if (!endpointArea.isBlank()) {
            return endpointArea;
        }

        String urlArea = areaFromUrl(finding.url());
        if (!urlArea.isBlank()) {
            return urlArea;
        }

        String identityArea = fallbackAreaFromIdentity(finding.identity());
        if (!identityArea.isBlank()) {
            return identityArea;
        }
        return finding.type().toLowerCase(Locale.ROOT);
    }

    private static String areaFromUrl(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(url);
            return normalizePath(uri.getPath());
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String endpointAreaFromIdentity(String identity) {
        if (identity == null || identity.isBlank()) {
            return "";
        }
        for (String part : identity.split("\\|")) {
            if (part == null || part.isBlank()) {
                continue;
            }
            String trimmed = part.trim();
            if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
                String area = areaFromUrl(trimmed);
                if (!area.isBlank()) {
                    return area;
                }
            }
            if (trimmed.startsWith("/")) {
                String area = normalizePath(trimmed);
                if (!area.isBlank()) {
                    return area;
                }
            }
        }
        return "";
    }

    private static String fallbackAreaFromIdentity(String identity) {
        if (identity == null || identity.isBlank()) {
            return "";
        }
        String bestFallback = "";
        for (String part : identity.split("\\|")) {
            if (part == null) {
                continue;
            }
            String trimmed = part.trim();
            if (trimmed.isBlank() || trimmed.startsWith("http") || trimmed.startsWith("/")) {
                continue;
            }
            String normalized = trimmed.toLowerCase(Locale.ROOT);
            if (normalized.contains("graphql")) {
                return "/graphql";
            }
            if (bestFallback.isBlank()) {
                if (normalized.length() > 48) {
                    normalized = normalized.substring(0, 48);
                }
                bestFallback = normalized;
            }
        }
        return bestFallback;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank() || "/".equals(path)) {
            return "";
        }
        String[] parts = path.split("/");
        List<String> keep = new ArrayList<>();
        int targetParts = pathStartsWithApiLikeSegment(parts) ? 3 : 2;
        for (String part : parts) {
            if (part == null || part.isBlank()) {
                continue;
            }
            keep.add(normalizeSegment(part));
            if (keep.size() == targetParts) {
                break;
            }
        }
        if (keep.isEmpty()) {
            return "";
        }
        return "/" + String.join("/", keep);
    }

    private static boolean pathStartsWithApiLikeSegment(String[] parts) {
        for (String part : parts) {
            if (part == null || part.isBlank()) {
                continue;
            }
            String lower = part.toLowerCase(Locale.ROOT);
            return lower.equals("api") || lower.equals("rest") || lower.equals("graphql") || lower.equals("auth") || lower.equals("v1") || lower.equals("v2");
        }
        return false;
    }

    private static String normalizeSegment(String segment) {
        String lower = segment.toLowerCase(Locale.ROOT);
        if (UUID_SEGMENT.matcher(lower).matches()) {
            return ":uuid";
        }
        if (NUMERIC_SEGMENT.matcher(lower).matches()) {
            return ":id";
        }
        if (LONG_HEX_SEGMENT.matcher(lower).matches()) {
            return ":hex";
        }
        if (HASHLIKE_SEGMENT.matcher(segment).matches()) {
            return ":token";
        }
        return lower;
    }
}
