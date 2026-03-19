package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

final class FindingAreaResolver {
    private FindingAreaResolver() {
    }

    static String resolve(Finding finding) {
        if (finding == null) {
            return "general";
        }
        try {
            URI uri = new URI(finding.url());
            String path = uri.getPath();
            if (path != null && !path.isBlank() && !"/".equals(path)) {
                String[] parts = path.split("/");
                List<String> keep = new ArrayList<>();
                for (String part : parts) {
                    if (part == null || part.isBlank()) {
                        continue;
                    }
                    keep.add(part);
                    if (keep.size() == 2) {
                        break;
                    }
                }
                if (!keep.isEmpty()) {
                    return "/" + String.join("/", keep);
                }
            }
        } catch (Exception ignored) {
            // Fall back to identity/type-based grouping when the URL is malformed.
        }

        String identity = finding.identity() == null ? "" : finding.identity();
        if (!identity.isBlank()) {
            String[] parts = identity.split("\\|");
            for (String part : parts) {
                if (part == null || part.isBlank() || part.startsWith("http")) {
                    continue;
                }
                return part.length() > 40 ? part.substring(0, 40) : part;
            }
        }
        return finding.type().toLowerCase();
    }
}
