package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.Finding.Severity;

import java.util.Locale;
import java.util.Set;

record FindingFilterState(
    String host,
    String search,
    boolean showHigh,
    boolean showMedium,
    boolean showLow,
    boolean showInfo,
    boolean showFalsePositives,
    Set<String> allowedTypes
) {
    boolean matches(Finding finding, boolean falsePositive, String area) {
        return matchesHost(finding)
            && matchesSearch(finding, area)
            && allowedTypes.contains(finding.type())
            && matchesSeverity(finding.severity())
            && (showFalsePositives || !falsePositive);
    }

    private boolean matchesHost(Finding finding) {
        return host.isEmpty() || finding.host().toLowerCase(Locale.ROOT).contains(host);
    }

    private boolean matchesSearch(Finding finding, String area) {
        return search.isEmpty()
            || finding.title().toLowerCase(Locale.ROOT).contains(search)
            || finding.url().toLowerCase(Locale.ROOT).contains(search)
            || finding.evidence().toLowerCase(Locale.ROOT).contains(search)
            || finding.identity().toLowerCase(Locale.ROOT).contains(search)
            || finding.type().toLowerCase(Locale.ROOT).contains(search)
            || area.toLowerCase(Locale.ROOT).contains(search);
    }

    private boolean matchesSeverity(Severity severity) {
        return switch (severity) {
            case HIGH -> showHigh;
            case MEDIUM -> showMedium;
            case LOW -> showLow;
            case INFO -> showInfo;
        };
    }
}
