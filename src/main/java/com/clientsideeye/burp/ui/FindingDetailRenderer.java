package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

final class FindingDetailRenderer {
    private FindingDetailRenderer() {
    }

    static String render(Finding finding, boolean falsePositive, String area) {
        return ""
            + "Severity: " + finding.severity() + " (" + finding.confidence() + ")\n"
            + "False positive: " + (falsePositive ? "yes" : "no") + "\n"
            + "Type: " + finding.type() + "\n"
            + "Area: " + area + "\n"
            + "URL: " + finding.url() + "\n"
            + "Host: " + finding.host() + "\n"
            + "Title: " + finding.title() + "\n"
            + "First seen: " + finding.firstSeen() + "\n"
            + "\n"
            + "Summary:\n" + finding.summary() + "\n"
            + "\n"
            + "Evidence:\n" + finding.evidence() + "\n"
            + "\n"
            + "Recommendation:\n" + finding.recommendation() + "\n";
    }
}
