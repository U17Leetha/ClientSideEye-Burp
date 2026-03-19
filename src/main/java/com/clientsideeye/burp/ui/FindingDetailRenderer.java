package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

final class FindingDetailRenderer {
    private FindingDetailRenderer() {
    }

    static String render(Finding finding, boolean falsePositive, String area) {
        FindHintBuilder.Result hintResult = FindHintBuilder.build(finding.evidence());

        StringBuilder out = new StringBuilder();
        out.append("Title: ").append(finding.title()).append('\n');
        out.append("Severity: ").append(finding.severity()).append(" (").append(finding.confidence()).append(")\n");
        out.append("False positive: ").append(falsePositive ? "yes" : "no").append('\n');
        out.append("Type: ").append(finding.type()).append('\n');
        out.append("Area: ").append(area).append('\n');
        out.append("Host: ").append(finding.host()).append('\n');
        out.append("URL: ").append(finding.url()).append('\n');
        out.append("First seen: ").append(finding.firstSeen()).append("\n\n");

        out.append("Evidence\n");
        out.append("--------\n");
        out.append(finding.evidence()).append("\n\n");

        out.append("Summary\n");
        out.append("-------\n");
        out.append(finding.summary()).append("\n\n");

        out.append(FindingTypeGuidance.guidanceText(finding, hintResult)).append("\n");

        out.append("Recommendation\n");
        out.append("--------------\n");
        out.append(finding.recommendation()).append('\n');
        return out.toString();
    }
}
