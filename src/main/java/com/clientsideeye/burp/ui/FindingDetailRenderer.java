package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;

final class FindingDetailRenderer {
    private FindingDetailRenderer() {
    }

    static String render(Finding finding, boolean falsePositive, String area) {
        FindHintBuilder.Result hintResult = FindHintBuilder.build(finding.evidence());
        boolean isDevtoolsFinding = FindingType.DEVTOOLS_BLOCKING.name().equals(finding.type());

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

        out.append("DevTools Usage\n");
        out.append("-------------\n");
        out.append("1. Paste the locate hint into the browser Console to find candidate nodes.\n");
        out.append("2. Paste the highlight snippet to confirm the right target visually.\n");
        out.append("3. Paste the reveal / unhide snippet when you need to expose or re-enable the control.\n\n");
        out.append("Locate hint\n");
        out.append("~~~~~~~~~~~\n");
        out.append(firstHintSnippet(hintResult)).append("\n\n");
        out.append("Highlight snippet\n");
        out.append("~~~~~~~~~~~~~~~~~\n");
        out.append(hintResult.highlightSnippet).append("\n\n");
        out.append("Reveal / unhide snippet\n");
        out.append("~~~~~~~~~~~~~~~~~~~~~~~\n");
        out.append(hintResult.revealSnippet).append("\n\n");
        if (isDevtoolsFinding) {
            out.append("DevTools bypass snippet\n");
            out.append("~~~~~~~~~~~~~~~~~~~~~~\n");
            out.append(DevtoolsBypassSnippets.script()).append("\n\n");
        }

        out.append("Recommendation\n");
        out.append("--------------\n");
        out.append(finding.recommendation()).append('\n');
        return out.toString();
    }

    private static String firstHintSnippet(FindHintBuilder.Result result) {
        if (result == null || result.hints == null || result.hints.isEmpty()) {
            return "";
        }
        return HintTextExtractor.extractExecutableText(result.hints.get(0));
    }
}
