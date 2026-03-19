package com.clientsideeye.burp.ui;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class SelectorHintBuilder {
    private SelectorHintBuilder() {
    }

    static List<SelectorCandidate> rankedSelectors(FindHintEvidence evidence) {
        Set<String> seen = new LinkedHashSet<>();
        List<SelectorCandidate> out = new ArrayList<>();
        addCandidate(out, seen, "Locate (high confidence: data-testid)", attrSelector("data-testid", evidence.dataTestId));
        addCandidate(out, seen, "Locate (high confidence: id)", attrSelector("id", evidence.id));
        addCandidate(out, seen, "Locate (high confidence: name)", attrSelector("name", evidence.name));
        addCandidate(out, seen, "Locate (fallback: aria-label)", attrSelector("aria-label", evidence.ariaLabel));
        if (!evidence.href.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: href)", "a[href=\"" + FindHintBuilder.cssEscape(evidence.href) + "\"]");
        }
        if (!evidence.action.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: form action)", "form[action=\"" + FindHintBuilder.cssEscape(evidence.action) + "\"]");
        }
        if (!evidence.src.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: src)", "[src=\"" + FindHintBuilder.cssEscape(evidence.src) + "\"]");
        }
        if (!evidence.type.isBlank()) {
            if (!evidence.value.isBlank()) {
                addCandidate(out, seen, "Locate (fallback: type + value)",
                    "input[type=\"" + FindHintBuilder.cssEscape(evidence.type) + "\"][value=\"" + FindHintBuilder.cssEscape(evidence.value) + "\"]");
            }
            addCandidate(out, seen, "Locate (fallback: type)",
                "button[type=\"" + FindHintBuilder.cssEscape(evidence.type) + "\"],input[type=\"" + FindHintBuilder.cssEscape(evidence.type) + "\"],select[type=\"" + FindHintBuilder.cssEscape(evidence.type) + "\"]");
        }
        if (!evidence.role.isBlank() && !evidence.text.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: role + text)", "[role=\"" + FindHintBuilder.cssEscape(evidence.role) + "\"]");
        }
        if (!evidence.text.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: button-ish text)", "button,a,[role=\"button\"],input[type=\"button\"],input[type=\"submit\"]");
            addCandidate(out, seen, "Locate (fallback: text anchor)", "*");
        }
        return out;
    }

    static List<String> inspectorHints(FindHintEvidence evidence, String originalEvidence, String bestSelector) {
        List<String> hints = new ArrayList<>();
        if (!bestSelector.isBlank()) {
            hints.add("Elements search (CSS): " + bestSelector);
        }
        if (!evidence.id.isBlank()) {
            hints.add("Inspector search text: id=\"" + evidence.id + "\"");
        }
        if (!evidence.dataTestId.isBlank()) {
            hints.add("Inspector search text: data-testid=\"" + evidence.dataTestId + "\"");
        }
        if (!evidence.name.isBlank()) {
            hints.add("Inspector search text: name=\"" + evidence.name + "\"");
        }
        if (!evidence.ariaLabel.isBlank()) {
            hints.add("Inspector search text: aria-label=\"" + evidence.ariaLabel + "\"");
        }
        if (!evidence.href.isBlank()) {
            hints.add("Inspector search text: href=\"" + evidence.href + "\"");
        }
        if (!evidence.text.isBlank()) {
            hints.add("Inspector search text: " + evidence.text);
        }
        String findTerm = FindHintBuilder.bestEvidenceSearchTerm(originalEvidence);
        if (!findTerm.isBlank()) {
            hints.add("Markup search term: " + findTerm);
        } else {
            hints.add("Markup search term: " + (originalEvidence == null ? "" : originalEvidence.replaceAll("\\s+", " ").trim()));
        }
        return hints;
    }

    private static String attrSelector(String attr, String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return "[" + attr + "=\"" + FindHintBuilder.cssEscape(value) + "\"]";
    }

    private static void addCandidate(List<SelectorCandidate> out, Set<String> seen, String label, String selector) {
        if (selector == null || selector.isBlank() || !seen.add(selector)) {
            return;
        }
        out.add(new SelectorCandidate(label, selector));
    }

    record SelectorCandidate(String label, String selector) {
    }
}
