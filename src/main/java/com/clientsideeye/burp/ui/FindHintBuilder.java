package com.clientsideeye.burp.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FindHintBuilder {

    private FindHintBuilder() {}

    static final class Result {
        final String bestSelector;
        final List<String> hints;
        final String revealSnippet;

        Result(String bestSelector, List<String> hints, String revealSnippet) {
            this.bestSelector = bestSelector == null ? "" : bestSelector;
            this.hints = hints == null ? List.of() : hints;
            this.revealSnippet = revealSnippet == null ? "" : revealSnippet;
        }
    }

    static Result build(String evidence) {
        String id = extractAttr(evidence, "id");
        String name = extractAttr(evidence, "name");
        String href = extractAttr(evidence, "href");
        String src = extractAttr(evidence, "src");
        String action = extractAttr(evidence, "action");
        String bestSelector = bestCssSelector(id, name, href, src, action);

        List<String> hints = new ArrayList<>();

        if (!bestSelector.isBlank()) {
            hints.add("Console (Chrome/Firefox): inspect(document.querySelector(\"" + bestSelector + "\"))");
            hints.add("Console (Chrome/Firefox): document.querySelector(\"" + bestSelector + "\")?.scrollIntoView({block:'center'})");
            hints.add("Elements/Inspector search (Chrome/Firefox): " + bestSelector);
        }

        if (!id.isBlank()) {
            hints.add("Inspector text: id=\"" + id + "\"");
        }

        if (!name.isBlank()) {
            hints.add("Inspector text: name=\"" + name + "\"");
        }

        if (!href.isBlank()) {
            hints.add("Inspector text: href=\"" + href + "\"");
        }

        String findTerm = bestEvidenceSearchTerm(evidence);
        if (!findTerm.isBlank()) {
            hints.add("Search term (markup): " + findTerm);
        }

        if (hints.isEmpty()) {
            hints.add("Search term (markup): " + (evidence == null ? "" : evidence.replaceAll("\\s+", " ").trim()));
        }

        String revealSelector = bestSelector.isBlank() ? "<selector>" : bestSelector;
        String revealSnippet =
                "const el = document.querySelector(\"" + revealSelector + "\");\n" +
                        "if (el) {\n" +
                        "  el.hidden = false;\n" +
                        "  el.removeAttribute('hidden');\n" +
                        "  el.style.display = '';\n" +
                        "  el.style.visibility = 'visible';\n" +
                        "  el.style.opacity = '1';\n" +
                        "  el.removeAttribute('aria-hidden');\n" +
                        "  if ('disabled' in el) el.disabled = false;\n" +
                        "  el.scrollIntoView({block:'center'});\n" +
                        "}\n";

        return new Result(bestSelector, hints, revealSnippet);
    }

    static String extractAttr(String text, String attr) {
        if (text == null) return "";
        Pattern p = Pattern.compile("(?i)\\b" + Pattern.quote(attr) + "\\s*=\\s*(?:([\"'])(.*?)\\1|([^\\s>]+))");
        Matcher m = p.matcher(text);
        if (m.find()) {
            String quoted = m.group(2);
            if (quoted != null) return quoted;
            String unquoted = m.group(3);
            return unquoted == null ? "" : unquoted;
        }
        return "";
    }

    static String bestEvidenceSearchTerm(String evidence) {
        if (evidence == null) return "";
        String href = extractAttr(evidence, "href");
        if (!href.isBlank()) return "href=\"" + href + "\"";

        String src = extractAttr(evidence, "src");
        if (!src.isBlank()) return "src=\"" + src + "\"";

        String action = extractAttr(evidence, "action");
        if (!action.isBlank()) return "action=\"" + action + "\"";

        String s = evidence.replaceAll("\\s+", " ").trim();
        if (s.length() > 80) s = s.substring(0, 80);
        return s;
    }

    static String bestCssSelector(String id, String name, String href, String src, String action) {
        if (id != null && !id.isBlank()) return "[id=\"" + cssEscape(id) + "\"]";
        if (name != null && !name.isBlank()) return "[name=\"" + cssEscape(name) + "\"]";
        if (href != null && !href.isBlank()) return "a[href=\"" + cssEscape(href) + "\"]";
        if (src != null && !src.isBlank()) return "[src=\"" + cssEscape(src) + "\"]";
        if (action != null && !action.isBlank()) return "form[action=\"" + cssEscape(action) + "\"]";
        return "";
    }

    static String cssEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
