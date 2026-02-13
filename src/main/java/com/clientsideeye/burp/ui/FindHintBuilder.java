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
        String dataTestId = extractAttr(evidence, "data-testid");
        String name = extractAttr(evidence, "name");
        String ariaLabel = extractAttr(evidence, "aria-label");
        String type = extractAttr(evidence, "type");
        String value = extractAttr(evidence, "value");
        String href = extractAttr(evidence, "href");
        String src = extractAttr(evidence, "src");
        String action = extractAttr(evidence, "action");
        String text = extractInnerText(evidence);
        String bestSelector = bestCssSelector(id, dataTestId, name, ariaLabel, type, value, href, src, action);

        List<String> hints = new ArrayList<>();

        if (!bestSelector.isBlank()) {
            hints.add("Console (Chrome/Firefox): inspect(document.querySelector(\"" + bestSelector + "\"))");
            hints.add("Console (Chrome/Firefox): document.querySelector(\"" + bestSelector + "\")?.scrollIntoView({block:'center'})");
            hints.add("Elements/Inspector search (Chrome/Firefox): " + bestSelector);
        }

        if (!id.isBlank()) {
            hints.add("Inspector text: id=\"" + id + "\"");
        }

        if (!dataTestId.isBlank()) {
            hints.add("Inspector text: data-testid=\"" + dataTestId + "\"");
        }

        if (!name.isBlank()) {
            hints.add("Inspector text: name=\"" + name + "\"");
        }

        if (!ariaLabel.isBlank()) {
            hints.add("Inspector text: aria-label=\"" + ariaLabel + "\"");
        }

        if (!href.isBlank()) {
            hints.add("Inspector text: href=\"" + href + "\"");
        }

        if (!text.isBlank()) {
            hints.add("Inspector text: " + text);
        }

        String findTerm = bestEvidenceSearchTerm(evidence);
        if (!findTerm.isBlank()) {
            hints.add("Search term (markup): " + findTerm);
        }

        if (hints.isEmpty()) {
            hints.add("Search term (markup): " + (evidence == null ? "" : evidence.replaceAll("\\s+", " ").trim()));
        }

        String revealSelector = bestSelector.isBlank() ? "<selector>" : bestSelector;
        String revealFallbackText = jsSingleQuoteEscape(text);
        String revealFallbackType = jsSingleQuoteEscape(type);
        String revealFallbackTestId = jsSingleQuoteEscape(dataTestId);
        String revealSnippet =
                "const targetSelector = \"" + revealSelector + "\";\n" +
                        "let el = targetSelector === \"<selector>\" ? null : document.querySelector(targetSelector);\n" +
                        "if (!el && '" + revealFallbackTestId + "') el = document.querySelector('[data-testid=\"" + cssEscape(dataTestId) + "\"]');\n" +
                        "if (!el && '" + revealFallbackText + "') {\n" +
                        "  const want = '" + revealFallbackText + "'.toLowerCase();\n" +
                        "  el = [...document.querySelectorAll('button,a,input,[role=\"button\"]')].find(n => ((n.innerText||n.textContent||n.value||'').trim().toLowerCase() === want));\n" +
                        "}\n" +
                        "if (!el && '" + revealFallbackType + "') {\n" +
                        "  el = document.querySelector('input[type=\"" + cssEscape(type) + "\"],button[type=\"" + cssEscape(type) + "\"]');\n" +
                        "}\n" +
                        "if (el) {\n" +
                        "  el.hidden = false;\n" +
                        "  el.removeAttribute('hidden');\n" +
                        "  el.removeAttribute('aria-hidden');\n" +
                        "  el.removeAttribute('aria-disabled');\n" +
                        "  if ('disabled' in el) el.disabled = false;\n" +
                        "  el.removeAttribute('disabled');\n" +
                        "  if (el.classList) {\n" +
                        "    el.classList.remove('pf-m-disabled','is-disabled','btn-disabled','disabled');\n" +
                        "  }\n" +
                        "  el.style.display = '';\n" +
                        "  el.style.visibility = 'visible';\n" +
                        "  el.style.opacity = '1';\n" +
                        "  el.style.pointerEvents = 'auto';\n" +
                        "  el.style.filter = '';\n" +
                        "  el.scrollIntoView({block:'center'});\n" +
                        "  console.log('[ClientSideEye] reveal target:', el);\n" +
                        "} else {\n" +
                        "  console.log('[ClientSideEye] reveal target not found. Try Elements search with data-testid/text hints.');\n" +
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
        String dataTestId = extractAttr(evidence, "data-testid");
        if (!dataTestId.isBlank()) return "data-testid=\"" + dataTestId + "\"";

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

    static String bestCssSelector(String id, String dataTestId, String name, String ariaLabel, String type, String value, String href, String src, String action) {
        if (id != null && !id.isBlank()) return "[id=\"" + cssEscape(id) + "\"]";
        if (dataTestId != null && !dataTestId.isBlank()) return "[data-testid=\"" + cssEscape(dataTestId) + "\"]";
        if (name != null && !name.isBlank()) return "[name=\"" + cssEscape(name) + "\"]";
        if (ariaLabel != null && !ariaLabel.isBlank()) return "[aria-label=\"" + cssEscape(ariaLabel) + "\"]";
        if (type != null && !type.isBlank()) {
            if (value != null && !value.isBlank()) return "input[type=\"" + cssEscape(type) + "\"][value=\"" + cssEscape(value) + "\"]";
            return "button[type=\"" + cssEscape(type) + "\"],input[type=\"" + cssEscape(type) + "\"]";
        }
        if (href != null && !href.isBlank()) return "a[href=\"" + cssEscape(href) + "\"]";
        if (src != null && !src.isBlank()) return "[src=\"" + cssEscape(src) + "\"]";
        if (action != null && !action.isBlank()) return "form[action=\"" + cssEscape(action) + "\"]";
        return "";
    }

    static String extractInnerText(String evidence) {
        if (evidence == null || evidence.isBlank()) return "";
        String s = evidence.replaceAll("(?is)<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        if (s.length() > 80) s = s.substring(0, 80);
        return s;
    }

    static String jsSingleQuoteEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'");
    }

    static String cssEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
