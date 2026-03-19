package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;

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
            + "Evidence:\n" + finding.evidence() + "\n"
            + "\n"
            + "Summary:\n" + finding.summary() + "\n"
            + "\n"
            + "Recommendation:\n" + finding.recommendation() + "\n";
    }

    static String renderHtml(Finding finding, boolean falsePositive, String area) {
        FindHintBuilder.Result hintResult = FindHintBuilder.build(finding.evidence());
        boolean isDevtoolsFinding = FindingType.DEVTOOLS_BLOCKING.name().equals(finding.type());

        String devtoolsSection = """
            <div style="padding: 12px; border: 1px solid #d6cfc2; border-radius: 12px; background: #fffdf8;">
              <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px; color: #9a3412;">DevTools Usage</div>
              <div style="white-space: pre-wrap; line-height: 1.45; margin-bottom: 10px;">1. Paste a locate hint into the Console to find candidate nodes.
2. Paste the highlight snippet to visually confirm the target.
3. Paste the reveal / unhide snippet to re-enable or unhide the control when needed.</div>
              <div style="font-size: 12px; font-weight: 700; margin: 8px 0 4px;">Locate hint</div>
              <pre style="margin: 0 0 10px; white-space: pre-wrap; font-family: Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.4;">__LOCATE__</pre>
              <div style="font-size: 12px; font-weight: 700; margin: 8px 0 4px;">Highlight snippet</div>
              <pre style="margin: 0 0 10px; white-space: pre-wrap; font-family: Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.4;">__HIGHLIGHT__</pre>
              <div style="font-size: 12px; font-weight: 700; margin: 8px 0 4px;">Reveal / unhide snippet</div>
              <pre style="margin: 0; white-space: pre-wrap; font-family: Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.4;">__REVEAL__</pre>
              __BYPASS__
            </div>
            """
            .replace("__LOCATE__", escapeHtml(firstHintSnippet(hintResult)))
            .replace("__HIGHLIGHT__", escapeHtml(hintResult.highlightSnippet))
            .replace("__REVEAL__", escapeHtml(hintResult.revealSnippet))
            .replace("__BYPASS__", isDevtoolsFinding
                ? "<div style=\"font-size: 12px; font-weight: 700; margin: 8px 0 4px;\">DevTools bypass snippet</div><pre style=\"margin: 0; white-space: pre-wrap; font-family: Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.4;\">" + escapeHtml(DevtoolsBypassSnippets.script()) + "</pre>"
                : "");

        return """
            <html>
              <body style="font-family: SansSerif; padding: 10px; color: #1f2937; background: #fbf7ef;">
                <div style="display: grid; gap: 12px;">
                  <div style="padding: 12px; border: 1px solid #d6cfc2; border-radius: 12px; background: #fffdf8;">
                    <div style="font-size: 18px; font-weight: 700; margin-bottom: 8px;">__TITLE__</div>
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                      <tr><td style="font-weight: 700; width: 120px; padding: 3px 0;">Severity</td><td>__SEVERITY__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">Type</td><td>__TYPE__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">Area</td><td>__AREA__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">Host</td><td>__HOST__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">URL</td><td>__URL__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">First seen</td><td>__FIRST_SEEN__</td></tr>
                      <tr><td style="font-weight: 700; padding: 3px 0;">False positive</td><td>__FALSE_POSITIVE__</td></tr>
                    </table>
                  </div>
                  <div style="padding: 12px; border: 1px solid #d6cfc2; border-radius: 12px; background: #fffdf8;">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px; color: #9a3412;">Evidence</div>
                    <pre style="margin: 0; white-space: pre-wrap; font-family: Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.4;">__EVIDENCE__</pre>
                  </div>
                  __DEVTOOLS__
                  <div style="padding: 12px; border: 1px solid #d6cfc2; border-radius: 12px; background: #fffdf8;">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px; color: #9a3412;">Summary</div>
                    <div style="white-space: pre-wrap; line-height: 1.45;">__SUMMARY__</div>
                  </div>
                  <div style="padding: 12px; border: 1px solid #d6cfc2; border-radius: 12px; background: #fffdf8;">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px; color: #9a3412;">Recommendation</div>
                    <div style="white-space: pre-wrap; line-height: 1.45;">__RECOMMENDATION__</div>
                  </div>
                </div>
              </body>
            </html>
            """
            .replace("__TITLE__", escapeHtml(finding.title()))
            .replace("__SEVERITY__", escapeHtml(finding.severity() + " (" + finding.confidence() + ")"))
            .replace("__TYPE__", escapeHtml(finding.type()))
            .replace("__AREA__", escapeHtml(area))
            .replace("__HOST__", escapeHtml(finding.host()))
            .replace("__URL__", escapeHtml(finding.url()))
            .replace("__FIRST_SEEN__", escapeHtml(finding.firstSeen()))
            .replace("__FALSE_POSITIVE__", falsePositive ? "yes" : "no")
            .replace("__EVIDENCE__", escapeHtml(finding.evidence()))
            .replace("__DEVTOOLS__", devtoolsSection)
            .replace("__SUMMARY__", escapeHtml(finding.summary()))
            .replace("__RECOMMENDATION__", escapeHtml(finding.recommendation()));
    }

    private static String firstHintSnippet(FindHintBuilder.Result result) {
        if (result == null || result.hints == null || result.hints.isEmpty()) {
            return "";
        }
        String item = result.hints.get(0);
        int idx = item.indexOf(": ");
        return idx >= 0 && idx + 2 < item.length() ? item.substring(idx + 2) : item;
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }
}
