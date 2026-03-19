package com.clientsideeye.burp.core;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.clientsideeye.burp.core.Finding.Severity;

final class HtmlControlAnalyzer {
    private static final String[] RISK_KEYWORDS = {
        "delete", "remove", "admin", "role", "permission", "privilege",
        "approve", "reject", "reset", "unlock", "disable", "enable",
        "export", "import", "service", "serviceaccount", "account",
        "sudo", "elevat", "impersonat", "grant", "revoke", "token", "key"
    };
    private static final String[] STATE_CHANGE_KEYWORDS = {
        "save", "submit", "update", "create", "add", "apply", "confirm"
    };

    private HtmlControlAnalyzer() {
    }

    static List<Finding> analyze(Document document, String url, String host) {
        List<Finding> findings = new ArrayList<>();
        addPasswordFindings(findings, document, url, host);
        addHiddenDisabledFindings(findings, document, url, host);
        return findings;
    }

    private static void addPasswordFindings(List<Finding> out, Document document, String url, String host) {
        for (Element input : document.select("input[type=password]")) {
            if (!input.hasAttr("value")) {
                continue;
            }

            String value = input.attr("value").trim();
            int confidence = 95;
            if (value.isEmpty()) {
                confidence = 70;
            }
            if (value.equalsIgnoreCase("password") || value.equalsIgnoreCase("********")) {
                confidence = 75;
            }

            out.add(new Finding(
                FindingType.PASSWORD_VALUE_IN_DOM.name(),
                Severity.HIGH,
                confidence,
                url,
                host,
                "Password value present in HTML",
                "An <input type=\"password\"> includes a value attribute in the HTML. Users can reveal it via DevTools or intercepting proxies.",
                HtmlAnalysisSupport.shrink(input.outerHtml(), 400),
                "Do not render secrets or passwords into client-side HTML. Populate credentials server-side only when needed, and never include password values in responses. Enforce server-side authorization and consider rotating exposed credentials.",
                HtmlAnalysisSupport.elementIdentity(input)
            ));
        }
    }

    private static void addHiddenDisabledFindings(List<Finding> out, Document document, String url, String host) {
        Elements controls = document.select("button,a,input,select,textarea,form,div,span,[role=button]");
        for (Element element : controls) {
            String tag = element.tagName().toLowerCase(Locale.ROOT);
            boolean hidden = hasHiddenSignal(element);
            boolean disabled = hasDisabledSignal(element);
            if (!hidden && !disabled) {
                continue;
            }
            if (isNonActionableInput(tag, element)) {
                continue;
            }

            ControlSignals signals = scoreControlSignals(element);
            if (!signals.actionable && ("div".equals(tag) || "span".equals(tag))) {
                continue;
            }

            out.add(buildControlFinding(element, url, host, hidden, disabled, signals));
        }
    }

    private static boolean isNonActionableInput(String tag, Element element) {
        if (!"input".equals(tag)) {
            return false;
        }
        String type = element.attr("type").toLowerCase(Locale.ROOT);
        return !(type.isBlank() || type.equals("submit") || type.equals("button") || type.equals("image") || type.equals("password") || type.equals("reset"));
    }

    private static Finding buildControlFinding(Element element, String url, String host, boolean hidden, boolean disabled, ControlSignals signals) {
        String state = (hidden ? "hidden" : "") + (hidden && disabled ? " & " : "") + (disabled ? "disabled" : "");
        String reasons = signals.reasons.isEmpty() ? "" : "Signals: " + String.join(", ", signals.reasons) + ".";
        String evidence = HtmlAnalysisSupport.shrink(element.outerHtml(), 420);
        String identity = HtmlAnalysisSupport.elementIdentity(element);

        if (signals.actionable) {
            return new Finding(
                FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
                severityForActionableHiddenControl(signals.confidence),
                signals.confidence,
                url,
                host,
                "Client-side " + state + " control likely to perform an action",
                "An interactive control is present in the HTML but is " + state + " on the client side and appears actionable. If server-side authorization is missing, users may be able to enable/trigger privileged actions. " + reasons,
                evidence,
                "Do not rely on client-side hiding/disabled states for authorization. Enforce authorization server-side for all actions. Prefer not rendering unauthorized controls at all (or render in a non-actionable form).",
                identity
            );
        }

        int informationalConfidence = Math.min(45, Math.max(15, signals.confidence));
        return new Finding(
            FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
            Severity.INFO,
            informationalConfidence,
            url,
            host,
            "Hidden/disabled control detected (informational)",
            "A control is present in the HTML but is " + state + " on the client side. It does not show clear signals of a state-changing action. " + reasons,
            evidence,
            "If this control maps to privileged actions, ensure authorization is enforced server-side. Otherwise, consider removing it from the DOM for unauthorized users.",
            identity
        );
    }

    private static boolean hasHiddenSignal(Element element) {
        Set<String> classes = HtmlAnalysisSupport.loweredClassNames(element);
        String style = element.attr("style").toLowerCase(Locale.ROOT);
        boolean a11yOnlyHidden = classes.contains("sr-only") || classes.contains("visually-hidden") || classes.contains("visuallyhidden");
        boolean visuallyHidden = style.contains("display:none") || style.contains("display: none")
            || style.contains("visibility:hidden") || style.contains("visibility: hidden")
            || style.contains("opacity:0") || style.contains("opacity: 0");
        boolean hiddenAttribute = element.hasAttr("hidden") || element.hasAttr("aria-hidden");
        boolean hiddenClass = classes.contains("hidden") || classes.contains("d-none");
        if (a11yOnlyHidden && !visuallyHidden && !hiddenAttribute) {
            return false;
        }
        return visuallyHidden || hiddenAttribute || hiddenClass;
    }

    private static boolean hasDisabledSignal(Element element) {
        Set<String> classes = HtmlAnalysisSupport.loweredClassNames(element);
        return element.hasAttr("disabled")
            || "true".equalsIgnoreCase(element.attr("aria-disabled"))
            || classes.contains("disabled")
            || classes.contains("pf-m-disabled")
            || classes.contains("is-disabled")
            || classes.contains("btn-disabled");
    }

    private static ControlSignals scoreControlSignals(Element element) {
        ControlSignals signals = new ControlSignals();
        int confidence = 10;
        int actionability = 0;
        String tag = element.tagName().toLowerCase(Locale.ROOT);
        String lowerHtml = element.outerHtml().toLowerCase(Locale.ROOT);
        String href = element.attr("href").toLowerCase(Locale.ROOT);

        if (element.hasAttr("onclick") || element.hasAttr("onmousedown") || element.hasAttr("onmouseup") || element.hasAttr("onchange")) {
            actionability += 30;
            signals.reasons.add("event handler");
        }
        if (element.hasAttr("formaction") || element.hasAttr("formmethod") || element.hasAttr("form")) {
            actionability += 30;
            signals.reasons.add("form action");
        }
        if ("submit".equalsIgnoreCase(element.attr("type"))) {
            actionability += 30;
            signals.reasons.add("submit");
        }
        if (hasDisabledSignal(element)) {
            actionability += 15;
            signals.reasons.add("client-side disabled gate");
        }
        if (!href.isBlank()) {
            if (href.startsWith("#") || href.startsWith("javascript:")) {
                actionability += 10;
                signals.reasons.add("href (weak)");
            } else {
                actionability += 25;
                signals.reasons.add("href");
            }
        }
        if (element.hasAttr("data-action") || element.hasAttr("data-url") || element.hasAttr("data-endpoint") || element.hasAttr("data-method")) {
            actionability += 20;
            signals.reasons.add("data-* action");
        }
        if ("button".equals(tag)) {
            actionability += 10;
        }
        if ("input".equals(tag)) {
            String type = element.attr("type").toLowerCase(Locale.ROOT);
            if (type.equals("button") || type.equals("submit") || type.equals("image") || type.equals("reset")) {
                actionability += 15;
            }
        }
        if ("button".equalsIgnoreCase(element.attr("role"))) {
            actionability += 10;
            signals.reasons.add("role=button");
        }
        if (element.hasAttr("tabindex")) {
            actionability += 5;
            signals.reasons.add("tabindex");
        }

        String idNameBlob = String.join(" ",
            element.id().toLowerCase(Locale.ROOT),
            element.attr("name").toLowerCase(Locale.ROOT),
            element.attr("value").toLowerCase(Locale.ROOT),
            element.attr("aria-label").toLowerCase(Locale.ROOT),
            element.attr("title").toLowerCase(Locale.ROOT),
            href,
            element.attr("data-action").toLowerCase(Locale.ROOT),
            element.attr("data-url").toLowerCase(Locale.ROOT),
            element.attr("data-endpoint").toLowerCase(Locale.ROOT),
            element.attr("data-testid").toLowerCase(Locale.ROOT),
            HtmlAnalysisSupport.ownText(element).toLowerCase(Locale.ROOT),
            lowerHtml
        );

        int keywordHits = 0;
        for (String keyword : RISK_KEYWORDS) {
            if (idNameBlob.contains(keyword)) {
                keywordHits++;
            }
        }
        if (keywordHits > 0) {
            confidence += Math.min(30, keywordHits * 8);
            actionability += Math.min(20, keywordHits * 12);
            signals.reasons.add("risky keyword(s)");
        }
        if (idNameBlob.contains("btn") || idNameBlob.contains("ctl00") || idNameBlob.contains("cphmain")) {
            confidence += 5;
            signals.reasons.add("webforms-ish id/name");
        }
        for (String keyword : STATE_CHANGE_KEYWORDS) {
            if (idNameBlob.contains(keyword)) {
                actionability += 10;
                signals.reasons.add("state-change label");
                break;
            }
        }

        signals.confidence = Math.max(0, Math.min(100, confidence + actionability));
        signals.actionable = actionability >= 60;
        return signals;
    }

    private static Severity severityForActionableHiddenControl(int confidence) {
        if (confidence >= 85) {
            return Severity.HIGH;
        }
        if (confidence >= 60) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    private static final class ControlSignals {
        private int confidence;
        private boolean actionable;
        private final List<String> reasons = new ArrayList<>();
    }
}
