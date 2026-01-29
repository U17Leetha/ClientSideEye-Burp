package com.clientsideeye.burp.core;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.clientsideeye.burp.core.Finding.Severity;

public final class HtmlAnalyzer {

    private HtmlAnalyzer() {}

    // Heuristic keywords that often correlate with privileged actions
    private static final String[] RISK_KEYWORDS = new String[]{
            "delete", "remove", "admin", "role", "permission", "privilege",
            "approve", "reject", "reset", "unlock", "disable", "enable",
            "export", "import", "service", "serviceaccount", "account",
            "sudo", "elevat", "impersonat", "grant", "revoke", "token", "key"
    };

    // Capture small snippets for evidence; keep it readable and stable
    private static String shrink(String s, int max) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ").trim();
        if (s.length() <= max) return s;
        return s.substring(0, max) + "…";
    }

    private static String hostFromUrl(String url) {
        try {
            return URI.create(url).getHost() == null ? "" : URI.create(url).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    public static List<Finding> analyzeHtml(String url, String html) {
        if (html == null || html.isBlank()) return List.of();

        List<Finding> out = new ArrayList<>();
        String host = hostFromUrl(url);

        // 1) Password value in DOM (high risk)
        // Match: <input ... type="password" ... value="SOMETHING">
        Pattern pw = Pattern.compile(
                "(?is)<input\\b[^>]*\\btype\\s*=\\s*([\"'])password\\1[^>]*\\bvalue\\s*=\\s*([\"'])(.*?)\\2[^>]*>"
        );
        Matcher mPw = pw.matcher(html);
        while (mPw.find()) {
            String snippet = shrink(mPw.group(0), 400);

            // Confidence: very high if value is non-empty and not just placeholder-ish
            int conf = 95;
            String val = mPw.group(3) == null ? "" : mPw.group(3).trim();
            if (val.isEmpty()) conf = 70;
            if (val.equalsIgnoreCase("password") || val.equalsIgnoreCase("********")) conf = 75;

            out.add(new Finding(
                    FindingType.PASSWORD_VALUE_IN_DOM.name(),
                    Severity.HIGH,
                    conf,
                    url,
                    host,
                    "Password value present in HTML",
                    "An <input type=\"password\"> includes a value attribute in the HTML. Users can reveal it via DevTools or intercepting proxies.",
                    snippet,
                    "Do not render secrets or passwords into client-side HTML. Populate credentials server-side only when needed, and never include password values in responses. Enforce server-side authorization and consider rotating exposed credentials."
            ));
        }

        // 2) Hidden/disabled controls (elevate only if likely state-changing)
        // We look for common interactive elements that are hidden/disabled via attributes or inline styles.
        Pattern control = Pattern.compile(
                "(?is)<(button|a|input)\\b([^>]*)>"
        );
        Matcher mCtl = control.matcher(html);

        while (mCtl.find()) {
            String tag = mCtl.group(1).toLowerCase(Locale.ROOT);
            String attrs = mCtl.group(2) == null ? "" : mCtl.group(2);
            String full = mCtl.group(0);

            boolean isHidden = hasHiddenSignal(attrs, full);
            boolean isDisabled = hasDisabledSignal(attrs, full);

            if (!(isHidden || isDisabled)) continue;

            // For <input>, only care about the interactive ones
            if ("input".equals(tag)) {
                String type = extractAttr(attrs, "type").toLowerCase(Locale.ROOT);
                if (!(type.isBlank() || type.equals("submit") || type.equals("button") || type.equals("image") || type.equals("password") || type.equals("reset"))) {
                    continue;
                }
                // Password inputs handled above (value in DOM). Here we treat hidden/disabled password fields as controls too.
            }

            ControlSignals s = scoreControlSignals(tag, attrs, full);
            String why = s.reasons.isEmpty() ? "" : ("Signals: " + String.join(", ", s.reasons) + ".");
            String state = (isHidden ? "hidden" : "") + (isHidden && isDisabled ? " & " : "") + (isDisabled ? "disabled" : "");

            if (s.actionable) {
                Severity sev = severityForActionableHiddenControl(s.confidence);
                String title = "Client-side " + state + " control likely to perform an action";

                out.add(new Finding(
                        FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
                        sev,
                        s.confidence,
                        url,
                        host,
                        title,
                        "An interactive control is present in the HTML but is " + state + " on the client side and appears actionable. If server-side authorization is missing, users may be able to enable/trigger privileged actions. " + why,
                        shrink(full, 420),
                        "Do not rely on client-side hiding/disabled states for authorization. Enforce authorization server-side for all actions. Prefer not rendering unauthorized controls at all (or render in a non-actionable form)."
                ));
            } else {
                int infoConf = Math.min(45, Math.max(15, s.confidence));
                String title = "Hidden/disabled control detected (informational)";

                out.add(new Finding(
                        FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
                        Severity.INFO,
                        infoConf,
                        url,
                        host,
                        title,
                        "A control is present in the HTML but is " + state + " on the client side. It does not show clear signals of a state-changing action. " + why,
                        shrink(full, 420),
                        "If this control maps to privileged actions, ensure authorization is enforced server-side. Otherwise, consider removing it from the DOM for unauthorized users."
                ));
            }
        }

        // 3) Role/permission hints (mostly informational, sometimes useful)
        Pattern roleHint = Pattern.compile("(?is)\\b(role|permission|authorize|isadmin|is_admin|acl|rbac|privilege)\\b");
        Matcher mRole = roleHint.matcher(html);
        if (mRole.find()) {
            out.add(new Finding(
                    FindingType.ROLE_PERMISSION_HINT.name(),
                    Severity.INFO,
                    35,
                    url,
                    host,
                    "Role/permission hints found in HTML/JS",
                    "The page contains role/permission-related keywords. This may help locate authorization logic or UI gating, but is not necessarily a vulnerability on its own.",
                    "Matched keyword: " + mRole.group(1),
                    "Confirm all authorization decisions are enforced server-side. Avoid leaking internal role names or authorization flags to the client unless required."
            ));
        }

        // 4) Inline script “secret-ish” strings (low confidence by default)
        Pattern inlineScript = Pattern.compile("(?is)<script\\b[^>]*>(.*?)</script>");
        Matcher mJs = inlineScript.matcher(html);
        int secretishCount = 0;
        while (mJs.find() && secretishCount < 3) {
            String body = mJs.group(1);
            if (body == null) continue;
            if (looksSecretish(body)) {
                secretishCount++;
                out.add(new Finding(
                        FindingType.INLINE_SCRIPT_SECRETISH.name(),
                        Severity.LOW,
                        30,
                        url,
                        host,
                        "Potential secret-like value in inline script",
                        "The page contains inline script content that looks like it may include credentials/tokens/keys. This is heuristic and can generate false positives.",
                        shrink(body, 420),
                        "Avoid embedding secrets in client-side code. Use server-side sessions or retrieve short-lived tokens from protected endpoints with proper authorization."
                ));
            }
        }

        return out;
    }

    private static boolean hasHiddenSignal(String attrs, String fullTag) {
        String a = (attrs + " " + fullTag).toLowerCase(Locale.ROOT);
        return a.contains(" hidden")
                || a.contains("\thidden")
                || a.contains("hidden=")
                || a.matches(".*\\bhidden\\b.*")
                || a.contains("aria-hidden=\"true\"")
                || a.contains("aria-hidden='true'")
                || a.contains("class=\"hidden\"")
                || a.contains("class='hidden'")
                || a.contains("class=\"d-none\"")
                || a.contains("class='d-none'")
                || a.contains("class=\"sr-only\"")
                || a.contains("class='sr-only'")
                || a.contains("class=\"visually-hidden\"")
                || a.contains("class='visually-hidden'")
                || a.contains("display:none")
                || a.contains("display: none")
                || a.contains("visibility:hidden")
                || a.contains("visibility: hidden")
                || a.contains("opacity:0")
                || a.contains("opacity: 0");
    }

    private static boolean hasDisabledSignal(String attrs, String fullTag) {
        String a = (attrs + " " + fullTag).toLowerCase(Locale.ROOT);
        return a.contains(" disabled")
                || a.contains("\tdisabled")
                || a.contains("disabled=")
                || a.contains("aria-disabled=\"true\"")
                || a.contains("aria-disabled='true'");
    }

    private static String extractAttr(String attrs, String name) {
        Pattern p = Pattern.compile("(?is)\\b" + Pattern.quote(name) + "\\s*=\\s*([\"'])(.*?)\\1");
        Matcher m = p.matcher(attrs);
        if (m.find()) return m.group(2) == null ? "" : m.group(2).trim();
        return "";
    }

    private static class ControlSignals {
        int confidence;
        boolean actionable;
        List<String> reasons = new ArrayList<>();
    }

    private static ControlSignals scoreControlSignals(String tag, String attrs, String fullTag) {
        ControlSignals s = new ControlSignals();
        int conf = 10; // baseline "hidden/disabled control exists"
        int action = 0;

        String lower = (attrs + " " + fullTag).toLowerCase(Locale.ROOT);

        // Action signals (strong)
        if (lower.contains("onclick=") || lower.contains("onmousedown=") || lower.contains("onmouseup=") || lower.contains("onchange=")) {
            action += 30;
            s.reasons.add("event handler");
        }
        if (lower.contains("formaction=") || lower.contains("formmethod=") || lower.contains("form=")) {
            action += 30;
            s.reasons.add("form action");
        }
        if (lower.contains("type=\"submit\"") || lower.contains("type='submit'")) {
            action += 30;
            s.reasons.add("submit");
        }

        // Links and data-* endpoints
        String href = extractAttr(attrs, "href").toLowerCase(Locale.ROOT);
        if (!href.isBlank()) {
            if (href.startsWith("#") || href.startsWith("javascript:")) {
                action += 10;
                s.reasons.add("href (weak)");
            } else {
                action += 25;
                s.reasons.add("href");
            }
        }
        if (hasAnyAttr(attrs, "data-action", "data-url", "data-endpoint", "data-method")) {
            action += 20;
            s.reasons.add("data-* action");
        }

        // Tag-specific hints
        if ("button".equals(tag)) action += 10;
        if ("input".equals(tag)) {
            String type = extractAttr(attrs, "type").toLowerCase(Locale.ROOT);
            if (type.equals("button") || type.equals("submit") || type.equals("image") || type.equals("reset")) action += 15;
        }
        if (lower.contains("role=\"button\"") || lower.contains("role='button'")) {
            action += 10;
            s.reasons.add("role=button");
        }

        // Privileged keyword boost (narrowed to specific attrs)
        String id = extractAttr(attrs, "id").toLowerCase(Locale.ROOT);
        String name = extractAttr(attrs, "name").toLowerCase(Locale.ROOT);
        String value = extractAttr(attrs, "value").toLowerCase(Locale.ROOT);
        String ariaLabel = extractAttr(attrs, "aria-label").toLowerCase(Locale.ROOT);
        String title = extractAttr(attrs, "title").toLowerCase(Locale.ROOT);
        String dataAction = extractAttr(attrs, "data-action").toLowerCase(Locale.ROOT);
        String dataUrl = extractAttr(attrs, "data-url").toLowerCase(Locale.ROOT);
        String dataEndpoint = extractAttr(attrs, "data-endpoint").toLowerCase(Locale.ROOT);

        String idNameBlob = String.join(" ", id, name, value, ariaLabel, title, href, dataAction, dataUrl, dataEndpoint);

        int keywordHits = 0;
        for (String k : RISK_KEYWORDS) {
            if (idNameBlob.contains(k)) keywordHits++;
        }
        if (keywordHits > 0) {
            conf += Math.min(30, keywordHits * 8);
            s.reasons.add("risky keyword(s)");
        }

        // ASP.NET WebForms typical privileged buttons: ctl00...btnDelete, etc
        if (idNameBlob.contains("btn") || idNameBlob.contains("ctl00") || idNameBlob.contains("cphmain")) {
            conf += 5;
            s.reasons.add("webforms-ish id/name");
        }

        int combined = conf + action;
        s.confidence = Math.max(0, Math.min(100, combined));
        s.actionable = action >= 60;
        return s;
    }

    private static boolean hasAnyAttr(String attrs, String... names) {
        for (String n : names) {
            if (!extractAttr(attrs, n).isBlank()) return true;
        }
        return false;
    }

    private static Severity severityForActionableHiddenControl(int confidence) {
        if (confidence >= 85) return Severity.HIGH;
        if (confidence >= 60) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private static boolean looksSecretish(String scriptBody) {
        String s = scriptBody;
        if (s == null) return false;
        String lower = s.toLowerCase(Locale.ROOT);

        // very simple heuristics: tokens/keys/pass-like assignments
        if (lower.contains("apikey") || lower.contains("api_key") || lower.contains("secret") || lower.contains("token") || lower.contains("bearer")) return true;

        // long base64-ish / hex-ish strings
        Pattern longToken = Pattern.compile("(?i)\\b([a-z0-9+/]{30,}={0,2}|[a-f0-9]{32,})\\b");
        return longToken.matcher(s).find();
    }
}
