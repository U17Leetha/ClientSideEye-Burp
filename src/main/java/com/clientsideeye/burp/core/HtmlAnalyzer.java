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
    private static final String[] STATE_CHANGE_KEYWORDS = new String[]{
            "save", "submit", "update", "create", "add", "apply", "confirm"
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
        // Match: any <input> with type="password" and a value attribute (order-agnostic)
        Pattern inputTag = Pattern.compile("(?is)<input\\b([^>]*)>");
        Matcher mInput = inputTag.matcher(html);
        while (mInput.find()) {
            String attrs = mInput.group(1) == null ? "" : mInput.group(1);
            String type = extractAttr(attrs, "type").toLowerCase(Locale.ROOT);
            if (!"password".equals(type)) continue;
            if (!hasAttrWithValue(attrs, "value")) continue;

            String snippet = shrink(mInput.group(0), 400);

            // Confidence: very high if value is non-empty and not just placeholder-ish
            int conf = 95;
            String val = extractAttr(attrs, "value");
            val = val == null ? "" : val.trim();
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
        // Strip script/style content to avoid false positives from inline JS/CSS.
        String scanHtml = stripScriptsAndStyles(html);
        Pattern control = Pattern.compile(
                "(?is)<(button|a|input|select|textarea|form|div|span)\\b([^>]*)>"
        );
        Matcher mCtl = control.matcher(scanHtml);

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
            if (!s.actionable && ("div".equals(tag) || "span".equals(tag))) {
                continue; // reduce noise from non-actionable containers
            }
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
        Pattern roleHint = Pattern.compile(
                "(?is)\\b(permission|authorize|isadmin|is_admin|acl|rbac|privilege)\\b|\\brole\\s*[:=]\\s*['\"]?(admin|superuser|owner|manager|privileged|staff)\\b"
        );
        Matcher mRole = roleHint.matcher(scanHtml);
        if (mRole.find()) {
            String matched = mRole.group(1) != null ? mRole.group(1) : mRole.group(2);
            out.add(new Finding(
                    FindingType.ROLE_PERMISSION_HINT.name(),
                    Severity.INFO,
                    35,
                    url,
                    host,
                    "Role/permission hints found in HTML/JS",
                    "The page contains role/permission-related keywords. This may help locate authorization logic or UI gating, but is not necessarily a vulnerability on its own.",
                    "Matched keyword: " + matched,
                    "Confirm all authorization decisions are enforced server-side. Avoid leaking internal role names or authorization flags to the client unless required."
            ));
        }

        // 4) Inline script “secret-ish” strings (low confidence by default)
        Pattern inlineScript = Pattern.compile("(?is)<script\\b[^>]*>(.*?)</script>");
        Matcher mJs = inlineScript.matcher(html);
        List<ScriptCandidate> secretishCandidates = new ArrayList<>();
        List<ScriptCandidate> devtoolsCandidates = new ArrayList<>();
        while (mJs.find()) {
            String body = mJs.group(1);
            if (body == null) continue;
            if (looksSecretish(body)) {
                secretishCandidates.add(new ScriptCandidate(30, body));
            }

            DevtoolsSignals d = scoreDevtoolsSignals(body);
            if (d.confidence >= 40) {
                devtoolsCandidates.add(new ScriptCandidate(d.confidence, body));
            }
        }

        addSecretishFindings(out, secretishCandidates, url, host);
        addDevtoolsFindings(out, devtoolsCandidates, url, host);

        // 5) DevTools detection hints in HTML (very low confidence)
        if (devtoolsCandidates.isEmpty() && looksDevtoolsHint(html)) {
            out.add(new Finding(
                    FindingType.DEVTOOLS_BLOCKING.name(),
                    Severity.INFO,
                    30,
                    url,
                    host,
                    "DevTools-related hint found in HTML",
                    "The page contains DevTools-related keywords. This may indicate client-side detection or blocking logic elsewhere (e.g., external scripts).",
                    shrink(html, 240),
                    "If DevTools access is blocked and testing is authorized, look for client-side detection in scripts and consider a controlled bypass snippet."
            ));
        }

        return out;
    }

    private static boolean hasHiddenSignal(String attrs, String fullTag) {
        String a = (attrs + " " + fullTag).toLowerCase(Locale.ROOT);
        if (hasA11yHiddenClass(a)) {
            // If it is only a11y-hidden (sr-only/visually-hidden), do not flag as hidden.
            if (!hasVisualHiddenSignal(a) && !hasHiddenAttribute(a)) return false;
        }

        return hasHiddenAttribute(a)
                || hasVisualHiddenSignal(a)
                || a.contains("class=\"hidden\"")
                || a.contains("class='hidden'")
                || a.contains("class=hidden")
                || a.contains("class=\"d-none\"")
                || a.contains("class='d-none'");
    }

    private static boolean hasDisabledSignal(String attrs, String fullTag) {
        String a = (attrs + " " + fullTag).toLowerCase(Locale.ROOT);
        return a.contains(" disabled")
                || a.contains("\tdisabled")
                || a.contains("disabled=")
                || a.contains("aria-disabled=\"true\"")
                || a.contains("aria-disabled='true'")
                || hasDisabledClassSignal(a);
    }

    private static boolean hasHiddenAttribute(String lowerAttrs) {
        return lowerAttrs.contains(" hidden")
                || lowerAttrs.contains("\thidden")
                || lowerAttrs.contains("hidden=");
    }

    private static boolean hasVisualHiddenSignal(String lowerAttrs) {
        return lowerAttrs.contains("display:none")
                || lowerAttrs.contains("display: none")
                || lowerAttrs.contains("visibility:hidden")
                || lowerAttrs.contains("visibility: hidden")
                || lowerAttrs.contains("opacity:0")
                || lowerAttrs.contains("opacity: 0");
    }

    private static boolean hasA11yHiddenClass(String lowerAttrs) {
        return lowerAttrs.contains("sr-only")
                || lowerAttrs.contains("visually-hidden")
                || lowerAttrs.contains("visuallyhidden");
    }

    private static boolean hasDisabledClassSignal(String lowerAttrs) {
        return hasClassToken(lowerAttrs, "disabled")
                || hasClassToken(lowerAttrs, "pf-m-disabled")
                || hasClassToken(lowerAttrs, "is-disabled")
                || hasClassToken(lowerAttrs, "btn-disabled");
    }

    private static boolean hasClassToken(String text, String token) {
        if (text == null || text.isBlank() || token == null || token.isBlank()) return false;
        Pattern p = Pattern.compile("(?is)\\bclass\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
        Matcher m = p.matcher(text);
        while (m.find()) {
            String cls = m.group(1) != null ? m.group(1) : (m.group(2) != null ? m.group(2) : m.group(3));
            if (cls == null || cls.isBlank()) continue;
            for (String c : cls.toLowerCase(Locale.ROOT).split("\\s+")) {
                if (token.equals(c)) return true;
            }
        }
        return false;
    }

    private static String extractAttr(String attrs, String name) {
        Pattern p = Pattern.compile("(?is)\\b" + Pattern.quote(name) + "\\s*=\\s*(?:([\"'])(.*?)\\1|([^\\s>]+))");
        Matcher m = p.matcher(attrs);
        if (m.find()) {
            String quoted = m.group(2);
            if (quoted != null) return quoted.trim();
            String unquoted = m.group(3);
            return unquoted == null ? "" : unquoted.trim();
        }
        return "";
    }

    private static boolean hasAttrWithValue(String attrs, String name) {
        Pattern p = Pattern.compile("(?is)\\b" + Pattern.quote(name) + "\\s*=");
        return p.matcher(attrs).find();
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
        if (lower.contains(" disabled")
                || lower.contains("\tdisabled")
                || lower.contains("disabled=")
                || lower.contains("aria-disabled=\"true\"")
                || lower.contains("aria-disabled='true'")
                || hasDisabledClassSignal(lower)) {
            action += 15;
            s.reasons.add("client-side disabled gate");
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
        if (hasAttrWithValue(attrs, "tabindex")) {
            action += 5;
            s.reasons.add("tabindex");
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
        String dataTestId = extractAttr(attrs, "data-testid").toLowerCase(Locale.ROOT);

        String idNameBlob = String.join(" ", id, name, value, ariaLabel, title, href, dataAction, dataUrl, dataEndpoint, dataTestId);

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
        for (String k : STATE_CHANGE_KEYWORDS) {
            if (idNameBlob.contains(k)) {
                action += 10;
                s.reasons.add("state-change label");
                break;
            }
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
        // Prefer real secret-like assignments with sufficient length
        Pattern secretAssign = Pattern.compile("(?i)\\b(api[_-]?key|secret|bearer|token)\\b\\s*[:=]\\s*['\\\"][^'\\\"]{20,}['\\\"]");
        if (secretAssign.matcher(s).find()) return true;

        // JWTs or long base64/hex-like strings
        if (s.contains("eyJ") && s.contains(".")) return true;
        Pattern tokenNearKeyword = Pattern.compile("(?is)\\b(api[_-]?key|secret|bearer|token|authorization)\\b.{0,80}?([a-z0-9+/]{30,}={0,2}|[a-f0-9]{32,})");
        return tokenNearKeyword.matcher(s).find();
    }

    private static String stripScriptsAndStyles(String html) {
        if (html == null || html.isEmpty()) return "";
        String withoutScripts = html.replaceAll("(?is)<script\\b[^>]*>.*?</script>", " ");
        return withoutScripts.replaceAll("(?is)<style\\b[^>]*>.*?</style>", " ");
    }

    private static class ScriptCandidate {
        final int confidence;
        final String body;

        ScriptCandidate(int confidence, String body) {
            this.confidence = confidence;
            this.body = body == null ? "" : body;
        }
    }

    private static void addSecretishFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        if (candidates == null || candidates.isEmpty()) return;
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate c : candidates) {
            String snippet = shrink(c.body, 420);
            if (!seen.add(snippet)) continue;
            out.add(new Finding(
                    FindingType.INLINE_SCRIPT_SECRETISH.name(),
                    Severity.LOW,
                    30,
                    url,
                    host,
                    "Potential secret-like value in inline script",
                    "The page contains inline script content that looks like it may include credentials/tokens/keys. This is heuristic and can generate false positives.",
                    snippet,
                    "Avoid embedding secrets in client-side code. Use server-side sessions or retrieve short-lived tokens from protected endpoints with proper authorization."
            ));
        }
    }

    private static void addDevtoolsFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        if (candidates == null || candidates.isEmpty()) return;
        candidates.sort((a, b) -> Integer.compare(b.confidence, a.confidence));
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate c : candidates) {
            String snippet = shrink(c.body, 420);
            if (!seen.add(snippet)) continue;
            Severity sev = c.confidence >= 65 ? Severity.MEDIUM : Severity.LOW;
            out.add(new Finding(
                    FindingType.DEVTOOLS_BLOCKING.name(),
                    sev,
                    c.confidence,
                    url,
                    host,
                    "Possible DevTools blocking or detection logic in client-side script",
                    "The page includes script patterns commonly used to detect or disrupt DevTools usage (e.g., debugger statements, window size checks, or devtools keywords). This can interfere with client-side enumeration and validation.",
                    snippet,
                    "If this behavior is authorized to bypass, use a controlled DevTools bypass snippet to neutralize common detection hooks. Ensure testing remains in-scope and approved."
            ));
        }
    }

    private static class DevtoolsSignals {
        int confidence;
    }

    private static DevtoolsSignals scoreDevtoolsSignals(String scriptBody) {
        DevtoolsSignals d = new DevtoolsSignals();
        int score = 0;
        String s = scriptBody == null ? "" : scriptBody;
        String lower = s.toLowerCase(Locale.ROOT);

        if (lower.contains("devtools") || lower.contains("dev tool") || lower.contains("developer tools")) score += 30;
        if (lower.contains("devtools-opened") || lower.contains("devtoolsopened")) score += 30;
        if (lower.contains("isdevtoolsopen") || lower.contains("devtoolsopen")) score += 20;
        if (lower.contains("disabletransformwhendevtoolsopen")) score += 25;
        if (lower.contains("outerwidth") && lower.contains("innerwidth")) score += 25;
        if (lower.contains("outerheight") && lower.contains("innerheight")) score += 20;
        if (lower.contains("outerwidth-innerwidth") || lower.contains("outerwidth - innerwidth")) score += 15;
        if (lower.contains("outerheight-innerheight") || lower.contains("outerheight - innerheight")) score += 15;
        if (lower.contains("outerwidth") && lower.contains("innerwidth") && lower.contains("math.abs")) score += 10;
        if ((lower.contains("outerwidth") && lower.contains("innerwidth") && lower.contains("160"))
                || (lower.contains("outerheight") && lower.contains("innerheight") && lower.contains("160"))) {
            score += 10;
        }
        if (lower.contains("debugger")) score += 20;
        if (lower.contains("setinterval") || lower.contains("settimeout")) score += 12;
        if (lower.contains("requestanimationframe")) score += 8;
        if (lower.contains("resize") && lower.contains("addEventListener")) score += 10;
        if (lower.contains("console.clear") || lower.contains("console.log") || lower.contains("console.profile")) score += 10;
        if (lower.contains("tostring") && lower.contains("function")) score += 10;
        if (lower.contains("performance.now") || lower.contains("date.now")) score += 8;
        if (lower.contains("chrome") && lower.contains("devtools")) score += 10;

        d.confidence = Math.max(0, Math.min(100, score));
        return d;
    }

    private static boolean looksDevtoolsHint(String html) {
        if (html == null) return false;
        String lower = html.toLowerCase(Locale.ROOT);
        return lower.contains("devtools") || lower.contains("dev tool") || lower.contains("developer tools");
    }
}
