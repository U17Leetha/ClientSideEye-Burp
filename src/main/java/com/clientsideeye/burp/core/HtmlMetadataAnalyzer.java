package com.clientsideeye.burp.core;

import org.jsoup.nodes.Document;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.clientsideeye.burp.core.Finding.Severity;

final class HtmlMetadataAnalyzer {
    private static final Pattern ROLE_HINT = Pattern.compile(
        "(?is)\\b(permission|authorize|isadmin|is_admin|acl|rbac|privilege)\\b|\\brole\\s*[:=]\\s*['\"]?(admin|superuser|owner|manager|privileged|staff)\\b"
    );
    private static final Pattern SECRET_ASSIGNMENT = Pattern.compile(
        "(?i)\\b(api[_-]?key|secret|bearer|token)\\b\\s*[:=]\\s*['\"][^'\"]{20,}['\"]"
    );
    private static final Pattern TOKEN_NEAR_KEYWORD = Pattern.compile(
        "(?is)\\b(api[_-]?key|secret|bearer|token|authorization)\\b.{0,80}?([a-z0-9+/]{30,}={0,2}|[a-f0-9]{32,})"
    );

    private HtmlMetadataAnalyzer() {
    }

    static List<Finding> analyze(Document document, String html, String url, String host) {
        List<Finding> findings = new ArrayList<>();
        addRoleHintFinding(findings, document, url, host);
        addScriptFindings(findings, document, html, url, host);
        return findings;
    }

    private static void addRoleHintFinding(List<Finding> out, Document document, String url, String host) {
        Matcher matcher = ROLE_HINT.matcher(document.outerHtml());
        if (!matcher.find()) {
            return;
        }
        String matched = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
        out.add(new Finding(
            FindingType.ROLE_PERMISSION_HINT.name(),
            Severity.INFO,
            35,
            url,
            host,
            "Role/permission hints found in HTML/JS",
            "The page contains role/permission-related keywords. This may help locate authorization logic or UI gating, but is not necessarily a vulnerability on its own.",
            "Matched keyword: " + matched,
            "Confirm all authorization decisions are enforced server-side. Avoid leaking internal role names or authorization flags to the client unless required.",
            "role-hint:" + matched.toLowerCase(Locale.ROOT)
        ));
    }

    private static void addScriptFindings(List<Finding> out, Document document, String html, String url, String host) {
        List<ScriptCandidate> secretCandidates = new ArrayList<>();
        List<ScriptCandidate> devtoolsCandidates = new ArrayList<>();
        document.select("script").forEach(script -> {
            String body = script.data();
            if (body == null || body.isBlank()) {
                body = script.html();
            }
            if (body == null || body.isBlank()) {
                return;
            }
            if (looksSecretish(body)) {
                secretCandidates.add(new ScriptCandidate(30, body));
            }
            int devtoolsConfidence = devtoolsConfidence(body);
            if (devtoolsConfidence >= 40) {
                devtoolsCandidates.add(new ScriptCandidate(devtoolsConfidence, body));
            }
        });

        addSecretishFindings(out, secretCandidates, url, host);
        addDevtoolsFindings(out, devtoolsCandidates, url, host);
        if (devtoolsCandidates.isEmpty() && looksDevtoolsHint(html)) {
            out.add(new Finding(
                FindingType.DEVTOOLS_BLOCKING.name(),
                Severity.INFO,
                30,
                url,
                host,
                "DevTools-related hint found in HTML",
                "The page contains DevTools-related keywords. This may indicate client-side detection or blocking logic elsewhere (e.g., external scripts).",
                HtmlAnalysisSupport.shrink(html, 240),
                "If DevTools access is blocked and testing is authorized, look for client-side detection in scripts and consider a controlled bypass snippet.",
                "devtools-hint"
            ));
        }
    }

    private static boolean looksSecretish(String scriptBody) {
        if (scriptBody == null) {
            return false;
        }
        if (SECRET_ASSIGNMENT.matcher(scriptBody).find()) {
            return true;
        }
        if (scriptBody.contains("eyJ") && scriptBody.contains(".")) {
            return true;
        }
        return TOKEN_NEAR_KEYWORD.matcher(scriptBody).find();
    }

    private static void addSecretishFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate candidate : candidates) {
            String snippet = HtmlAnalysisSupport.shrink(candidate.body, 420);
            if (!seen.add(snippet)) {
                continue;
            }
            out.add(new Finding(
                FindingType.INLINE_SCRIPT_SECRETISH.name(),
                Severity.LOW,
                30,
                url,
                host,
                "Potential secret-like value in inline script",
                "The page contains inline script content that looks like it may include credentials/tokens/keys. This is heuristic and can generate false positives.",
                snippet,
                "Avoid embedding secrets in client-side code. Use server-side sessions or retrieve short-lived tokens from protected endpoints with proper authorization.",
                "script-secret:" + Integer.toHexString(snippet.hashCode())
            ));
        }
    }

    private static void addDevtoolsFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        candidates.sort((a, b) -> Integer.compare(b.confidence, a.confidence));
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate candidate : candidates) {
            String snippet = HtmlAnalysisSupport.shrink(candidate.body, 420);
            if (!seen.add(snippet)) {
                continue;
            }
            Severity severity = candidate.confidence >= 65 ? Severity.MEDIUM : Severity.LOW;
            out.add(new Finding(
                FindingType.DEVTOOLS_BLOCKING.name(),
                severity,
                candidate.confidence,
                url,
                host,
                "Possible DevTools blocking or detection logic in client-side script",
                "The page includes script patterns commonly used to detect or disrupt DevTools usage (e.g., debugger statements, window size checks, or devtools keywords). This can interfere with client-side enumeration and validation.",
                snippet,
                "If this behavior is authorized to bypass, use a controlled DevTools bypass snippet to neutralize common detection hooks. Ensure testing remains in-scope and approved.",
                "script-devtools:" + Integer.toHexString(snippet.hashCode())
            ));
        }
    }

    private static int devtoolsConfidence(String scriptBody) {
        int score = 0;
        String lower = scriptBody == null ? "" : scriptBody.toLowerCase(Locale.ROOT);
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
        if (lower.contains("resize") && lower.contains("addeventlistener")) score += 10;
        if (lower.contains("console.clear") || lower.contains("console.log") || lower.contains("console.profile")) score += 10;
        if (lower.contains("tostring") && lower.contains("function")) score += 10;
        if (lower.contains("performance.now") || lower.contains("date.now")) score += 8;
        if (lower.contains("chrome") && lower.contains("devtools")) score += 10;
        return Math.max(0, Math.min(100, score));
    }

    private static boolean looksDevtoolsHint(String html) {
        if (html == null) {
            return false;
        }
        String lower = html.toLowerCase(Locale.ROOT);
        return lower.contains("devtools") || lower.contains("dev tool") || lower.contains("developer tools");
    }

    private record ScriptCandidate(int confidence, String body) {
    }
}
