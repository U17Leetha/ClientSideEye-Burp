package com.clientsideeye.burp.core;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Analyzer {

    private static final Pattern PASSWORD_VALUE_ATTR =
            Pattern.compile("(?is)<input\\b[^>]*\\btype\\s*=\\s*(['\"])password\\1[^>]*\\bvalue\\s*=\\s*(['\"])(.*?)\\2[^>]*>");

    private static final Pattern HIDDEN_OR_DISABLED_ELEMENT =
            Pattern.compile("(?is)<(button|a|input|select|textarea|div|span)\\b[^>]*\\b(" +
                    "hidden\\b|" +
                    "disabled\\b|" +
                    "aria-hidden\\s*=\\s*(['\"])true\\3|" +
                    "aria-disabled\\s*=\\s*(['\"])true\\4|" +
                    "style\\s*=\\s*(['\"]).*?(display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0|pointer-events\\s*:\\s*none).*?\\5" +
                    ")[^>]*>");

    private static final Pattern ROLE_PERMISSION_HINTS =
            Pattern.compile("(?is)\\b(data-(role|permission|perm|admin|owner|scope|policy|acl|feature|flag)\\b|role\\b|permission\\b)\\s*=\\s*(['\"])(.*?)\\3");

    private static final Pattern SCRIPT_INLINE_SECRETISH =
            Pattern.compile("(?is)<script\\b[^>]*>.*?(password|passwd|pwd|secret|token)\\s*[:=]\\s*(['\"])(.{1,200}?)\\2.*?</script>");

    public static List<Finding> analyze(String url, String host, String body) {
        if (body == null || body.isBlank()) return List.of();

        List<Finding> out = new ArrayList<>();
        Instant now = Instant.now();

        // 1) Password value attribute (high signal)
        Matcher mPwd = PASSWORD_VALUE_ATTR.matcher(body);
        int pwdCount = 0;
        while (mPwd.find() && pwdCount < 20) {
            pwdCount++;
            String raw = safe(mPwd.group(3));
            if (raw.isBlank()) continue;

            String preview = redactPreview(raw);
            Map<String, Object> meta = new HashMap<>();
            meta.put("kind", "input[type=password][value]");
            meta.put("preview", preview);

            out.add(new Finding(
                    uuid(),
                    now,
                    Finding.Type.PASSWORD_VALUE_IN_DOM,
                    url,
                    host,
                    "Client-side password masking exposes plaintext",
                    "High",
                    "Firm",
                    "Password input contains a non-empty value attribute (preview: " + preview + ")",
                    meta
            ));
        }

        // 2) Hidden/disabled (informational)
        Matcher mHidden = HIDDEN_OR_DISABLED_ELEMENT.matcher(body);
        int hiddenCount = 0;
        while (mHidden.find() && hiddenCount < 200) hiddenCount++;

        if (hiddenCount > 0) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("count", hiddenCount);
            out.add(new Finding(
                    uuid(),
                    now,
                    Finding.Type.HIDDEN_OR_DISABLED_CONTROL,
                    url,
                    host,
                    "Client-side only access control signals (hidden/disabled controls)",
                    "Information",
                    "Tentative",
                    "Detected " + hiddenCount + " hidden/disabled elements (HTML/CSS attributes).",
                    meta
            ));
        }

        // 3) Role/permission hints (informational)
        Matcher mHints = ROLE_PERMISSION_HINTS.matcher(body);
        int hintCount = 0;
        while (mHints.find() && hintCount < 200) hintCount++;

        if (hintCount > 0) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("count", hintCount);
            out.add(new Finding(
                    uuid(),
                    now,
                    Finding.Type.ROLE_PERMISSION_HINT,
                    url,
                    host,
                    "Role/permission hints exposed in client-side markup",
                    "Information",
                    "Tentative",
                    "Detected " + hintCount + " role/permission-related attributes in markup.",
                    meta
            ));
        }

        // 4) Secret-ish inline script (informational)
        Matcher mScript = SCRIPT_INLINE_SECRETISH.matcher(body);
        int sCount = 0;
        while (mScript.find() && sCount < 20) {
            sCount++;
            String var = safe(mScript.group(1));
            String val = safe(mScript.group(3));
            String preview = redactPreview(val);

            Map<String, Object> meta = new HashMap<>();
            meta.put("key", var);
            meta.put("preview", preview);

            out.add(new Finding(
                    uuid(),
                    now,
                    Finding.Type.INLINE_SCRIPT_SECRETISH,
                    url,
                    host,
                    "Potential secret-like values in inline scripts",
                    "Information",
                    "Tentative",
                    "Inline script assigns " + var + " to a quoted string (preview: " + preview + ")",
                    meta
            ));
        }

        return out;
    }

    private static String uuid() { return UUID.randomUUID().toString(); }
    private static String safe(String s) { return s == null ? "" : s; }

    private static String redactPreview(String s) {
        if (s == null) return "REDACTED";
        String t = s.trim();
        if (t.isEmpty()) return "REDACTED";
        if (t.length() <= 6) return "REDACTED";
        return t.substring(0, 3) + "…";
    }
}
