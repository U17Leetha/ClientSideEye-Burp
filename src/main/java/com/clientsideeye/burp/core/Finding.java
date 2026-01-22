package com.clientsideeye.burp.core;

import java.time.Instant;
import java.util.Map;

public class Finding {
    public enum Type {
        PASSWORD_VALUE_IN_DOM,
        HIDDEN_OR_DISABLED_CONTROL,
        ROLE_PERMISSION_HINT,
        INLINE_SCRIPT_SECRETISH
    }

    public final String id;
    public final Instant time;
    public final Type type;
    public final String url;
    public final String host;
    public final String title;
    public final String severity;   // "High", "Information", etc.
    public final String confidence; // "Firm", "Tentative"
    public final String evidence;   // short, redacted
    public final Map<String, Object> meta;

    public Finding(String id, Instant time, Type type, String url, String host,
                   String title, String severity, String confidence,
                   String evidence, Map<String, Object> meta) {
        this.id = id;
        this.time = time;
        this.type = type;
        this.url = url;
        this.host = host;
        this.title = title;
        this.severity = severity;
        this.confidence = confidence;
        this.evidence = evidence;
        this.meta = meta;
    }
}
