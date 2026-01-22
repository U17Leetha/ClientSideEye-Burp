package com.clientsideeye.burp.core;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class JsonExporter {

    public static String export(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"tool\":\"ClientSideEye-Burp\",\"version\":\"0.1.0\",\"findings\":[");
        boolean first = true;

        for (Finding f : findings) {
            if (!first) sb.append(",");
            first = false;

            sb.append("{");
            j(sb, "id", f.id); sb.append(",");
            j(sb, "time", DateTimeFormatter.ISO_INSTANT.format(f.time)); sb.append(",");
            j(sb, "type", f.type.name()); sb.append(",");
            j(sb, "url", f.url); sb.append(",");
            j(sb, "host", f.host); sb.append(",");
            j(sb, "title", f.title); sb.append(",");
            j(sb, "severity", f.severity); sb.append(",");
            j(sb, "confidence", f.confidence); sb.append(",");
            j(sb, "evidence", f.evidence); sb.append(",");
            sb.append("\"meta\":").append(obj(f.meta));
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    private static void j(StringBuilder sb, String k, String v) {
        sb.append("\"").append(esc(k)).append("\":\"").append(esc(v)).append("\"");
    }

    private static String obj(Map<String, Object> m) {
        if (m == null) return "{}";
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (var e : m.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(esc(e.getKey())).append("\":");
            Object v = e.getValue();
            if (v == null) sb.append("null");
            else if (v instanceof Number || v instanceof Boolean) sb.append(v.toString());
            else sb.append("\"").append(esc(v.toString())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
