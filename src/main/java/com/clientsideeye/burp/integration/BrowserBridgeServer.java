package com.clientsideeye.burp.integration;

import burp.api.montoya.MontoyaApi;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.ui.ClientSideEyeTab;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class BrowserBridgeServer {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 17373;

    private final MontoyaApi api;
    private final ClientSideEyeTab tab;
    private HttpServer server;

    public BrowserBridgeServer(MontoyaApi api, ClientSideEyeTab tab) {
        this.api = api;
        this.tab = tab;
    }

    public void start() {
        if (server != null) return;
        try {
            server = HttpServer.create(new InetSocketAddress(HOST, PORT), 0);
            server.createContext("/api/health", new HealthHandler());
            server.createContext("/api/finding", new FindingHandler(api, tab));
            server.setExecutor(null);
            server.start();
            api.logging().logToOutput("[ClientSideEye] Browser bridge listening on http://" + HOST + ":" + PORT + " (/api/health, /api/finding)");
        } catch (IOException e) {
            api.logging().logToError("[ClientSideEye] Browser bridge failed to start: " + e);
        }
    }

    private static final class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod()) && !"OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 405, "Method not allowed");
                return;
            }
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 204, "");
                return;
            }
            respond(ex, 200, "{\"status\":\"ok\"}");
        }
    }

    private static final class FindingHandler implements HttpHandler {
        private final MontoyaApi api;
        private final ClientSideEyeTab tab;

        FindingHandler(MontoyaApi api, ClientSideEyeTab tab) {
            this.api = api;
            this.tab = tab;
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 204, "");
                return;
            }
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 405, "Method not allowed");
                return;
            }

            String body = readAll(ex.getRequestBody());
            Map<String, String> form = parseFormEncoded(body);

            String url = safe(form.get("url"));
            if (url.isBlank()) {
                respond(ex, 400, "{\"error\":\"url is required\"}");
                return;
            }

            String type = normalizeType(form.get("type"));
            Finding.Severity severity = parseSeverity(form.get("severity"));
            int confidence = parseInt(form.get("confidence"), 55);
            String title = defaultIfBlank(form.get("title"), "Browser-reported client-side control finding");
            String summary = defaultIfBlank(form.get("summary"),
                    "A browser extension submitted a client-side control signal for review.");
            String evidence = defaultIfBlank(form.get("evidence"), "(no evidence)");
            String recommendation = defaultIfBlank(form.get("recommendation"),
                    "Validate server-side authorization for this action. Do not rely on client-side disabled/hidden states.");
            String host = hostFromUrl(url);

            Finding finding = new Finding(
                    type,
                    severity,
                    confidence,
                    url,
                    host,
                    title,
                    summary,
                    evidence,
                    recommendation
            );

            List<Finding> findings = new ArrayList<>();
            findings.add(finding);
            tab.addFindings(findings);

            String source = defaultIfBlank(form.get("source"), "browser-extension");
            api.logging().logToOutput("[ClientSideEye] Bridge accepted finding from " + source + " | " + type + " | " + severity + " (" + confidence + ") | " + url);
            respond(ex, 200, "{\"accepted\":1}");
        }
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

        byte[] out = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    private static String readAll(InputStream in) throws IOException {
        byte[] buf = in.readAllBytes();
        return new String(buf, StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseFormEncoded(String body) {
        Map<String, String> out = new HashMap<>();
        if (body == null || body.isBlank()) return out;
        String[] parts = body.split("&");
        for (String p : parts) {
            if (p == null || p.isBlank()) continue;
            int idx = p.indexOf('=');
            String k = idx >= 0 ? p.substring(0, idx) : p;
            String v = idx >= 0 ? p.substring(idx + 1) : "";
            k = URLDecoder.decode(k, StandardCharsets.UTF_8);
            v = URLDecoder.decode(v, StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
    }

    private static String normalizeType(String type) {
        String t = safe(type).trim();
        if (t.isBlank()) return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
        for (FindingType ft : FindingType.values()) {
            if (ft.name().equalsIgnoreCase(t)) return ft.name();
        }
        return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
    }

    private static Finding.Severity parseSeverity(String s) {
        String x = safe(s).trim().toUpperCase(Locale.ROOT);
        try {
            return Finding.Severity.valueOf(x);
        } catch (Exception e) {
            return Finding.Severity.MEDIUM;
        }
    }

    private static int parseInt(String s, int dflt) {
        try {
            return Integer.parseInt(safe(s).trim());
        } catch (Exception e) {
            return dflt;
        }
    }

    private static String defaultIfBlank(String s, String dflt) {
        String x = safe(s).trim();
        return x.isBlank() ? dflt : x;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String hostFromUrl(String url) {
        try {
            URI u = URI.create(url);
            return u.getHost() == null ? "" : u.getHost();
        } catch (Exception e) {
            return "";
        }
    }
}
