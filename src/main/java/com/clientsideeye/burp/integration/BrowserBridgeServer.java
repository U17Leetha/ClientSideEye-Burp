package com.clientsideeye.burp.integration;

import burp.api.montoya.MontoyaApi;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.ui.ClientSideEyeTab;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class BrowserBridgeServer {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 17373;
    private static final int MAX_PORT_ATTEMPTS = 10;

    private final MontoyaApi api;
    private final ClientSideEyeTab tab;
    private final ExecutorService exec;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private int boundPort = -1;

    public BrowserBridgeServer(MontoyaApi api, ClientSideEyeTab tab) {
        this.api = api;
        this.tab = tab;
        this.exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ClientSideEye-bridge");
            t.setDaemon(true);
            return t;
        });
    }

    public synchronized void start() {
        if (running) return;
        IOException last = null;
        for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
            int candidatePort = PORT + i;
            try {
                serverSocket = new ServerSocket();
                serverSocket.setReuseAddress(true);
                serverSocket.bind(new InetSocketAddress(HOST, candidatePort), 50);
                serverSocket.setSoTimeout(1000);
                boundPort = candidatePort;
                running = true;
                exec.submit(this::acceptLoop);
                api.logging().logToOutput("[ClientSideEye] Browser bridge listening on http://" + HOST + ":" + boundPort + " (/api/health, /api/finding)");
                if (boundPort != PORT) {
                    api.logging().logToOutput("[ClientSideEye] Default port " + PORT + " was busy. Using fallback port " + boundPort + ".");
                }
                return;
            } catch (IOException e) {
                last = e;
                try {
                    if (serverSocket != null) serverSocket.close();
                } catch (IOException ignored) {}
                serverSocket = null;
            }
        }
        api.logging().logToError("[ClientSideEye] Browser bridge failed to start after " + MAX_PORT_ATTEMPTS + " port attempts from " + PORT + ": " + last);
    }

    public synchronized void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
            // best-effort close
        } finally {
            serverSocket = null;
        }
        exec.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                handleClient(s);
            } catch (SocketTimeoutException ignored) {
                // periodic loop check
            } catch (Exception e) {
                if (running) {
                    api.logging().logToError("[ClientSideEye] Bridge accept error: " + e);
                }
            }
        }
    }

    private void handleClient(Socket socket) {
        try (socket;
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {

            String requestLine = in.readLine();
            if (requestLine == null || requestLine.isBlank()) {
                writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"bad request\"}");
                return;
            }

            String[] reqParts = requestLine.split(" ");
            if (reqParts.length < 2) {
                writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"bad request\"}");
                return;
            }
            String method = reqParts[0].trim().toUpperCase(Locale.ROOT);
            String rawPath = reqParts[1].trim();
            String path = rawPath;
            int qIdx = rawPath.indexOf('?');
            if (qIdx >= 0) {
                path = rawPath.substring(0, qIdx);
            }

            int contentLength = 0;
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
                    } catch (Exception ignored) {
                        contentLength = 0;
                    }
                }
            }

            String body = "";
            if (contentLength > 0) {
                char[] buf = new char[contentLength];
                int read = 0;
                while (read < contentLength) {
                    int n = in.read(buf, read, contentLength - read);
                    if (n < 0) break;
                    read += n;
                }
                body = new String(buf, 0, read);
            }

            if ("OPTIONS".equals(method)) {
                writeResponse(out, 204, "text/plain; charset=utf-8", "");
                return;
            }

            if ("/api/health".equals(path)) {
                if (!"GET".equals(method)) {
                    writeResponse(out, 405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}");
                    return;
                }
                writeResponse(out, 200, "application/json; charset=utf-8", "{\"status\":\"ok\"}");
                return;
            }

            if ("/api/finding".equals(path)) {
                if (!"POST".equals(method)) {
                    writeResponse(out, 405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}");
                    return;
                }
                handleFindingPost(out, body);
                return;
            }

            writeResponse(out, 404, "application/json; charset=utf-8", "{\"error\":\"not found\"}");
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Bridge client error: " + e);
        }
    }

    private void handleFindingPost(BufferedWriter out, String body) throws IOException {
        Map<String, String> form = parseFormEncoded(body);
        String url = safe(form.get("url"));
        if (url.isBlank()) {
            writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"url is required\"}");
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
        writeResponse(out, 200, "application/json; charset=utf-8", "{\"accepted\":1}");
    }

    private static void writeResponse(BufferedWriter out, int status, String contentType, String body) throws IOException {
        String statusText = switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            default -> "Error";
        };
        byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        out.write("HTTP/1.1 " + status + " " + statusText + "\r\n");
        out.write("Content-Type: " + contentType + "\r\n");
        out.write("Content-Length: " + bodyBytes.length + "\r\n");
        out.write("Access-Control-Allow-Origin: *\r\n");
        out.write("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n");
        out.write("Access-Control-Allow-Headers: Content-Type\r\n");
        out.write("Connection: close\r\n");
        out.write("\r\n");
        if (bodyBytes.length > 0) {
            out.write(new String(bodyBytes, StandardCharsets.UTF_8));
        }
        out.flush();
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
