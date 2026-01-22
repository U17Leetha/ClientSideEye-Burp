package com.clientsideeye.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.*;

import com.clientsideeye.burp.core.Analyzer;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.ui.ClientSideEyeTab;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class ClientSideEyeExtension implements BurpExtension {

    private MontoyaApi api;
    private ClientSideEyeTab tab;
    private ExecutorService bg;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("ClientSideEye");

        bg = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ClientSideEye-bg");
            t.setDaemon(true);
            return t;
        });

        tab = new ClientSideEyeTab(api, bg);
        api.userInterface().registerSuiteTab("ClientSideEye", tab);

        api.scanner().registerScanCheck(new ClientSideEyeScanCheck());

        // Acceptance criteria: unload cleanly
        api.extension().registerUnloadingHandler(() -> {
            try { if (tab != null) tab.onUnload(); }
            catch (Exception e) { api.logging().logToError("ClientSideEye unload error (tab): " + e); }

            if (bg != null) {
                bg.shutdownNow();
                try { bg.awaitTermination(2, TimeUnit.SECONDS); }
                catch (InterruptedException ignored) {}
            }
        });

        api.logging().logToOutput("ClientSideEye loaded (Montoya).");
    }

    private class ClientSideEyeScanCheck implements ScanCheck {

        @Override
        public List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse) {
            // Acceptance criteria: do NOT do outbound comms in passiveAudit
            return analyzeAndReport(baseRequestResponse, false);
        }

        @Override
        public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
            // We do not probe insertion points or issue requests; we analyze encountered responses during active scan runs.
            return analyzeAndReport(baseRequestResponse, true);
        }

        private List<AuditIssue> analyzeAndReport(HttpRequestResponse base, boolean isActive) {
            try {
                HttpResponse resp = base.response();
                if (resp == null) return List.of();

                String ct = contentType(resp);
                if (!looksLikeHtml(ct, resp.body())) return List.of();

                String body = safeBody(resp.body());
                if (body.isBlank()) return List.of();

                String url = base.request().url();
                String host = base.request().httpService().host();

                List<Finding> findings = Analyzer.analyze(url, host, body);
                if (findings.isEmpty()) return List.of();

                SwingUtilities.invokeLater(() -> tab.addFindings(findings));

                List<AuditIssue> issues = new ArrayList<>(findings.size());
                for (Finding f : findings) issues.add(toIssue(base, f, isActive));
                return issues;

            } catch (Exception e) {
                api.logging().logToError("ClientSideEye scancheck error: " + e);
                return List.of();
            }
        }

        private AuditIssue toIssue(HttpRequestResponse base, Finding f, boolean isActive) {
            AuditIssueSeverity sev = switch (f.severity.toLowerCase(Locale.ROOT)) {
                case "high" -> AuditIssueSeverity.HIGH;
                case "medium" -> AuditIssueSeverity.MEDIUM;
                case "low" -> AuditIssueSeverity.LOW;
                default -> AuditIssueSeverity.INFORMATION;
            };

            AuditIssueConfidence conf = switch (f.confidence.toLowerCase(Locale.ROOT)) {
                case "firm" -> AuditIssueConfidence.FIRM;
                case "certain" -> AuditIssueConfidence.CERTAIN;
                default -> AuditIssueConfidence.TENTATIVE;
            };

            String desc = """
                    ClientSideEye detected a client-side control signal.

                    Evidence:
                    %s

                    Notes:
                    - This is heuristic signal detection. Hidden/disabled UI controls often indicate UI-only access control.
                    - Validate impact with server-side authorization testing.
                    """.formatted(f.evidence);

            String remediation = switch (f.type) {
                case PASSWORD_VALUE_IN_DOM ->
                        "Do not embed secrets client-side. Only return secrets to authorized users via protected endpoints. Enforce access control server-side.";
                case HIDDEN_OR_DISABLED_CONTROL ->
                        "Do not rely on hidden/disabled controls for access control. Enforce authorization server-side for every action/object.";
                case ROLE_PERMISSION_HINT ->
                        "Avoid exposing sensitive authorization logic in client-side markup. Never rely on it for enforcement.";
                case INLINE_SCRIPT_SECRETISH ->
                        "Avoid embedding secret-like values in inline scripts. Rotate/scope tokens and prefer server-side retrieval.";
            };

            String title = f.title + (isActive ? " (during active scan)" : "");

            AuditIssueDefinition def = AuditIssueDefinitionBuilder.auditIssueDefinitionBuilder()
                    .name(title)
                    .type(AuditIssueType.GENERIC)
                    .build();

            AuditIssueDetail detail = AuditIssueDetailBuilder.auditIssueDetailBuilder()
                    .description(desc + "\nRemediation:\n" + remediation)
                    .build();

            return AuditIssueBuilder.auditIssueBuilder()
                    .auditIssueDefinition(def)
                    .severity(sev)
                    .confidence(conf)
                    .detail(detail)
                    .baseRequestResponse(base)
                    .build();
        }

        private String safeBody(ByteArray body) {
            try {
                if (body == null) return "";
                return new String(body.getBytes(), StandardCharsets.UTF_8);
            } catch (Exception ignored) {
                return "";
            }
        }

        private String contentType(HttpResponse resp) {
            return resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                    .map(h -> h.value())
                    .findFirst().orElse("");
        }

        private boolean looksLikeHtml(String ct, ByteArray body) {
            String l = ct == null ? "" : ct.toLowerCase(Locale.ROOT);
            if (l.contains("text/html") || l.contains("application/xhtml")) return true;

            String b = safeBody(body);
            String s = b.stripLeading().toLowerCase(Locale.ROOT);
            return s.startsWith("<!doctype html") || s.startsWith("<html") || s.contains("<input") || s.contains("<form");
        }
    }
}
