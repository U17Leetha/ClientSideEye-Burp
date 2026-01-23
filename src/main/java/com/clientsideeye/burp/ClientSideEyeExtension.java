package com.clientsideeye.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.clientsideeye.burp.core.Analyzer;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.ui.ClientSideEyeTab;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

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

        // OK, though deprecated; compiles on 2025.12
        api.scanner().registerScanCheck(new ClientSideEyeScanCheck());

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
        public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
            // Passive must not make new HTTP requests. :contentReference[oaicite:5]{index=5}
            return analyzeAndReport(baseRequestResponse, false);
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
            // This check does not send probe requests; it just analyzes the observed base response.
            return analyzeAndReport(baseRequestResponse, true);
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            // If same baseUrl + same name => treat as duplicate.
            try {
                if (existingIssue != null && newIssue != null
                        && Objects.equals(existingIssue.baseUrl(), newIssue.baseUrl())
                        && Objects.equals(existingIssue.name(), newIssue.name())) {
                    return ConsolidationAction.KEEP_EXISTING;
                }
            } catch (Exception ignored) {}
            return ConsolidationAction.KEEP_BOTH;
        }

        private AuditResult analyzeAndReport(HttpRequestResponse base, boolean isActive) {
            try {
                HttpResponse resp = base.response();
                if (resp == null) return auditResult();

                String ct = contentType(resp);
                if (!looksLikeHtml(ct, resp.body())) return auditResult();

                String body = safeBody(resp.body());
                if (body.isBlank()) return auditResult();

                String url = base.request().url();
                String host = base.request().httpService().host();

                List<Finding> findings = Analyzer.analyze(url, host, body);
                if (findings.isEmpty()) return auditResult();

                SwingUtilities.invokeLater(() -> tab.addFindings(findings));

                List<AuditIssue> issues = new ArrayList<>(findings.size());
                for (Finding f : findings) {
                    issues.add(toIssue(base, f, isActive));
                }

                return auditResult(issues);

            } catch (Exception e) {
                api.logging().logToError("ClientSideEye scancheck error: " + e);
                return auditResult();
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

            String remediation = switch (f.type) {
                case PASSWORD_VALUE_IN_DOM ->
                        "Do not embed secrets client-side. Only return secrets to authorized users via protected endpoints. Enforce access control server-side.";
                case HIDDEN_OR_DISABLED_CONTROL ->
                        "Do not rely on hidden/disabled UI controls for access control. Enforce authorization server-side for every action/object.";
                case ROLE_PERMISSION_HINT ->
                        "Avoid exposing sensitive authorization logic in client-side markup. Never rely on it for enforcement.";
                case INLINE_SCRIPT_SECRETISH ->
                        "Avoid embedding secret-like values in inline scripts. Rotate/scope tokens and prefer server-side retrieval.";
            };

            String title = f.title + (isActive ? " (during active scan)" : "");
            String detail = """
                    ClientSideEye detected a client-side control signal.

                    Evidence:
                    %s

                    Validation guidance:
                    - Confirm server-side enforcement by invoking the underlying request/action directly (Repeater).
                    - Attempt privilege transitions using a low-privileged account/session.
                    """.formatted(escapeHtml(f.evidence));

            String background = """
                    Some applications implement authorization in the UI by hiding/disable controls or masking sensitive values.
                    These measures do not provide security if the server still returns the data or accepts the action.
                    """;

            String remediationBackground = """
                    Enforce authorization server-side for every request and object. Do not return secrets to the client unless required and authorized.
                    """;

            // Use Montoya static factory. :contentReference[oaicite:6]{index=6}
            return auditIssue(
                    title,
                    detail,
                    escapeHtml(remediation),
                    base.request().url(),
                    sev,
                    conf,
                    escapeHtml(background),
                    escapeHtml(remediationBackground),
                    sev,
                    base
            );
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

        private String escapeHtml(String s) {
            if (s == null) return "";
            // Burp applies an HTML whitelist; keep it simple and safe.
            return s.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;");
        }
    }
}
