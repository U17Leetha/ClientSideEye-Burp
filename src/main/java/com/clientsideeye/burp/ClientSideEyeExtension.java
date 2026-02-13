package com.clientsideeye.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.HtmlAnalyzer;
import com.clientsideeye.burp.ui.ClientSideEyeTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ClientSideEyeExtension implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService bg;
    private ClientSideEyeTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("ClientSideEye");

        this.bg = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ClientSideEye-bg");
            t.setDaemon(true);
            return t;
        });

        this.tab = new ClientSideEyeTab(api, bg);
        api.userInterface().registerSuiteTab("ClientSideEye", tab);

        // Right-click: Send selected items for analysis (Proxy, Target, Repeater, Logger, etc.)
        api.userInterface().registerContextMenuItemsProvider(new SendToClientSideEyeMenu(api, tab, bg));

        api.logging().logToOutput("[ClientSideEye] Loaded. Use right-click 'Send to ClientSideEye' or the tab button 'Analyze Site Map (in-scope)'.");
    }

    // -------------------------
    // Right-click "Send to" menu
    // -------------------------
    private static class SendToClientSideEyeMenu implements ContextMenuItemsProvider {
        private final MontoyaApi api;
        private final ClientSideEyeTab tab;
        private final ExecutorService bg;

        SendToClientSideEyeMenu(MontoyaApi api, ClientSideEyeTab tab, ExecutorService bg) {
            this.api = api;
            this.tab = tab;
            this.bg = bg;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected == null || selected.isEmpty()) {
                return Collections.emptyList();
            }
            List<HttpRequestResponse> snapshot = new ArrayList<>(selected);

            JMenuItem item = new JMenuItem("Send to ClientSideEye (analyze response HTML)");
            item.addActionListener(e -> bg.submit(() -> analyzeSelection(snapshot)));

            JMenu menu = new JMenu("ClientSideEye");
            menu.add(item);

            return List.of(menu);
        }

        private void analyzeSelection(List<HttpRequestResponse> selected) {
            try {
                int added = 0;
                int analyzed = 0;
                int skippedMissingResponse = 0;
                int skippedEmptyBody = 0;

                for (HttpRequestResponse rr : selected) {
                    if (rr == null || rr.request() == null || rr.response() == null) {
                        skippedMissingResponse++;
                        continue;
                    }

                    String url = rr.request().url();
                    String body = rr.response().bodyToString();
                    if (body == null || body.isBlank()) {
                        skippedEmptyBody++;
                        continue;
                    }

                    analyzed++;
                    List<Finding> findings = HtmlAnalyzer.analyzeHtml(url, body);
                    if (!findings.isEmpty()) {
                        tab.addFindings(findings);
                        added += findings.size();
                    }
                }

                api.logging().logToOutput(
                        "[ClientSideEye] Right-click analyze complete. Selected: " + selected.size()
                                + " | Analyzed: " + analyzed
                                + " | Findings added: " + added
                                + " | Skipped (no response): " + skippedMissingResponse
                                + " | Skipped (empty body): " + skippedEmptyBody
                );
            } catch (Exception ex) {
                api.logging().logToError("[ClientSideEye] Right-click analyze error: " + ex);
            }
        }
    }
}
