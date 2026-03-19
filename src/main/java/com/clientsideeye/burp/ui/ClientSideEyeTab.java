package com.clientsideeye.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.core.JsonExporter;

import javax.swing.*;
import javax.swing.RowSorter.SortKey;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import static com.clientsideeye.burp.core.Finding.Severity;

public class ClientSideEyeTab extends JPanel {

    private final MontoyaApi api;
    private final ExecutorService bg;

    private static final int MAX_FINDINGS = 5000;
    private static final int SITE_MAP_SCAN_WARN_THRESHOLD = 1000;
    private static final int SITE_MAP_SCAN_HARD_CAP = 2000;

    // Dedupe by stable key -> Finding (LinkedHashMap preserves insertion order)
    private final LinkedHashMap<String, Finding> findingsByKey = new LinkedHashMap<>();
    private final Set<String> falsePositiveKeys = new HashSet<>();

    private final FindingsTableModel tableModel = new FindingsTableModel(this::isFalsePositive, this::findingArea);
    private final JTable table = new JTable();
    private final TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextArea detailArea = new JTextArea();
    private final JTextField filterHost = new JTextField();
    private final JTextField filterSearch = new JTextField();
    private final JTextField bridgeEndpointField = new JTextField("Bridge not started");
    private final JTextField bridgeTokenField = new JTextField();
    private final JSpinner scanLimitSpinner = new JSpinner(new SpinnerNumberModel(SITE_MAP_SCAN_HARD_CAP, 100, 10000, 100));
    private final JCheckBox exportVisibleOnly = new JCheckBox("Export visible rows only", true);

    private final JCheckBoxMenuItem filterTypePassword = new JCheckBoxMenuItem(FindingType.PASSWORD_VALUE_IN_DOM.name(), true);
    private final JCheckBoxMenuItem filterTypeHidden = new JCheckBoxMenuItem(FindingType.HIDDEN_OR_DISABLED_CONTROL.name(), true);
    private final JCheckBoxMenuItem filterTypeRole = new JCheckBoxMenuItem(FindingType.ROLE_PERMISSION_HINT.name(), true);
    private final JCheckBoxMenuItem filterTypeInline = new JCheckBoxMenuItem(FindingType.INLINE_SCRIPT_SECRETISH.name(), true);
    private final JCheckBoxMenuItem filterTypeDevtools = new JCheckBoxMenuItem(FindingType.DEVTOOLS_BLOCKING.name(), true);
    private final JCheckBoxMenuItem filterTypeEndpoint = new JCheckBoxMenuItem(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name(), true);
    private final JCheckBoxMenuItem filterTypeDomXss = new JCheckBoxMenuItem(FindingType.DOM_XSS_SINK.name(), true);
    private final JCheckBoxMenuItem filterTypePostMessage = new JCheckBoxMenuItem(FindingType.POSTMESSAGE_HANDLER.name(), true);
    private final JCheckBoxMenuItem filterTypeStorage = new JCheckBoxMenuItem(FindingType.STORAGE_TOKEN.name(), true);
    private final JCheckBoxMenuItem filterTypeSourceMap = new JCheckBoxMenuItem(FindingType.SOURCE_MAP_DISCLOSURE.name(), true);
    private final JCheckBoxMenuItem filterTypeRuntimeNetwork = new JCheckBoxMenuItem(FindingType.RUNTIME_NETWORK_REFERENCE.name(), true);
    private final JPopupMenu typeMenu = new JPopupMenu();
    private final JButton typeMenuButton = new JButton("Type…");

    private final JCheckBoxMenuItem filterHigh = new JCheckBoxMenuItem("High", true);
    private final JCheckBoxMenuItem filterMedium = new JCheckBoxMenuItem("Medium", true);
    private final JCheckBoxMenuItem filterLow = new JCheckBoxMenuItem("Low", true);
    private final JCheckBoxMenuItem filterInfo = new JCheckBoxMenuItem("Informational", true);
    private final JPopupMenu severityMenu = new JPopupMenu();
    private final JButton severityMenuButton = new JButton("Severity…");
    private final JCheckBox filterFalsePositive = new JCheckBox("Show false positives", true);

    public ClientSideEyeTab(MontoyaApi api, ExecutorService bg) {
        super(new BorderLayout(10, 10));
        this.api = api;
        this.bg = bg;

        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top controls
        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; c.weightx = 0;
        controls.add(new JLabel("Host filter:"), c);

        c.gridx = 1; c.gridy = 0; c.weightx = 1;
        controls.add(filterHost, c);

        c.gridx = 2; c.gridy = 0; c.weightx = 0;
        controls.add(new JLabel("Search:"), c);

        c.gridx = 3; c.gridy = 0; c.weightx = 1;
        controls.add(filterSearch, c);

        c.gridx = 4; c.gridy = 0; c.weightx = 0;
        controls.add(new JLabel("Type:"), c);

        typeMenu.add(filterTypePassword);
        typeMenu.add(filterTypeHidden);
        typeMenu.add(filterTypeRole);
        typeMenu.add(filterTypeInline);
        typeMenu.add(filterTypeDevtools);
        typeMenu.add(filterTypeEndpoint);
        typeMenu.add(filterTypeDomXss);
        typeMenu.add(filterTypePostMessage);
        typeMenu.add(filterTypeStorage);
        typeMenu.add(filterTypeSourceMap);
        typeMenu.add(filterTypeRuntimeNetwork);
        typeMenuButton.addActionListener(e ->
                typeMenu.show(typeMenuButton, 0, typeMenuButton.getHeight()));

        c.gridx = 5; c.gridy = 0; c.weightx = 0.5;
        controls.add(typeMenuButton, c);

        c.gridx = 6; c.gridy = 0; c.weightx = 0;
        controls.add(new JLabel("Severity:"), c);

        severityMenu.add(filterHigh);
        severityMenu.add(filterMedium);
        severityMenu.add(filterLow);
        severityMenu.add(filterInfo);
        severityMenuButton.addActionListener(e ->
                severityMenu.show(severityMenuButton, 0, severityMenuButton.getHeight()));

        c.gridx = 7; c.gridy = 0; c.weightx = 0.0;
        controls.add(severityMenuButton, c);
        c.gridx = 8; c.gridy = 0; c.weightx = 0.0;
        controls.add(filterFalsePositive, c);

        JButton btnAnalyzeSiteMap = new JButton("Analyze Site Map (Quick)");
        JButton btnExport = new JButton("Export JSON…");
        JButton btnView = new JButton("View in Browser…");
        JButton btnPurge = new JButton("Clear Findings");
        JButton btnCopyToken = new JButton("Copy Bridge Token");

        c.gridx = 9; c.gridy = 0; c.weightx = 0;
        controls.add(btnAnalyzeSiteMap, c);
        c.gridx = 10; controls.add(btnExport, c);
        c.gridx = 11; controls.add(btnView, c);
        c.gridx = 12; controls.add(btnPurge, c);

        bridgeEndpointField.setEditable(false);
        bridgeTokenField.setEditable(false);

        c.gridx = 0; c.gridy = 1; c.weightx = 0;
        controls.add(new JLabel("Bridge:"), c);
        c.gridx = 1; c.gridy = 1; c.gridwidth = 4; c.weightx = 1;
        controls.add(bridgeEndpointField, c);
        c.gridx = 5; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        controls.add(new JLabel("Token:"), c);
        c.gridx = 6; c.gridy = 1; c.gridwidth = 4; c.weightx = 1;
        controls.add(bridgeTokenField, c);
        c.gridx = 10; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        controls.add(btnCopyToken, c);
        c.gridx = 11; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        controls.add(new JLabel("Scan limit:"), c);
        c.gridx = 12; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        controls.add(scanLimitSpinner, c);

        c.gridx = 0; c.gridy = 2; c.gridwidth = 3; c.weightx = 0;
        controls.add(exportVisibleOnly, c);
        c.gridx = 3; c.gridy = 2; c.gridwidth = 10; c.weightx = 1;
        controls.add(new JLabel("Host filter also scopes Site Map scans when set."), c);

        add(controls, BorderLayout.NORTH);

        // Table + detail
        table.setModel(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Row highlighting
        table.setDefaultRenderer(Object.class, new SeverityRowRenderer(tableModel));

        JScrollPane tableScroll = new JScrollPane(table);

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.6);
        add(split, BorderLayout.CENTER);

        // sorter
        sorter.setComparator(0, (a, b) -> severityRank((String) a) - severityRank((String) b));
        sorter.setComparator(1, Comparator.comparingInt(o -> Integer.parseInt(String.valueOf(o))));

        // default sort: Severity desc then Confidence desc
        sorter.setSortKeys(List.of(
                new SortKey(0, SortOrder.DESCENDING),
                new SortKey(1, SortOrder.DESCENDING)
        ));

        // listeners
        btnPurge.addActionListener(e -> clearFindings());
        btnExport.addActionListener(e -> exportJson());
        btnView.addActionListener(e -> showViewInBrowserDialog());
        btnAnalyzeSiteMap.addActionListener(e -> bg.submit(this::analyzeSiteMapInScope));
        btnCopyToken.addActionListener(e -> copyBridgeToken());
        registerRefreshActions(
                filterHigh,
                filterMedium,
                filterLow,
                filterInfo,
                filterFalsePositive,
                filterTypePassword,
                filterTypeHidden,
                filterTypeRole,
                filterTypeInline,
                filterTypeDevtools,
                filterTypeEndpoint,
                filterTypeDomXss,
                filterTypePostMessage,
                filterTypeStorage,
                filterTypeSourceMap,
                filterTypeRuntimeNetwork
        );
        DocumentListener refreshListener = new RefreshDocumentListener();
        filterHost.getDocument().addDocumentListener(refreshListener);
        filterSearch.getDocument().addDocumentListener(refreshListener);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                detailArea.setText("");
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            Finding f = tableModel.getAt(modelRow);
            if (f == null) {
                detailArea.setText("");
                return;
            }
            detailArea.setText(renderFinding(f));
            detailArea.setCaretPosition(0);
        });

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            private void maybeShowFindingMenu(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger() && !SwingUtilities.isRightMouseButton(e)) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                table.setRowSelectionInterval(viewRow, viewRow);
                showFindingContextMenu(e.getComponent(), e.getX(), e.getY());
            }

            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybeShowFindingMenu(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybeShowFindingMenu(e);
            }
        });

        refreshTable();
    }

    // Called by extension (context menu / site map analysis)
    public void addFindings(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) return;

        SwingUtilities.invokeLater(() -> {
            for (Finding f : findings) {
                findingsByKey.put(f.stableKey(), f);
            }

            // cap
            while (findingsByKey.size() > MAX_FINDINGS) {
                String firstKey = findingsByKey.keySet().iterator().next();
                findingsByKey.remove(firstKey);
            }

            refreshTable();
        });
    }

    private void analyzeSiteMapInScope() {
        try {
            List<HttpRequestResponse> items = api.siteMap().requestResponses();
            long inScopeCount = SiteMapScanRunner.countEligible(items, this::scanHostMatches);

            if (inScopeCount == 0) {
                api.logging().logToOutput("[ClientSideEye] Site Map analyze skipped. No in-scope items.");
                return;
            }

            if (inScopeCount > SITE_MAP_SCAN_WARN_THRESHOLD) {
                boolean proceed = confirmLargeSiteMapScan((int) Math.min(inScopeCount, Integer.MAX_VALUE));
                if (!proceed) {
                    api.logging().logToOutput("[ClientSideEye] Site Map analyze cancelled by user.");
                    return;
                }
            }

            int scanLimit = ((Number) scanLimitSpinner.getValue()).intValue();
            SiteMapScanSummary summary = SiteMapScanRunner.scan(items, this::scanHostMatches, scanLimit, this::addFindings);

            api.logging().logToOutput("[ClientSideEye] Site Map analyze complete. Pages analyzed: " + summary.analyzed() + " | Findings added: " + summary.added() + " | Skipped (non-analyzable): " + summary.skippedNonAnalyzable() + " | Skipped (scan cap): " + summary.skippedByCap() + " | Host scope: " + currentScanHostScope());
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Site Map analyze error: " + e);
        }
    }

    private void clearFindings() {
        findingsByKey.clear();
        falsePositiveKeys.clear();
        refreshTable();
        detailArea.setText("");
    }

    private void copyBridgeToken() {
        copyToClipboard(bridgeTokenField.getText());
        api.logging().logToOutput("[ClientSideEye] Copied browser bridge token to clipboard.");
    }

    private void registerRefreshActions(AbstractButton... buttons) {
        for (AbstractButton button : buttons) {
            button.addActionListener(e -> refreshTable());
        }
    }

    private Finding selectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        return tableModel.getAt(table.convertRowIndexToModel(viewRow));
    }

    private final class RefreshDocumentListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent e) {
            refreshTable();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            refreshTable();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            refreshTable();
        }
    }

    private void refreshTable() {
        String host = filterHost.getText().trim().toLowerCase(Locale.ROOT);
        String search = filterSearch.getText().trim().toLowerCase(Locale.ROOT);
        boolean showHigh = filterHigh.isSelected();
        boolean showMedium = filterMedium.isSelected();
        boolean showLow = filterLow.isSelected();
        boolean showInfo = filterInfo.isSelected();
        boolean showFalsePositives = filterFalsePositive.isSelected();
        Set<String> allowedTypes = selectedTypes();

        List<Finding> all = new ArrayList<>(findingsByKey.values());

        List<Finding> filtered = all.stream()
                .filter(f -> host.isEmpty() || f.host().toLowerCase(Locale.ROOT).contains(host))
                .filter(f -> search.isEmpty() || matchesSearch(f, search))
                .filter(f -> allowedTypes.contains(f.type()))
                .filter(f -> {
                    if (f.severity() == Severity.HIGH) return showHigh;
                    if (f.severity() == Severity.MEDIUM) return showMedium;
                    if (f.severity() == Severity.LOW) return showLow;
                    return showInfo;
                })
                .filter(f -> showFalsePositives || !isFalsePositive(f))
                .collect(Collectors.toList());

        tableModel.setRows(filtered);

        if (sorter != null) {
            sorter.setSortKeys(List.of(
                    new SortKey(0, SortOrder.DESCENDING),
                    new SortKey(1, SortOrder.DESCENDING)
            ));
        }
    }

    private void toggleFalsePositiveForSelection() {
        Finding f = selectedFinding();
        if (f == null) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), "Select a finding first.", "ClientSideEye", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String key = f.stableKey();
        if (falsePositiveKeys.contains(key)) {
            falsePositiveKeys.remove(key);
        } else {
            falsePositiveKeys.add(key);
        }

        refreshTable();
        detailArea.setText(renderFinding(f));
        detailArea.setCaretPosition(0);
    }

    private void showFindingContextMenu(Component invoker, int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem toggleFp = new JMenuItem("Toggle false positive");
        toggleFp.addActionListener(e -> toggleFalsePositiveForSelection());
        menu.add(toggleFp);
        menu.show(invoker, x, y);
    }

    public void setBridgeConnectionInfo(int port, String token) {
        SwingUtilities.invokeLater(() -> {
            String endpoint = port > 0 ? ("http://127.0.0.1:" + port) : "Bridge not started";
            bridgeEndpointField.setText(endpoint);
            bridgeTokenField.setText(token == null ? "" : token);
        });
    }


    private void exportJson() {
        try {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Export ClientSideEye JSON Report");
            chooser.setSelectedFile(new File("clientsideeye_report.json"));
            int res = chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
            if (res != JFileChooser.APPROVE_OPTION) return;

            File out = chooser.getSelectedFile();
            List<Finding> toExport = exportVisibleOnly.isSelected()
                    ? tableModel.rowsSnapshot()
                    : new ArrayList<>(findingsByKey.values());
            String json = JsonExporter.toJson(toExport, falsePositiveKeys);
            Files.writeString(out.toPath(), json);

            api.logging().logToOutput("[ClientSideEye] Exported: " + out.getAbsolutePath());
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Export failed: " + e);
        }
    }

    private void showViewInBrowserDialog() {
        Finding f = selectedFinding();
        if (f == null) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), "Select a finding first.", "ClientSideEye", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ViewInBrowserDialog.show(api, f, ClientSideEyeTab::copyToClipboard);
    }

    // --- helpers ---

    private static void copyToClipboard(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s == null ? "" : s), null);
    }

    private static int severityRank(String s) {
        if (s == null) return 0;
        return switch (s) {
            case "HIGH" -> 4;
            case "MEDIUM" -> 3;
            case "LOW" -> 2;
            case "INFO" -> 1;
            default -> 0;
        };
    }

    private boolean confirmLargeSiteMapScan(int inScopeCount) {
        int scanLimit = ((Number) scanLimitSpinner.getValue()).intValue();
        final int[] decision = new int[]{JOptionPane.CLOSED_OPTION};
        Runnable prompt = () -> decision[0] = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "ClientSideEye found " + inScopeCount + " in-scope Site Map items.\n"
                        + "To stay responsive, this run will analyze at most " + scanLimit + " HTML-like responses.\n"
                        + "Current host scope: " + currentScanHostScope() + "\n\n"
                        + "Continue?",
                "Large Site Map Scan",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (SwingUtilities.isEventDispatchThread()) {
            prompt.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(prompt);
            } catch (Exception e) {
                api.logging().logToError("[ClientSideEye] Large scan prompt error: " + e);
                return false;
            }
        }

        return decision[0] == JOptionPane.OK_OPTION;
    }

    private boolean matchesSearch(Finding finding, String search) {
        return finding.title().toLowerCase(Locale.ROOT).contains(search)
                || finding.url().toLowerCase(Locale.ROOT).contains(search)
                || finding.evidence().toLowerCase(Locale.ROOT).contains(search)
                || finding.identity().toLowerCase(Locale.ROOT).contains(search)
                || finding.type().toLowerCase(Locale.ROOT).contains(search)
                || findingArea(finding).toLowerCase(Locale.ROOT).contains(search);
    }

    private boolean scanHostMatches(String url) {
        String hostScope = filterHost.getText().trim().toLowerCase(Locale.ROOT);
        if (hostScope.isEmpty()) return true;
        try {
            String host = new java.net.URI(url).getHost();
            return host != null && host.toLowerCase(Locale.ROOT).contains(hostScope);
        } catch (Exception e) {
            return false;
        }
    }

    private String currentScanHostScope() {
        String hostScope = filterHost.getText().trim();
        return hostScope.isEmpty() ? "(all in-scope hosts)" : hostScope;
    }

    private String findingArea(Finding finding) {
        return FindingAreaResolver.resolve(finding);
    }

    private String renderFinding(Finding f) {
        return ""
                + "Severity: " + f.severity() + " (" + f.confidence() + ")\n"
                + "False positive: " + (isFalsePositive(f) ? "yes" : "no") + "\n"
                + "Type: " + f.type() + "\n"
                + "Area: " + findingArea(f) + "\n"
                + "URL: " + f.url() + "\n"
                + "Host: " + f.host() + "\n"
                + "Title: " + f.title() + "\n"
                + "First seen: " + f.firstSeen() + "\n"
                + "\n"
                + "Summary:\n" + f.summary() + "\n"
                + "\n"
                + "Evidence:\n" + f.evidence() + "\n"
                + "\n"
                + "Recommendation:\n" + f.recommendation() + "\n";
    }

    private boolean isFalsePositive(Finding f) {
        return f != null && falsePositiveKeys.contains(f.stableKey());
    }

    private Set<String> selectedTypes() {
        Set<String> types = new HashSet<>();
        if (filterTypePassword.isSelected()) types.add(FindingType.PASSWORD_VALUE_IN_DOM.name());
        if (filterTypeHidden.isSelected()) types.add(FindingType.HIDDEN_OR_DISABLED_CONTROL.name());
        if (filterTypeRole.isSelected()) types.add(FindingType.ROLE_PERMISSION_HINT.name());
        if (filterTypeInline.isSelected()) types.add(FindingType.INLINE_SCRIPT_SECRETISH.name());
        if (filterTypeDevtools.isSelected()) types.add(FindingType.DEVTOOLS_BLOCKING.name());
        if (filterTypeEndpoint.isSelected()) types.add(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name());
        if (filterTypeDomXss.isSelected()) types.add(FindingType.DOM_XSS_SINK.name());
        if (filterTypePostMessage.isSelected()) types.add(FindingType.POSTMESSAGE_HANDLER.name());
        if (filterTypeStorage.isSelected()) types.add(FindingType.STORAGE_TOKEN.name());
        if (filterTypeSourceMap.isSelected()) types.add(FindingType.SOURCE_MAP_DISCLOSURE.name());
        if (filterTypeRuntimeNetwork.isSelected()) types.add(FindingType.RUNTIME_NETWORK_REFERENCE.name());
        return types;
    }

}
