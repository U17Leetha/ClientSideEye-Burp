package com.clientsideeye.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.core.JsonExporter;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter.SortKey;
import javax.swing.SortOrder;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
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
    private final JPasswordField bridgeTokenField = new JPasswordField();
    private final JToggleButton showTokenButton = new JToggleButton("Show");
    private final JSpinner scanLimitSpinner = new JSpinner(new SpinnerNumberModel(SITE_MAP_SCAN_HARD_CAP, 100, 10000, 100));
    private final JCheckBox exportVisibleOnly = new JCheckBox("Export visible rows only", true);

    private final FindingTypeFilterMenu typeFilterMenu = new FindingTypeFilterMenu();

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

        JButton analyzeSiteMapButton = new JButton("Analyze Site Map (Quick)");
        JButton exportButton = new JButton("Export JSON…");
        JButton viewButton = new JButton("View in Browser…");
        JButton clearButton = new JButton("Clear Findings");
        JButton copyTokenButton = new JButton("Copy Bridge Token");

        configureMenus();
        configureTable();
        add(buildControlsPanel(analyzeSiteMapButton, exportButton, viewButton, clearButton, copyTokenButton), BorderLayout.NORTH);
        add(buildContentSplitPane(), BorderLayout.CENTER);
        bindListeners(analyzeSiteMapButton, exportButton, viewButton, clearButton, copyTokenButton);
        refreshTable();
    }

    private void configureMenus() {
        configurePopupMenu(severityMenu, severityMenuButton, filterHigh, filterMedium, filterLow, filterInfo);
    }

    private void configurePopupMenu(JPopupMenu menu, JButton button, JMenuItem... items) {
        for (JMenuItem item : items) {
            menu.add(item);
        }
        button.addActionListener(e -> menu.show(button, 0, button.getHeight()));
    }

    private JPanel buildControlsPanel(
        JButton analyzeSiteMapButton,
        JButton exportButton,
        JButton viewButton,
        JButton clearButton,
        JButton copyTokenButton
    ) {
        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints c = defaultConstraints();

        addControlRowOne(controls, c, analyzeSiteMapButton, exportButton, viewButton, clearButton);
        addControlRowTwo(controls, c, copyTokenButton);
        addControlRowThree(controls, c);
        return controls;
    }

    private GridBagConstraints defaultConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        return c;
    }

    private void addControlRowOne(
        JPanel controls,
        GridBagConstraints c,
        JButton analyzeSiteMapButton,
        JButton exportButton,
        JButton viewButton,
        JButton clearButton
    ) {
        addControl(controls, c, 0, 0, 0, 1, new JLabel("Host filter:"));
        addControl(controls, c, 1, 0, 1, 1, filterHost);
        addControl(controls, c, 2, 0, 0, 1, new JLabel("Search:"));
        addControl(controls, c, 3, 0, 1, 1, filterSearch);
        addControl(controls, c, 4, 0, 0, 1, new JLabel("Type:"));
        addControl(controls, c, 5, 0, 0.5, 1, typeFilterMenu.button());
        addControl(controls, c, 6, 0, 0, 1, new JLabel("Severity:"));
        addControl(controls, c, 7, 0, 0, 1, severityMenuButton);
        addControl(controls, c, 8, 0, 0, 1, filterFalsePositive);
        addControl(controls, c, 9, 0, 0, 1, analyzeSiteMapButton);
        addControl(controls, c, 10, 0, 0, 1, exportButton);
        addControl(controls, c, 11, 0, 0, 1, viewButton);
        addControl(controls, c, 12, 0, 0, 1, clearButton);
    }

    private void addControlRowTwo(JPanel controls, GridBagConstraints c, JButton copyTokenButton) {
        bridgeEndpointField.setEditable(false);
        bridgeTokenField.setEditable(false);
        char defaultEchoChar = bridgeTokenField.getEchoChar();
        showTokenButton.addActionListener(e -> {
            boolean show = showTokenButton.isSelected();
            bridgeTokenField.setEchoChar(show ? (char) 0 : defaultEchoChar);
            showTokenButton.setText(show ? "Hide" : "Show");
        });

        addControl(controls, c, 0, 1, 0, 1, new JLabel("Bridge:"));
        addControl(controls, c, 1, 1, 1, 4, bridgeEndpointField);
        addControl(controls, c, 5, 1, 0, 1, new JLabel("Token:"));
        addControl(controls, c, 6, 1, 1, 3, bridgeTokenField);
        addControl(controls, c, 9, 1, 0, 1, showTokenButton);
        addControl(controls, c, 10, 1, 0, 1, copyTokenButton);
        addControl(controls, c, 11, 1, 0, 1, new JLabel("Scan limit:"));
        addControl(controls, c, 12, 1, 0, 1, scanLimitSpinner);
    }

    private void addControlRowThree(JPanel controls, GridBagConstraints c) {
        addControl(controls, c, 0, 2, 0, 3, exportVisibleOnly);
        addControl(controls, c, 3, 2, 1, 10, new JLabel("Host filter also scopes Site Map scans when set."));
    }

    private void addControl(
        JPanel panel,
        GridBagConstraints c,
        int x,
        int y,
        double weightX,
        int gridWidth,
        Component component
    ) {
        c.gridx = x;
        c.gridy = y;
        c.weightx = weightX;
        c.gridwidth = gridWidth;
        panel.add(component, c);
    }

    private JSplitPane buildContentSplitPane() {
        JScrollPane tableScroll = new JScrollPane(table);
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.6);
        return split;
    }

    private void configureTable() {
        table.setModel(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setDefaultRenderer(Object.class, new SeverityRowRenderer(tableModel));
        sorter.setComparator(0, (a, b) -> severityRank((String) a) - severityRank((String) b));
        sorter.setComparator(1, Comparator.comparingInt(o -> Integer.parseInt(String.valueOf(o))));
        sorter.setSortKeys(defaultSortKeys());
    }

    private List<SortKey> defaultSortKeys() {
        return List.of(new SortKey(0, SortOrder.DESCENDING), new SortKey(1, SortOrder.DESCENDING));
    }

    private void bindListeners(
        JButton analyzeSiteMapButton,
        JButton exportButton,
        JButton viewButton,
        JButton clearButton,
        JButton copyTokenButton
    ) {
        clearButton.addActionListener(e -> clearFindings());
        exportButton.addActionListener(e -> exportJson());
        viewButton.addActionListener(e -> showViewInBrowserDialog());
        analyzeSiteMapButton.addActionListener(e -> bg.submit(this::analyzeSiteMapInScope));
        copyTokenButton.addActionListener(e -> copyBridgeToken());
        registerRefreshActions(
            filterHigh, filterMedium, filterLow, filterInfo, filterFalsePositive
        );
        typeFilterMenu.addChangeListener(e -> refreshTable());
        DocumentListener refreshListener = new RefreshDocumentListener();
        filterHost.getDocument().addDocumentListener(refreshListener);
        filterSearch.getDocument().addDocumentListener(refreshListener);
        table.getSelectionModel().addListSelectionListener(e -> onFindingSelectionChanged(e.getValueIsAdjusting()));
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybeShowFindingMenu(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybeShowFindingMenu(e);
            }
        });
    }

    private void onFindingSelectionChanged(boolean adjusting) {
        if (adjusting) {
            return;
        }
        Finding finding = selectedFinding();
        if (finding == null) {
            detailArea.setText("");
            return;
        }
        detailArea.setText(FindingDetailRenderer.render(finding, isFalsePositive(finding), findingArea(finding)));
        detailArea.setCaretPosition(0);
    }

    private void maybeShowFindingMenu(java.awt.event.MouseEvent e) {
        if (!e.isPopupTrigger() && !SwingUtilities.isRightMouseButton(e)) {
            return;
        }
        int viewRow = table.rowAtPoint(e.getPoint());
        if (viewRow < 0) {
            return;
        }
        table.setRowSelectionInterval(viewRow, viewRow);
        showFindingContextMenu(e.getComponent(), e.getX(), e.getY());
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
        copyToClipboard(new String(bridgeTokenField.getPassword()));
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
        FindingFilterState filters = currentFilters();
        List<Finding> filtered = new ArrayList<>(findingsByKey.values()).stream()
            .filter(finding -> filters.matches(finding, isFalsePositive(finding), findingArea(finding)))
            .collect(Collectors.toList());
        tableModel.setRows(filtered);
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
        detailArea.setText(FindingDetailRenderer.render(f, isFalsePositive(f), findingArea(f)));
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
        ClipboardHelper.copy(s);
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
                        + "To stay responsive, this run will analyze at most " + scanLimit + " analyzable responses.\n"
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

    private FindingFilterState currentFilters() {
        return new FindingFilterState(
            filterHost.getText().trim().toLowerCase(Locale.ROOT),
            filterSearch.getText().trim().toLowerCase(Locale.ROOT),
            filterHigh.isSelected(),
            filterMedium.isSelected(),
            filterLow.isSelected(),
            filterInfo.isSelected(),
            filterFalsePositive.isSelected(),
            typeFilterMenu.selectedTypes()
        );
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

    private boolean isFalsePositive(Finding f) {
        return f != null && falsePositiveKeys.contains(f.stableKey());
    }


}