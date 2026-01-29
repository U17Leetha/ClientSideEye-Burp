package com.clientsideeye.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.core.HtmlAnalyzer;
import com.clientsideeye.burp.core.JsonExporter;

import javax.swing.*;
import javax.swing.RowSorter.SortKey;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.clientsideeye.burp.core.Finding.Severity;

public class ClientSideEyeTab extends JPanel {

    private final MontoyaApi api;
    private final ExecutorService bg;

    private static final int MAX_FINDINGS = 5000;

    // Dedupe by stable key -> Finding (LinkedHashMap preserves insertion order)
    private final LinkedHashMap<String, Finding> findingsByKey = new LinkedHashMap<>();

    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table = new JTable(tableModel);
    private TableRowSorter<FindingsTableModel> sorter;

    private final JTextArea detailArea = new JTextArea();
    private final JTextField filterHost = new JTextField();

    private final JComboBox<String> filterType = new JComboBox<>(new String[]{
            "All",
            FindingType.PASSWORD_VALUE_IN_DOM.name(),
            FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
            FindingType.ROLE_PERMISSION_HINT.name(),
            FindingType.INLINE_SCRIPT_SECRETISH.name()
    });

    private final JCheckBox filterHigh = new JCheckBox("High", true);
    private final JCheckBox filterMedium = new JCheckBox("Medium", true);
    private final JCheckBox filterLow = new JCheckBox("Low", true);
    private final JCheckBox filterInfo = new JCheckBox("Informational", true);

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
        controls.add(new JLabel("Type:"), c);

        c.gridx = 3; c.gridy = 0; c.weightx = 0.5;
        controls.add(filterType, c);

        c.gridx = 4; c.gridy = 0; c.weightx = 0;
        controls.add(new JLabel("Severity:"), c);

        c.gridx = 5; c.gridy = 0; c.weightx = 0.0;
        controls.add(filterHigh, c);
        c.gridx = 6; c.gridy = 0; c.weightx = 0.0;
        controls.add(filterMedium, c);
        c.gridx = 7; c.gridy = 0; c.weightx = 0.0;
        controls.add(filterLow, c);
        c.gridx = 8; c.gridy = 0; c.weightx = 0.0;
        controls.add(filterInfo, c);

        JButton btnApply = new JButton("Apply");
        JButton btnClear = new JButton("Clear");
        JButton btnAnalyzeSiteMap = new JButton("Analyze Site Map (in-scope)");
        JButton btnExport = new JButton("Export JSON…");
        JButton btnView = new JButton("View in Browser…");
        JButton btnPurge = new JButton("Clear Findings");

        c.gridx = 9; c.gridy = 0; c.weightx = 0;
        controls.add(btnApply, c);
        c.gridx = 10; controls.add(btnClear, c);
        c.gridx = 11; controls.add(btnAnalyzeSiteMap, c);
        c.gridx = 12; controls.add(btnExport, c);
        c.gridx = 13; controls.add(btnView, c);
        c.gridx = 14; controls.add(btnPurge, c);

        add(controls, BorderLayout.NORTH);

        // Table + detail
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

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
        sorter = (TableRowSorter<FindingsTableModel>) table.getRowSorter();
        sorter.setComparator(0, (a, b) -> severityRank((String) a) - severityRank((String) b));
        sorter.setComparator(1, Comparator.comparingInt(o -> Integer.parseInt(String.valueOf(o))));

        // default sort: Severity desc then Confidence desc
        sorter.setSortKeys(List.of(
                new SortKey(0, SortOrder.DESCENDING),
                new SortKey(1, SortOrder.DESCENDING)
        ));

        // listeners
        btnApply.addActionListener(e -> refreshTable());
        btnClear.addActionListener(e -> {
            filterHost.setText("");
            filterType.setSelectedIndex(0);
            filterHigh.setSelected(true);
            filterMedium.setSelected(true);
            filterLow.setSelected(true);
            filterInfo.setSelected(true);
            refreshTable();
        });

        btnPurge.addActionListener(e -> {
            findingsByKey.clear();
            refreshTable();
            detailArea.setText("");
        });

        btnExport.addActionListener(e -> exportJson());
        btnView.addActionListener(e -> showViewInBrowserDialog());
        btnAnalyzeSiteMap.addActionListener(e -> bg.submit(this::analyzeSiteMapInScope));

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

            int analyzed = 0;
            int added = 0;

            for (HttpRequestResponse rr : items) {
                if (rr == null || rr.request() == null || rr.response() == null) continue;
                if (!rr.request().isInScope()) continue;

                String body = rr.response().bodyToString();
                if (body == null || body.isBlank()) continue;

                String url = rr.request().url();
                List<Finding> f = HtmlAnalyzer.analyzeHtml(url, body);
                analyzed++;
                if (!f.isEmpty()) {
                    added += f.size();
                    addFindings(f);
                }
            }

            api.logging().logToOutput("[ClientSideEye] Site Map analyze complete. Pages analyzed: " + analyzed + " | Findings added: " + added);
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Site Map analyze error: " + e);
        }
    }

    private void refreshTable() {
        String host = filterHost.getText().trim().toLowerCase(Locale.ROOT);
        String type = String.valueOf(filterType.getSelectedItem());
        boolean showHigh = filterHigh.isSelected();
        boolean showMedium = filterMedium.isSelected();
        boolean showLow = filterLow.isSelected();
        boolean showInfo = filterInfo.isSelected();

        List<Finding> all = new ArrayList<>(findingsByKey.values());

        List<Finding> filtered = all.stream()
                .filter(f -> host.isEmpty() || f.host().toLowerCase(Locale.ROOT).contains(host))
                .filter(f -> "All".equals(type) || f.type().equals(type))
                .filter(f -> {
                    if (f.severity() == Severity.HIGH) return showHigh;
                    if (f.severity() == Severity.MEDIUM) return showMedium;
                    if (f.severity() == Severity.LOW) return showLow;
                    return showInfo;
                })
                .collect(Collectors.toList());

        tableModel.setRows(filtered);

        if (sorter != null) {
            sorter.setSortKeys(List.of(
                    new SortKey(0, SortOrder.DESCENDING),
                    new SortKey(1, SortOrder.DESCENDING)
            ));
        }
    }

    private void exportJson() {
        try {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Export ClientSideEye JSON Report");
            chooser.setSelectedFile(new File("clientsideeye_report.json"));
            int res = chooser.showSaveDialog(this);
            if (res != JFileChooser.APPROVE_OPTION) return;

            File out = chooser.getSelectedFile();
            String json = JsonExporter.toJson(new ArrayList<>(findingsByKey.values()));
            Files.writeString(out.toPath(), json);

            api.logging().logToOutput("[ClientSideEye] Exported: " + out.getAbsolutePath());
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Export failed: " + e);
        }
    }

    private void showViewInBrowserDialog() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a finding first.", "ClientSideEye", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        Finding f = tableModel.getAt(modelRow);
        if (f == null) return;

        String url = f.url();
        String evidence = f.evidence();

        String id = extractAttr(evidence, "id");
        String name = extractAttr(evidence, "name");
        String href = extractAttr(evidence, "href");

        DefaultComboBoxModel<String> hintModel = new DefaultComboBoxModel<>();

        if (!id.isBlank()) {
            hintModel.addElement("Console (recommended): inspect(document.querySelector('#" + id + "'))");
            hintModel.addElement("CSS selector: #" + id);
            hintModel.addElement("Firefox Inspector text: id=\"" + id + "\"");
            hintModel.addElement("Firefox Inspector text: " + id);
        }

        if (!name.isBlank()) {
            hintModel.addElement("CSS selector: [name=\"" + name + "\"]");
            hintModel.addElement("Firefox Inspector text: name=\"" + name + "\"");
        }

        if (!href.isBlank()) {
            hintModel.addElement("Console: inspect(document.querySelector('a[href=\"" + href + "\"]'))");
            hintModel.addElement("CSS selector: a[href=\"" + href + "\"]");
            hintModel.addElement("Firefox Inspector text: href=\"" + href + "\"");
        }

        // Always provide a “findable” snippet
        String findTerm = bestEvidenceSearchTerm(evidence);
        if (!findTerm.isBlank()) {
            hintModel.addElement("Search term (markup): " + findTerm);
        }

        if (hintModel.getSize() == 0) {
            hintModel.addElement("Search term (markup): " + (evidence == null ? "" : evidence.replaceAll("\\s+", " ").trim()));
        }

        JComboBox<String> hintCombo = new JComboBox<>(hintModel);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "View in Browser", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;

        JTextField urlField = new JTextField(url);
        urlField.setEditable(false);

        JButton copyUrlBtn = new JButton("Copy URL");
        copyUrlBtn.addActionListener(e -> {
            copyToClipboard(url);
            api.logging().logToOutput("[ClientSideEye] Copied URL to clipboard.");
        });

        JButton copyHintBtn = new JButton("Copy selected Find Hint");
        copyHintBtn.addActionListener(e -> {
            String item = String.valueOf(hintCombo.getSelectedItem());
            if (item == null) item = "";
            String hint = item;
            int idx = item.indexOf(": ");
            if (idx >= 0 && idx + 2 < item.length()) hint = item.substring(idx + 2);
            copyToClipboard(hint);
            api.logging().logToOutput("[ClientSideEye] Copied find hint to clipboard: " + hint);
        });

        c.gridx = 0; c.gridy = 0; c.weightx = 0;
        top.add(new JLabel("URL:"), c);
        c.gridx = 1; c.gridy = 0; c.weightx = 1;
        top.add(urlField, c);
        c.gridx = 2; c.gridy = 0; c.weightx = 0;
        top.add(copyUrlBtn, c);

        c.gridx = 0; c.gridy = 1; c.weightx = 0;
        top.add(new JLabel("Find Hint:"), c);
        c.gridx = 1; c.gridy = 1; c.weightx = 1;
        top.add(hintCombo, c);
        c.gridx = 2; c.gridy = 1; c.weightx = 0;
        top.add(copyHintBtn, c);

        dialog.add(top, BorderLayout.NORTH);

        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setText(
                "DevTools usage (Firefox/Chrome):\n" +
                        "1) Open the page in your browser\n" +
                        "2) Use ONE Find Hint:\n" +
                        "   - Firefox easiest: paste a Console hint in DevTools Console\n" +
                        "   - Or in Inspector markup panel, Cmd/Ctrl+F and use the Firefox text hints\n\n" +
                        "Evidence snippet:\n" + evidence + "\n"
        );
        ta.setCaretPosition(0);

        JScrollPane sp = new JScrollPane(ta);
        sp.setPreferredSize(new Dimension(900, 420));
        dialog.add(sp, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        bottom.add(closeBtn);
        dialog.add(bottom, BorderLayout.SOUTH);

        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    // --- helpers ---

    private static void copyToClipboard(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s == null ? "" : s), null);
    }

    private static String extractAttr(String text, String attr) {
        if (text == null) return "";
        Pattern p = Pattern.compile("(?i)\\b" + Pattern.quote(attr) + "\\s*=\\s*([\"'])(.*?)\\1");
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(2);
        return "";
    }

    private static String bestEvidenceSearchTerm(String evidence) {
        if (evidence == null) return "";
        String href = extractAttr(evidence, "href");
        if (!href.isBlank()) return "href=\"" + href + "\"";

        String src = extractAttr(evidence, "src");
        if (!src.isBlank()) return "src=\"" + src + "\"";

        String action = extractAttr(evidence, "action");
        if (!action.isBlank()) return "action=\"" + action + "\"";

        String s = evidence.replaceAll("\\s+", " ").trim();
        if (s.length() > 80) s = s.substring(0, 80);
        return s;
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

    private String renderFinding(Finding f) {
        return ""
                + "Severity: " + f.severity() + " (" + f.confidence() + ")\n"
                + "Type: " + f.type() + "\n"
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

    // -------------------------
    // Table model
    // -------------------------
    private static class FindingsTableModel extends AbstractTableModel {

        private final String[] cols = new String[]{"Severity", "Confidence", "Type", "Host", "Title", "URL"};
        private List<Finding> rows = List.of();

        void setRows(List<Finding> rows) {
            this.rows = rows == null ? List.of() : rows;
            fireTableDataChanged();
        }

        Finding getAt(int row) {
            if (row < 0 || row >= rows.size()) return null;
            return rows.get(row);
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int column) { return cols[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Finding f = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.severity().name();
                case 1 -> String.valueOf(f.confidence());
                case 2 -> f.type();
                case 3 -> f.host();
                case 4 -> f.title();
                case 5 -> f.url();
                default -> "";
            };
        }
    }

    // Row renderer to highlight risk
    private static class SeverityRowRenderer extends DefaultTableCellRenderer {
        private final FindingsTableModel model;

        SeverityRowRenderer(FindingsTableModel model) {
            this.model = model;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (isSelected) return c;

            int modelRow = table.convertRowIndexToModel(row);
            Finding f = model.getAt(modelRow);
            if (f == null) return c;

            Color bg = switch (f.severity()) {
                case HIGH -> new Color(255, 230, 230);
                case MEDIUM -> new Color(255, 242, 220);
                case LOW -> new Color(240, 240, 240);
                case INFO -> new Color(248, 248, 248);
            };

            c.setBackground(bg);
            return c;
        }
    }
}
