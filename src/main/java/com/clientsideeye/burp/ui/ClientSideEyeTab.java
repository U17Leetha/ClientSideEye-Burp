package com.clientsideeye.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.swing.SwingUtils;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.JsonExporter;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

public class ClientSideEyeTab extends JPanel {

    private final MontoyaApi api;
    private final ExecutorService bg;

    private static final int MAX_FINDINGS = 5000;

    // Dedupe and cap memory
    private final LinkedHashMap<String, Finding> findingsByKey = new LinkedHashMap<>();

    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table = new JTable(tableModel);

    private final JTextArea detailArea = new JTextArea();
    private final JTextField filterHost = new JTextField();
    private final JComboBox<String> filterType = new JComboBox<>(new String[]{
            "All", "PASSWORD_VALUE_IN_DOM", "HIDDEN_OR_DISABLED_CONTROL", "ROLE_PERMISSION_HINT", "INLINE_SCRIPT_SECRETISH"
    });

    public ClientSideEyeTab(MontoyaApi api, ExecutorService bg) {
        super(new BorderLayout(10, 10));
        this.api = api;
        this.bg = bg;

        setBorder(BorderFactory.createEmptyBorder(10,10,10,10));

        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4,4,4,4);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx=0; c.gridy=0; c.weightx=0;
        controls.add(new JLabel("Host filter:"), c);

        c.gridx=1; c.gridy=0; c.weightx=1;
        controls.add(filterHost, c);

        c.gridx=2; c.gridy=0; c.weightx=0;
        controls.add(new JLabel("Type:"), c);

        c.gridx=3; c.gridy=0; c.weightx=0.5;
        controls.add(filterType, c);

        JButton btnApply = new JButton("Apply");
        JButton btnClear = new JButton("Clear");
        JButton btnExport = new JButton("Export JSON…");
        JButton btnCopy = new JButton("Copy JSON");
        JButton btnPurge = new JButton("Clear Findings");

        c.gridx=4; c.gridy=0; c.weightx=0;
        controls.add(btnApply, c);
        c.gridx=5; controls.add(btnClear, c);
        c.gridx=6; controls.add(btnExport, c);
        c.gridx=7; controls.add(btnCopy, c);
        c.gridx=8; controls.add(btnPurge, c);

        add(controls, BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tableScroll = new JScrollPane(table);

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.65);
        add(split, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            int r = table.getSelectedRow();
            if (r < 0) return;
            Finding f = tableModel.getAt(r);
            detailArea.setText(formatDetail(f));
            detailArea.setCaretPosition(0);
        });

        btnApply.addActionListener(e -> refreshView());
        btnClear.addActionListener(e -> {
            filterHost.setText("");
            filterType.setSelectedIndex(0);
            refreshView();
        });

        btnPurge.addActionListener(e -> {
            synchronized (findingsByKey) { findingsByKey.clear(); }
            refreshView();
            detailArea.setText("");
        });

        btnCopy.addActionListener(e -> runBg(() -> {
            String json = JsonExporter.export(snapshotFiltered());
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(json), null);
            uiInfo("JSON copied to clipboard.");
        }));

        btnExport.addActionListener(e -> {
            Frame parent = burpFrame();
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("clientsideeye-burp-findings.json"));

            int res = fc.showSaveDialog(parent);
            if (res != JFileChooser.APPROVE_OPTION) return;

            File out = fc.getSelectedFile();
            runBg(() -> {
                String json = JsonExporter.export(snapshotFiltered());
                Files.writeString(out.toPath(), json);
                uiInfo("Exported: " + out.getAbsolutePath());
            });
        });

        refreshView();
    }

    public void onUnload() {
        // hook for future resources
    }

    public void addFindings(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) return;

        synchronized (findingsByKey) {
            for (Finding f : findings) {
                findingsByKey.put(dedupeKey(f), f);
            }
            while (findingsByKey.size() > MAX_FINDINGS) {
                Iterator<String> it = findingsByKey.keySet().iterator();
                if (!it.hasNext()) break;
                it.next();
                it.remove();
            }
        }
        refreshView();
    }

    private String dedupeKey(Finding f) {
        String preview = "";
        if (f.meta != null && f.meta.containsKey("preview")) preview = String.valueOf(f.meta.get("preview"));
        return (safe(f.host) + "|" + safe(f.url) + "|" + f.type.name() + "|" + safe(preview) + "|" + safe(f.evidence))
                .toLowerCase(Locale.ROOT);
    }

    private void refreshView() {
        tableModel.setRows(snapshotFiltered());
    }

    private List<Finding> snapshotFiltered() {
        String host = filterHost.getText().trim().toLowerCase(Locale.ROOT);
        String type = (String) filterType.getSelectedItem();

        List<Finding> all;
        synchronized (findingsByKey) {
            all = new ArrayList<>(findingsByKey.values());
        }

        return all.stream()
                .filter(f -> host.isEmpty() || (f.host != null && f.host.toLowerCase(Locale.ROOT).contains(host)))
                .filter(f -> "All".equals(type) || f.type.name().equals(type))
                .sorted(Comparator.comparing((Finding f) -> f.time).reversed())
                .collect(Collectors.toList());
    }

    private String formatDetail(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("Title: ").append(f.title).append("\n");
        sb.append("Type: ").append(f.type).append("\n");
        sb.append("Severity: ").append(f.severity).append("\n");
        sb.append("Confidence: ").append(f.confidence).append("\n");
        sb.append("Time: ").append(f.time).append("\n");
        sb.append("Host: ").append(f.host).append("\n");
        sb.append("URL: ").append(f.url).append("\n\n");
        sb.append("Evidence:\n").append(f.evidence).append("\n\n");
        sb.append("Meta:\n");
        if (f.meta == null || f.meta.isEmpty()) sb.append("(none)\n");
        else for (var e : f.meta.entrySet()) sb.append("- ").append(e.getKey()).append(": ").append(String.valueOf(e.getValue())).append("\n");
        return sb.toString();
    }

    private Frame burpFrame() {
        try {
            SwingUtils su = api.userInterface().swingUtils();
            return su.suiteFrame();
        } catch (Exception e) {
            return null;
        }
    }

    private void uiInfo(String msg) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(burpFrame(), msg, "ClientSideEye", JOptionPane.INFORMATION_MESSAGE)
        );
    }

    private void uiError(String msg) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(burpFrame(), msg, "ClientSideEye", JOptionPane.ERROR_MESSAGE)
        );
    }

    private void runBg(Runnable r) {
        bg.submit(() -> {
            try {
                r.run();
            } catch (Exception e) {
                api.logging().logToError("ClientSideEye background error: " + e);
                uiError("Operation failed: " + e.getMessage());
            }
        });
    }

    private static String safe(String s) { return s == null ? "" : s; }

    private static class FindingsTableModel extends AbstractTableModel {
        private final String[] cols = {"Time", "Severity", "Type", "Host", "Title"};
        private List<Finding> rows = new ArrayList<>();

        public void setRows(List<Finding> rows) {
            this.rows = rows == null ? new ArrayList<>() : rows;
            fireTableDataChanged();
        }

        public Finding getAt(int row) { return rows.get(row); }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int col) { return cols[col]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Finding f = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.time.toString();
                case 1 -> f.severity;
                case 2 -> f.type.name();
                case 3 -> f.host;
                case 4 -> f.title;
                default -> "";
            };
        }
    }
}
