package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

final class FindingsTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
        "Severity", "Confidence", "FP", "Type", "Area", "Host", "Title", "URL"
    };

    private final Predicate<Finding> falsePositiveChecker;
    private final Function<Finding, String> areaResolver;
    private List<Finding> rows = List.of();

    FindingsTableModel(Predicate<Finding> falsePositiveChecker, Function<Finding, String> areaResolver) {
        this.falsePositiveChecker = falsePositiveChecker;
        this.areaResolver = areaResolver;
    }

    void setRows(List<Finding> rows) {
        this.rows = rows == null ? List.of() : List.copyOf(rows);
        fireTableDataChanged();
    }

    List<Finding> rowsSnapshot() {
        return new ArrayList<>(rows);
    }

    Finding getAt(int row) {
        if (row < 0 || row >= rows.size()) {
            return null;
        }
        return rows.get(row);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Finding finding = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> finding.severity().name();
            case 1 -> String.valueOf(finding.confidence());
            case 2 -> falsePositiveChecker.test(finding) ? "yes" : "";
            case 3 -> finding.type();
            case 4 -> areaResolver.apply(finding);
            case 5 -> finding.host();
            case 6 -> finding.title();
            case 7 -> finding.url();
            default -> "";
        };
    }
}
