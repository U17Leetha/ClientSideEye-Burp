package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.Finding.Severity;

import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;

final class SeverityRowRenderer extends DefaultTableCellRenderer {
    private final FindingsTableModel model;

    SeverityRowRenderer(FindingsTableModel model) {
        this.model = model;
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table,
        Object value,
        boolean isSelected,
        boolean hasFocus,
        int row,
        int column
    ) {
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (isSelected) {
            return component;
        }

        int modelRow = table.convertRowIndexToModel(row);
        Finding finding = model.getAt(modelRow);
        if (finding == null) {
            return component;
        }

        component.setBackground(severityBackground(finding.severity()));
        component.setForeground(table.getForeground());
        return component;
    }

    private static Color severityBackground(Severity severity) {
        Color base = UIManager.getColor("Table.background");
        if (base == null) {
            base = Color.WHITE;
        }
        Color accent = UIManager.getColor("Table.selectionBackground");
        if (accent == null) {
            accent = base.darker();
        }

        double blend = switch (severity) {
            case HIGH -> 0.35;
            case MEDIUM -> 0.25;
            case LOW -> 0.12;
            case INFO -> 0.06;
        };
        return blend(base, accent, blend);
    }

    private static Color blend(Color base, Color accent, double ratio) {
        double bounded = Math.max(0.0, Math.min(1.0, ratio));
        int red = (int) Math.round(base.getRed() * (1.0 - bounded) + accent.getRed() * bounded);
        int green = (int) Math.round(base.getGreen() * (1.0 - bounded) + accent.getGreen() * bounded);
        int blue = (int) Math.round(base.getBlue() * (1.0 - bounded) + accent.getBlue() * bounded);
        return new Color(red, green, blue);
    }
}
