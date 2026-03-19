package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.FindingType;

import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JPopupMenu;
import java.awt.event.ActionListener;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

final class FindingTypeFilterMenu {
    private final Map<FindingType, JCheckBoxMenuItem> items = new EnumMap<>(FindingType.class);
    private final JPopupMenu menu = new JPopupMenu();
    private final JButton button = new JButton("Type…");

    FindingTypeFilterMenu() {
        for (FindingType findingType : FindingType.values()) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(findingType.name(), true);
            items.put(findingType, item);
            menu.add(item);
        }
        button.addActionListener(event -> menu.show(button, 0, button.getHeight()));
    }

    JButton button() {
        return button;
    }

    void addChangeListener(ActionListener listener) {
        items.values().forEach(item -> item.addActionListener(listener));
    }

    Set<String> selectedTypes() {
        Set<String> selected = new HashSet<>();
        items.forEach((findingType, item) -> {
            if (item.isSelected()) {
                selected.add(findingType.name());
            }
        });
        return selected;
    }
}
