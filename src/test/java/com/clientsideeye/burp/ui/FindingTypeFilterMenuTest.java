package com.clientsideeye.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Set;

import static com.clientsideeye.burp.core.FindingType.DOM_XSS_SINK;
import static com.clientsideeye.burp.core.FindingType.PASSWORD_VALUE_IN_DOM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingTypeFilterMenuTest {
    @Test
    @SuppressWarnings("unchecked")
    void returnsSelectedFindingTypes() throws Exception {
        FindingTypeFilterMenu menu = new FindingTypeFilterMenu();

        Field itemsField = FindingTypeFilterMenu.class.getDeclaredField("items");
        itemsField.setAccessible(true);
        Map<?, JCheckBoxMenuItem> items = (Map<?, JCheckBoxMenuItem>) itemsField.get(menu);
        items.get(PASSWORD_VALUE_IN_DOM).setSelected(false);
        items.get(DOM_XSS_SINK).setSelected(true);

        Set<String> selected = menu.selectedTypes();

        assertTrue(selected.contains(DOM_XSS_SINK.name()));
        assertEquals(false, selected.contains(PASSWORD_VALUE_IN_DOM.name()));
    }

    @Test
    void exposesTypeButton() {
        FindingTypeFilterMenu menu = new FindingTypeFilterMenu();
        JButton button = menu.button();

        assertEquals("Type…", button.getText());
    }
}
