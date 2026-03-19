package com.clientsideeye.burp.ui;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

final class ClipboardHelper {
    private ClipboardHelper() {
    }

    static void copy(String value) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            new StringSelection(value == null ? "" : value),
            null
        );
    }
}
