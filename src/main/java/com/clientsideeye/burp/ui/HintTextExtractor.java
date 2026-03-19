package com.clientsideeye.burp.ui;

final class HintTextExtractor {
    private HintTextExtractor() {
    }

    static String extractExecutableText(String item) {
        if (item == null) {
            return "";
        }
        int idx = item.lastIndexOf(": ");
        return idx >= 0 && idx + 2 < item.length() ? item.substring(idx + 2) : item;
    }
}
