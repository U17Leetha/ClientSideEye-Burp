package com.clientsideeye.burp.ui;

final class FindHintEvidence {
    final String id;
    final String dataTestId;
    final String name;
    final String ariaLabel;
    final String role;
    final String type;
    final String value;
    final String href;
    final String src;
    final String action;
    final String text;

    private FindHintEvidence(String id, String dataTestId, String name, String ariaLabel, String role, String type, String value, String href, String src, String action, String text) {
        this.id = id;
        this.dataTestId = dataTestId;
        this.name = name;
        this.ariaLabel = ariaLabel;
        this.role = role;
        this.type = type;
        this.value = value;
        this.href = href;
        this.src = src;
        this.action = action;
        this.text = text;
    }

    static FindHintEvidence from(String evidence) {
        return new FindHintEvidence(
            FindHintBuilder.extractAttr(evidence, "id"),
            FindHintBuilder.extractAttr(evidence, "data-testid"),
            FindHintBuilder.extractAttr(evidence, "name"),
            FindHintBuilder.extractAttr(evidence, "aria-label"),
            FindHintBuilder.extractAttr(evidence, "role"),
            FindHintBuilder.extractAttr(evidence, "type"),
            FindHintBuilder.extractAttr(evidence, "value"),
            FindHintBuilder.extractAttr(evidence, "href"),
            FindHintBuilder.extractAttr(evidence, "src"),
            FindHintBuilder.extractAttr(evidence, "action"),
            FindHintBuilder.extractInnerText(evidence)
        );
    }
}
