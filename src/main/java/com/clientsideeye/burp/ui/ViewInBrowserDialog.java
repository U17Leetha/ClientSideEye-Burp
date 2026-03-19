package com.clientsideeye.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.function.Consumer;

final class ViewInBrowserDialog {
    private ViewInBrowserDialog() {
    }

    static void show(MontoyaApi api, Finding finding, Consumer<String> clipboardWriter) {
        String evidence = finding.evidence();
        boolean isDevtoolsFinding = FindingType.DEVTOOLS_BLOCKING.name().equals(finding.type());
        boolean supportsDomWorkflows = FindingTypeGuidance.supportsDomWorkflows(finding);
        FindHintBuilder.Result hintResult = FindHintBuilder.build(evidence);

        DefaultComboBoxModel<String> hintModel = new DefaultComboBoxModel<>();
        for (String hint : hintResult.hints) {
            hintModel.addElement(hint);
        }
        JComboBox<String> hintCombo = new JComboBox<>(hintModel);
        JDialog dialog = new JDialog(
            api.userInterface().swingUtils().suiteFrame(),
            "View in Browser",
            Dialog.ModalityType.APPLICATION_MODAL
        );
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.add(buildTopPanel(api, finding, hintCombo, hintResult, isDevtoolsFinding, supportsDomWorkflows, clipboardWriter), BorderLayout.NORTH);
        dialog.add(buildInstructionsPane(finding, evidence, hintResult, isDevtoolsFinding, supportsDomWorkflows), BorderLayout.CENTER);
        dialog.add(buildFooter(dialog), BorderLayout.SOUTH);
        dialog.pack();
        applyPreferredDialogSize(dialog);
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        dialog.setVisible(true);
    }

    private static JPanel buildTopPanel(
        MontoyaApi api,
        Finding finding,
        JComboBox<String> hintCombo,
        FindHintBuilder.Result hintResult,
        boolean isDevtoolsFinding,
        boolean supportsDomWorkflows,
        Consumer<String> clipboardWriter
    ) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;

        JTextField urlField = new JTextField(finding.url());
        urlField.setEditable(false);

        JButton copyUrlButton = new JButton("Copy URL");
        copyUrlButton.addActionListener(e -> {
            clipboardWriter.accept(finding.url());
            api.logging().logToOutput("[ClientSideEye] Copied URL to clipboard.");
        });

        JButton copyLocateButton = new JButton("Copy Locate Hint");
        copyLocateButton.addActionListener(e -> {
            String hint = HintTextExtractor.extractExecutableText(String.valueOf(hintCombo.getSelectedItem()));
            clipboardWriter.accept(hint);
            api.logging().logToOutput("[ClientSideEye] Copied locate hint to clipboard.");
        });

        JButton copyHighlightButton = new JButton("Copy Highlight Snippet");
        copyHighlightButton.addActionListener(e -> {
            clipboardWriter.accept(hintResult.highlightSnippet);
            api.logging().logToOutput("[ClientSideEye] Copied highlight snippet to clipboard.");
        });

        JButton copyRevealButton = new JButton("Copy Reveal / Unhide Snippet");
        copyRevealButton.addActionListener(e -> {
            clipboardWriter.accept(hintResult.revealSnippet);
            api.logging().logToOutput("[ClientSideEye] Copied reveal snippet to clipboard.");
        });

        JButton copyGuidanceButton = new JButton("Copy Validation Guidance");
        copyGuidanceButton.addActionListener(e -> {
            clipboardWriter.accept(FindingTypeGuidance.guidanceText(finding, hintResult).trim());
            api.logging().logToOutput("[ClientSideEye] Copied validation guidance to clipboard.");
        });

        c.gridx = 0; c.gridy = 0; c.weightx = 0;
        panel.add(new JLabel("URL:"), c);
        c.gridx = 1; c.weightx = 1;
        panel.add(urlField, c);
        c.gridx = 2; c.weightx = 0;
        panel.add(copyUrlButton, c);

        if (supportsDomWorkflows) {
            c.gridx = 0; c.gridy = 1; c.weightx = 0;
            panel.add(new JLabel("Locate hint:"), c);
            c.gridx = 1; c.weightx = 1;
            panel.add(hintCombo, c);
            c.gridx = 2; c.weightx = 0;
            panel.add(copyLocateButton, c);

            addSnippetRow(panel, c, 2, "Highlight:", "Marks all likely matches in the page", copyHighlightButton);
            addSnippetRow(panel, c, 3, "Reveal / unhide:", "Unhides or re-enables the target and ancestors", copyRevealButton);
        } else {
            addSnippetRow(panel, c, 1, "Validation:", "Investigation and PoC guidance for this finding type", copyGuidanceButton);
        }

        if (isDevtoolsFinding) {
            JButton copyBypassButton = new JButton("Copy DevTools Bypass Snippet");
            copyBypassButton.addActionListener(e -> {
                clipboardWriter.accept(DevtoolsBypassSnippets.script());
                api.logging().logToOutput("[ClientSideEye] Copied DevTools bypass snippet to clipboard.");
            });
            addSnippetRow(panel, c, supportsDomWorkflows ? 4 : 2, "Bypass:", "Neutralizes common DevTools detection hooks", copyBypassButton);
        }
        return panel;
    }

    private static void addSnippetRow(JPanel panel, GridBagConstraints c, int row, String label, String description, JButton button) {
        c.gridx = 0; c.gridy = row; c.weightx = 0;
        panel.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1;
        panel.add(new JLabel(description), c);
        c.gridx = 2; c.weightx = 0;
        panel.add(button, c);
    }

    private static JScrollPane buildInstructionsPane(Finding finding, String evidence, FindHintBuilder.Result hintResult, boolean isDevtoolsFinding, boolean supportsDomWorkflows) {
        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setText(buildInstructionsText(finding, evidence, hintResult, isDevtoolsFinding, supportsDomWorkflows));
        textArea.setCaretPosition(0);
        JScrollPane pane = new JScrollPane(textArea);
        pane.setPreferredSize(new Dimension(760, 420));
        return pane;
    }

    private static JPanel buildFooter(JDialog dialog) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        panel.add(closeButton);
        return panel;
    }

    private static void applyPreferredDialogSize(JDialog dialog) {
        Rectangle bounds = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        int preferredWidth = Math.min(900, bounds.width - 160);
        int preferredHeight = Math.min(760, bounds.height - 120);
        int width = Math.min(Math.max(dialog.getWidth(), 720), preferredWidth);
        int height = Math.min(Math.max(dialog.getHeight(), 560), preferredHeight);
        dialog.setSize(width, height);
    }

    private static String buildInstructionsText(Finding finding, String evidence, FindHintBuilder.Result hintResult, boolean isDevtoolsFinding, boolean supportsDomWorkflows) {
        String bypassSection = isDevtoolsFinding
            ? "DevTools bypass snippet (Console):\n" + DevtoolsBypassSnippets.script() + "\n"
                + "Tip: If the app blocks on load, run the snippet as a DevTools Snippet and reload.\n\n"
            : "";
        return """
            Recommended DevTools flow:
            1) Copy a Locate hint and paste it into the Console to identify the right node(s)
            2) Copy the Highlight snippet to visually confirm the match on the page
            3) Copy the Reveal / Unhide snippet when you need to re-enable a hidden or disabled control
            4) Use Elements / Inspector search (Cmd/Ctrl+F) with the same selector or text hint if needed

            Highlight snippet (Console):
            """
            + hintResult.highlightSnippet + "\n\n"
            + "Reveal / unhide snippet (Console):\n"
            + hintResult.revealSnippet + "\n\n"
            + bypassSection
            + "Evidence snippet:\n" + evidence + "\n";
    }


}