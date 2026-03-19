package com.clientsideeye.burp.ui;

import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;

import java.util.Set;

final class FindingTypeGuidance {
    private static final Set<String> DOM_FOCUSED_TYPES = Set.of(
        FindingType.PASSWORD_VALUE_IN_DOM.name(),
        FindingType.HIDDEN_OR_DISABLED_CONTROL.name()
    );

    private FindingTypeGuidance() {
    }

    static boolean supportsDomWorkflows(Finding finding) {
        return finding != null && DOM_FOCUSED_TYPES.contains(finding.type());
    }

    static String guidanceText(Finding finding, FindHintBuilder.Result hintResult) {
        if (finding == null) {
            return "";
        }
        if (supportsDomWorkflows(finding)) {
            return domWorkflowText(finding, hintResult);
        }
        return investigationWorkflowText(finding);
    }

    private static String domWorkflowText(Finding finding, FindHintBuilder.Result hintResult) {
        StringBuilder out = new StringBuilder();
        out.append("DevTools Usage\n");
        out.append("-------------\n");
        out.append("1. Paste the locate hint into the browser Console to find candidate nodes.\n");
        out.append("2. Paste the highlight snippet to confirm the right target visually.\n");
        out.append("3. Paste the reveal / unhide snippet to expose or re-enable the control when needed.\n\n");
        out.append("Locate hint\n");
        out.append("~~~~~~~~~~~\n");
        out.append(firstHintSnippet(hintResult)).append("\n\n");
        out.append("Highlight snippet\n");
        out.append("~~~~~~~~~~~~~~~~~\n");
        out.append(hintResult.highlightSnippet).append("\n\n");
        out.append("Reveal / unhide snippet\n");
        out.append("~~~~~~~~~~~~~~~~~~~~~~~\n");
        out.append(hintResult.revealSnippet).append("\n");
        return out.toString();
    }

    private static String investigationWorkflowText(Finding finding) {
        String type = finding.type();
        return switch (type) {
            case "RUNTIME_NETWORK_REFERENCE" -> """
                Validation Workflow
                -------------------
                This finding is attack-surface discovery, not proof of a vulnerability by itself.

                1. Reproduce the page action and inspect the request in Burp Proxy, HTTP history, or browser DevTools.
                2. Replay the request directly and test whether the same endpoint works without the original client-side flow.
                3. Modify identifiers, roles, parameters, or GraphQL operations to test authorization and data exposure.
                4. If the endpoint is tied to a hidden or disabled control, use that control finding as the UI-side PoC and this request as the backend-side PoC.
                5. Document the real issue as unauthorized data access, privileged action exposure, or hidden client-side functionality if the replay succeeds.
                """;
            case "JAVASCRIPT_ENDPOINT_REFERENCE" -> """
                Validation Workflow
                -------------------
                This finding highlights client-side attack surface referenced in JavaScript.

                1. Search the endpoint or route in Burp and browser DevTools to find where it is used.
                2. Open the related page path or replay the referenced request manually.
                3. Check whether the endpoint is reachable without the intended UI path or role.
                4. Correlate with source maps, hidden controls, or runtime network findings for a stronger PoC.
                """;
            case "POSTMESSAGE_HANDLER" -> """
                Validation Workflow
                -------------------
                This finding points to cross-window messaging logic that needs manual trust-boundary review.

                1. Identify the message sender and listener contexts.
                2. Test whether messages from an untrusted frame or origin are accepted.
                3. Look for dangerous actions triggered by message data, especially DOM writes or privileged requests.
                4. Build the PoC around origin-validation failure or dangerous message handling, not the message API alone.
                """;
            case "DOM_XSS_SINK" -> """
                Validation Workflow
                -------------------
                This finding is a dangerous sink indicator, not a confirmed DOM XSS by itself.

                1. Identify attacker-controlled inputs such as query parameters, postMessage data, storage values, or server-rendered fields.
                2. Trace whether those inputs can reach the sink shown in the evidence.
                3. Confirm execution or injection behavior with a safe test payload.
                4. Build the PoC around source-to-sink control, not the sink alone.
                """;
            case "SOURCE_MAP_DISCLOSURE" -> """
                Validation Workflow
                -------------------
                This finding indicates exposed client-side implementation detail.

                1. Open the source map and review disclosed source paths, comments, routes, and unminified logic.
                2. Pivot from exposed routes or operations into real authorization or exposure tests.
                3. Document source-map disclosure itself only if exposure of original sources is material in your target context.
                """;
            case "STORAGE_TOKEN" -> """
                Validation Workflow
                -------------------
                This finding indicates potentially sensitive browser storage use.

                1. Confirm whether the stored value is actually sensitive or security-relevant.
                2. Determine whether it can be abused by client-side injection, weak logout flows, or cross-context access.
                3. Build the PoC around token exposure, persistence, replay, or misuse rather than storage presence alone.
                """;
            case "DEVTOOLS_BLOCKING" -> """
                Validation Workflow
                -------------------
                This finding indicates client-side resistance to analysis rather than a vulnerability by itself.

                1. Use the bypass snippet if testing is authorized.
                2. Confirm whether the blocking logic interferes with observing hidden controls, messages, or requests.
                3. Treat this as supporting context for a larger client-side issue unless the behavior itself is security-relevant.
                """;
            default -> """
                Validation Workflow
                -------------------
                Review the evidence in context, reproduce the behavior, and confirm whether it leads to a real security outcome.
                Build the PoC around the resulting unauthorized action, exposure, or trust-boundary failure rather than the heuristic alone.
                """;
        };
    }

    private static String firstHintSnippet(FindHintBuilder.Result result) {
        if (result == null || result.hints == null || result.hints.isEmpty()) {
            return "";
        }
        return HintTextExtractor.extractExecutableText(result.hints.get(0));
    }
}
