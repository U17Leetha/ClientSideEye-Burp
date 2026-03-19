package com.clientsideeye.burp.core;

import java.util.ArrayList;
import java.util.List;

public final class ResponseAnalyzer {
    private ResponseAnalyzer() {
    }

    public static List<Finding> analyze(String url, String body) {
        boolean htmlLike = HtmlAnalyzer.looksLikeHtmlForAnalysis(url, body);
        boolean jsLike = JavaScriptAnalyzer.looksLikeJavaScriptForAnalysis(url, body);
        boolean sourceMapLike = SourceMapAnalyzer.looksLikeSourceMap(url, body);
        if (!htmlLike && !jsLike && !sourceMapLike) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        if (htmlLike) {
            findings.addAll(HtmlAnalyzer.analyzeHtml(url, body));
        }
        if (jsLike) {
            findings.addAll(JavaScriptAnalyzer.analyzeJavaScript(url, body));
            findings.addAll(SourceMapAnalyzer.analyzeSourceMappingReference(url, body));
        }
        if (sourceMapLike) {
            findings.addAll(SourceMapAnalyzer.analyzeSourceMap(url, body));
        }
        return findings;
    }
}
