package com.clientsideeye.burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.ResponseAnalyzer;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;

final class SiteMapScanRunner {
    private SiteMapScanRunner() {
    }

    static SiteMapScanSummary scan(
        List<HttpRequestResponse> items,
        Predicate<String> hostMatcher,
        int scanLimit,
        Consumer<List<Finding>> findingsConsumer
    ) {
        int analyzed = 0;
        int added = 0;
        int skippedNonAnalyzable = 0;
        int skippedByCap = 0;

        for (HttpRequestResponse requestResponse : items) {
            if (requestResponse == null || requestResponse.request() == null || requestResponse.response() == null) {
                continue;
            }
            if (!requestResponse.request().isInScope()) {
                continue;
            }
            String url = requestResponse.request().url();
            if (!hostMatcher.test(url)) {
                continue;
            }
            if (analyzed >= scanLimit) {
                skippedByCap++;
                continue;
            }

            String body = requestResponse.response().bodyToString();
            if (body == null || body.isBlank()) {
                continue;
            }

            List<Finding> findings = ResponseAnalyzer.analyze(url, body);
            if (findings.isEmpty()) {
                skippedNonAnalyzable++;
                continue;
            }

            analyzed++;
            added += findings.size();
            findingsConsumer.accept(findings);
        }

        return new SiteMapScanSummary(analyzed, added, skippedNonAnalyzable, skippedByCap);
    }

    static long countEligible(List<HttpRequestResponse> items, Predicate<String> hostMatcher) {
        return items.stream()
            .filter(Objects::nonNull)
            .filter(requestResponse -> requestResponse.request() != null && requestResponse.request().isInScope())
            .filter(requestResponse -> hostMatcher.test(requestResponse.request().url()))
            .count();
    }
}
