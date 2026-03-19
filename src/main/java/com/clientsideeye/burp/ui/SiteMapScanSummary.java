package com.clientsideeye.burp.ui;

final class SiteMapScanSummary {
    private final int analyzed;
    private final int added;
    private final int skippedNonAnalyzable;
    private final int skippedByCap;

    SiteMapScanSummary(int analyzed, int added, int skippedNonAnalyzable, int skippedByCap) {
        this.analyzed = analyzed;
        this.added = added;
        this.skippedNonAnalyzable = skippedNonAnalyzable;
        this.skippedByCap = skippedByCap;
    }

    int analyzed() {
        return analyzed;
    }

    int added() {
        return added;
    }

    int skippedNonAnalyzable() {
        return skippedNonAnalyzable;
    }

    int skippedByCap() {
        return skippedByCap;
    }
}
