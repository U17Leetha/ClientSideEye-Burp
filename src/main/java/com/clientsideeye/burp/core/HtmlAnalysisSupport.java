package com.clientsideeye.burp.core;

import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;

import java.net.URI;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

final class HtmlAnalysisSupport {
    private HtmlAnalysisSupport() {
    }

    static String hostFromUrl(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? "" : uri.getHost();
        } catch (Exception ignored) {
            return "";
        }
    }

    static String shrink(String value, int max) {
        if (value == null) {
            return "";
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        if (normalized.length() <= max) {
            return normalized;
        }
        return normalized.substring(0, max) + "...";
    }

    static Set<String> loweredClassNames(Element element) {
        Set<String> out = new HashSet<>();
        for (String className : element.classNames()) {
            out.add(className.toLowerCase(Locale.ROOT));
        }
        return out;
    }

    static String ownText(Element element) {
        StringBuilder sb = new StringBuilder();
        for (Node node : element.childNodes()) {
            if (node instanceof TextNode textNode) {
                sb.append(textNode.text()).append(' ');
            }
        }
        String text = sb.toString().replaceAll("\\s+", " ").trim();
        if (!text.isBlank()) {
            return text;
        }
        return element.text().replaceAll("\\s+", " ").trim();
    }

    static String elementIdentity(Element element) {
        String text = ownText(element);
        if (text.length() > 80) {
            text = text.substring(0, 80);
        }
        return String.join("|",
            element.tagName().toLowerCase(Locale.ROOT),
            element.id(),
            element.attr("data-testid"),
            element.attr("name"),
            element.attr("href"),
            element.attr("action"),
            element.attr("aria-label"),
            text
        );
    }
}
