package com.backend.devsecopsplatform_backend.service.ai;

import java.util.Locale;

/**
 * Extrait le bloc sémantique (méthode/fonction) contenant une ligne vulnérable,
 * plutôt qu'une fenêtre fixe de N lignes.
 */
public final class CodeContextExtractor {

    private static final int FALLBACK_CONTEXT_LINES = 18;
    private static final int ANNOTATION_PADDING_LINES = 3;
    private static final int MAX_BLOCK_LINES = 280;
    private static final int WHOLE_FILE_MAX_LINES = 160;

    private CodeContextExtractor() {}

    public record ExtractionResult(int startLine1Based, int endLine1Based, boolean functionBlock) {}

    /**
     * @param fullSource contenu brut du fichier
     * @param targetLine1Based ligne vulnérable (1-based), ou &lt;= 0 pour début de fichier
     */
    public static ExtractionResult locateBlock(String fullSource, int targetLine1Based) {
        if (fullSource == null || fullSource.isBlank()) {
            return new ExtractionResult(1, 1, false);
        }
        String[] lines = fullSource.split("\r\n|\n|\r", -1);
        if (lines.length <= WHOLE_FILE_MAX_LINES) {
            return new ExtractionResult(1, lines.length, false);
        }
        if (targetLine1Based <= 0) {
            return fallbackWindow(lines.length, 1);
        }
        int targetIdx = Math.min(lines.length - 1, Math.max(0, targetLine1Based - 1));
        int[] block = findEnclosingBraceBlock(lines, targetIdx);
        if (block == null) {
            return fallbackWindow(lines.length, targetLine1Based);
        }
        int start = Math.max(0, block[0] - ANNOTATION_PADDING_LINES);
        int end = Math.min(lines.length - 1, block[1]);
        if (end - start + 1 > MAX_BLOCK_LINES) {
            return fallbackWindow(lines.length, targetLine1Based);
        }
        return new ExtractionResult(start + 1, end + 1, true);
    }

    public static String formatWithLineNumbers(String[] lines, int startIdx0, int endIdx0) {
        StringBuilder sb = new StringBuilder();
        for (int i = startIdx0; i <= endIdx0 && i < lines.length; i++) {
            sb.append(String.format(Locale.ROOT, "%5d| %s%n", i + 1, lines[i]));
        }
        return sb.toString();
    }

    public static String extractSnippet(String fullSource, int targetLine1Based, int maxChars) {
        if (fullSource == null || fullSource.isBlank()) {
            return "";
        }
        String[] lines = fullSource.split("\r\n|\n|\r", -1);
        ExtractionResult loc = locateBlock(fullSource, targetLine1Based);
        int startIdx = loc.startLine1Based() - 1;
        int endIdx = loc.endLine1Based() - 1;
        String header = loc.functionBlock()
                ? "// Contexte : méthode/fonction englobante (ligne cible " + targetLine1Based + ")\n"
                : "// Contexte : fenêtre autour de la ligne " + targetLine1Based + "\n";
        String body = formatWithLineNumbers(lines, startIdx, endIdx);
        String out = header + body;
        if (out.length() > maxChars) {
            return out.substring(0, maxChars) + "\n...[truncated]";
        }
        return out;
    }

    /** Normalise un extrait pour clé de cache (sans numéros de marge). */
    public static String normalizeForCacheKey(String snippet) {
        if (snippet == null || snippet.isBlank()) {
            return "";
        }
        String[] lines = snippet.split("\r\n|\n|\r", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            String stripped = line.replaceFirst("^\\s*\\d+\\|\\s?", "").trim();
            if (!stripped.startsWith("// Contexte :")) {
                sb.append(stripped).append('\n');
            }
        }
        String norm = sb.toString().trim();
        return norm.length() > 2000 ? norm.substring(0, 2000) : norm;
    }

    private static ExtractionResult fallbackWindow(int totalLines, int targetLine1Based) {
        int targetIdx = Math.min(totalLines - 1, Math.max(0, targetLine1Based - 1));
        int start = Math.max(0, targetIdx - FALLBACK_CONTEXT_LINES);
        int end = Math.min(totalLines - 1, targetIdx + FALLBACK_CONTEXT_LINES);
        return new ExtractionResult(start + 1, end + 1, false);
    }

    /**
     * Remonte depuis la ligne cible pour trouver le début d'un bloc {@code {…}},
     * puis avance jusqu'à la fermeture du bloc.
     */
    static int[] findEnclosingBraceBlock(String[] lines, int targetIdx) {
        int depth = 0;
        int start = targetIdx;
        for (int i = targetIdx; i >= 0; i--) {
            depth += closeBraces(lines[i]) - openBraces(lines[i]);
            if (depth < 0) {
                start = i;
                break;
            }
            if (i == 0) {
                start = 0;
            }
        }
        depth = 0;
        int end = targetIdx;
        for (int i = start; i < lines.length; i++) {
            depth += openBraces(lines[i]) - closeBraces(lines[i]);
            if (depth <= 0 && i >= targetIdx) {
                end = i;
                return new int[]{start, end};
            }
        }
        if (end > start) {
            return new int[]{start, end};
        }
        return null;
    }

    private static int openBraces(String line) {
        int count = 0;
        boolean inString = false;
        char stringChar = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inString) {
                if (c == stringChar && (i == 0 || line.charAt(i - 1) != '\\')) {
                    inString = false;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                inString = true;
                stringChar = c;
            } else if (c == '{') {
                count++;
            }
        }
        return count;
    }

    private static int closeBraces(String line) {
        int count = 0;
        boolean inString = false;
        char stringChar = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inString) {
                if (c == stringChar && (i == 0 || line.charAt(i - 1) != '\\')) {
                    inString = false;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                inString = true;
                stringChar = c;
            } else if (c == '}') {
                count++;
            }
        }
        return count;
    }
}
