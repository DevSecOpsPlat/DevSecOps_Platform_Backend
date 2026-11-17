package com.backend.devsecopsplatform_backend.service.defectdojo;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rend lisibles les textes bruts des scanners (Grype, Trivy, Semgrep…) importés par DefectDojo.
 * <p>
 * Ces textes mélangent la vraie description de la vulnérabilité et des métadonnées techniques
 * au format {@code **Clé:** valeur} (namespace, matcher, Package URL…). Les métadonnées sont
 * extraites dans une table (libellés français) ; seule la description reste dans le texte, qui
 * peut alors être traduit sans bruit.
 */
final class ScannerTextFormatter {

    /** {@code **Clé:** valeur} ou {@code **Clé**: valeur} en début de ligne. */
    private static final Pattern FIELD_LINE =
            Pattern.compile("^\\s*\\*\\*([^*\\n]{1,80}?)\\s*:?\\s*\\*\\*\\s*:?\\s*(.*)$");
    /** Plusieurs champs collés sur une même ligne : on force un retour avant chaque {@code **Clé:**}. */
    private static final Pattern INLINE_FIELD_START =
            Pattern.compile("(?<!^)(?<!\\n)\\s*(?=\\*\\*[A-Z][A-Za-z ()/_-]{1,60}:\\*\\*)");

    private static final Map<String, String> LABELS = new LinkedHashMap<>();

    static {
        LABELS.put("vulnerability namespace", "Base de vulnérabilités");
        LABELS.put("matcher", "Méthode de détection");
        LABELS.put("matchers", "Méthode de détection");
        LABELS.put("package url", "Paquet (PURL)");
        LABELS.put("purl", "Paquet (PURL)");
        LABELS.put("package", "Paquet");
        LABELS.put("package name", "Paquet");
        LABELS.put("installed version", "Version installée");
        LABELS.put("version", "Version");
        LABELS.put("fixed version", "Version corrigée");
        LABELS.put("fix version", "Version corrigée");
        LABELS.put("fixed versions", "Versions corrigées");
        LABELS.put("fix available", "Correctif disponible");
        LABELS.put("target", "Cible");
        LABELS.put("type", "Type");
        LABELS.put("class", "Classe");
        LABELS.put("layer", "Couche d'image");
        LABELS.put("layer digest", "Couche d'image");
        LABELS.put("image", "Image");
        LABELS.put("file path", "Fichier");
        LABELS.put("path", "Fichier");
        LABELS.put("location", "Emplacement");
        LABELS.put("locations", "Emplacements");
        LABELS.put("vulnerability datasource", "Source");
        LABELS.put("related vulnerability datasource", "Source associée");
        LABELS.put("vulnerability urls", "Liens");
        LABELS.put("cvss", "CVSS");
        LABELS.put("cvss v3", "CVSS v3");
        LABELS.put("epss", "EPSS");
        LABELS.put("severity source", "Source de la sévérité");
        LABELS.put("rule", "Règle");
        LABELS.put("rule id", "Règle");
        LABELS.put("check id", "Contrôle");
        LABELS.put("check name", "Contrôle");
        LABELS.put("resource", "Ressource");
        LABELS.put("guideline", "Référence");
        LABELS.put("confidence", "Confiance");
        LABELS.put("likelihood", "Probabilité");
    }

    /** Phrases fréquentes des scanners : traduction déterministe, sans appel réseau. */
    private static final List<String[]> PHRASES = List.of(
            new String[]{"(?i)^\\s*upgrade to version:?\\s*", "Mettre à jour vers la version "},
            new String[]{"(?i)^\\s*upgrade to:?\\s*", "Mettre à jour vers "},
            new String[]{"(?i)^\\s*no fix available\\.?\\s*$", "Aucun correctif publié pour le moment."},
            new String[]{"(?i)^\\s*not fixed\\.?\\s*$", "Aucun correctif publié pour le moment."},
            new String[]{"(?i)^\\s*won't fix\\.?\\s*$", "L'éditeur ne prévoit pas de correctif."},
            new String[]{"(?i)^\\s*n/?a\\.?\\s*$", "Non renseigné."}
    );

    record Formatted(String text, Map<String, String> fields) {}

    private ScannerTextFormatter() {
    }

    /**
     * Sépare description et métadonnées. Si le texte ne contient aucun champ {@code **Clé:**},
     * il est renvoyé tel quel (nettoyé des lignes vides superflues).
     */
    static Formatted format(String raw) {
        if (raw == null || raw.isBlank()) {
            return new Formatted(raw, Map.of());
        }
        String normalized = raw.replace("\r\n", "\n").replace('\r', '\n');
        normalized = INLINE_FIELD_START.matcher(normalized).replaceAll("\n");

        Map<String, String> fields = new LinkedHashMap<>();
        StringBuilder text = new StringBuilder();
        String pendingDescriptive = null;

        for (String line : normalized.split("\n")) {
            Matcher m = FIELD_LINE.matcher(line);
            if (!m.matches()) {
                appendLine(text, line);
                continue;
            }
            String key = m.group(1).trim();
            String value = m.group(2) == null ? "" : m.group(2).trim();
            String lower = key.toLowerCase(Locale.ROOT);

            if (isDescriptive(lower)) {
                // La description elle-même : on la garde dans le texte, sans son intitulé anglais.
                if (!value.isEmpty()) {
                    if (pendingDescriptive != null && pendingDescriptive.equals(value)) {
                        continue;
                    }
                    appendParagraph(text, value);
                    pendingDescriptive = value;
                }
                continue;
            }
            if (value.isEmpty()) {
                continue;
            }
            String label = LABELS.getOrDefault(lower, key);
            fields.merge(label, value, (a, b) -> a.equals(b) ? a : a + ", " + b);
        }

        String cleaned = collapseBlankLines(text.toString()).trim();
        if (fields.isEmpty()) {
            return new Formatted(collapseBlankLines(raw.trim()), Map.of());
        }
        return new Formatted(cleaned.isEmpty() ? null : cleaned, fields);
    }

    /** Traduction déterministe des phrases courtes typiques (mitigation Grype/Trivy). */
    static String frenchHints(String text) {
        if (text == null || text.isBlank()) {
            return text;
        }
        String out = text.trim();
        for (String[] p : PHRASES) {
            out = out.replaceAll(p[0], p[1]);
        }
        return out;
    }

    private static boolean isDescriptive(String lowerKey) {
        return lowerKey.contains("description")
                || lowerKey.equals("details")
                || lowerKey.equals("message")
                || lowerKey.equals("result message")
                || lowerKey.equals("summary");
    }

    private static void appendLine(StringBuilder sb, String line) {
        sb.append(line).append('\n');
    }

    private static void appendParagraph(StringBuilder sb, String paragraph) {
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') {
            sb.append('\n');
        }
        if (sb.length() > 0) {
            sb.append('\n');
        }
        sb.append(paragraph).append('\n');
    }

    private static String collapseBlankLines(String s) {
        return s.replaceAll("\n{3,}", "\n\n");
    }
}
