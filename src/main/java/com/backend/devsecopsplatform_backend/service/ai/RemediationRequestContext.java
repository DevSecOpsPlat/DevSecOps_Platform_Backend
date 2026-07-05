package com.backend.devsecopsplatform_backend.service.ai;

/**
 * Métadonnées pour cache, templates statiques et mode analyse.
 */
public record RemediationRequestContext(
        String ruleKey,
        String filePath,
        Integer line,
        boolean deepAnalysis
) {
    public static RemediationRequestContext fromFindingContext(String findingContext, boolean deepAnalysis) {
        String ruleKey = StaticRemediationTemplateService.extractRuleKey(findingContext);
        String filePath = extractLineValue(findingContext, "Fichier:");
        Integer line = parseLine(extractLineValue(findingContext, "Ligne:"));
        return new RemediationRequestContext(ruleKey, filePath, line, deepAnalysis);
    }

    private static String extractLineValue(String ctx, String prefix) {
        if (ctx == null) {
            return null;
        }
        for (String line : ctx.split("\n")) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    private static Integer parseLine(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(s.replaceAll("\\D.*", ""));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
