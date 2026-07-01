package com.backend.devsecopsplatform_backend.service.qualitygate;

/**
 * Dérive la clé projet SonarQube depuis l'URL du repo — même logique que pipeline.md :
 * {@code https://github.com/Amenybn/Angular → github_com_Amenybn_Angular}
 */
public final class SonarProjectKeyUtil {

    private SonarProjectKeyUtil() {
    }

    public static String deriveSonarProjectKey(String repoUrl) {
        if (repoUrl == null || repoUrl.isBlank()) {
            return "";
        }
        String normalized = repoUrl.trim();
        normalized = normalized.replaceFirst("^https?://", "");
        normalized = normalized.replaceFirst("\\.git$", "");
        normalized = normalized.replace('/', '_');
        normalized = normalized.replaceAll("[^a-zA-Z0-9_]", "_");
        return normalized;
    }
}
