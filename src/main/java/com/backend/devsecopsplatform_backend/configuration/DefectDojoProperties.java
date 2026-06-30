package com.backend.devsecopsplatform_backend.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "defectdojo")
public class DefectDojoProperties {

    /** Base URL, ex. https://defectdojo.example.com */
    private String url = "";

    /** Token API (avec ou sans préfixe « Token »). */
    private String token = "";

    /** Seuil critique au-delà duquel le déploiement n'est pas recommandé (aligné pipeline CI). */
    private int criticalThreshold = 5;

    /**
     * Désactive la vérification SSL (hostname / certificat) — tunnels locaux ou certificats auto-signés uniquement.
     * Ne pas activer en production.
     */
    private boolean insecureSsl = false;

    public boolean isConfigured() {
        return !normalizedBaseUrl().isBlank() && token != null && !token.trim().isBlank();
    }

    public String normalizedBaseUrl() {
        if (url == null || url.isBlank()) {
            return "";
        }
        String u = url.trim();
        if ((u.startsWith("\"") && u.endsWith("\"")) || (u.startsWith("'") && u.endsWith("'"))) {
            u = u.substring(1, u.length() - 1).trim();
        }
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            u = "https://" + u;
        }
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }

    /** Hôte utilisé pour les logs (sans token ni chemin). */
    public String hostForLog() {
        String base = normalizedBaseUrl();
        if (base.isBlank()) {
            return "(non configuré)";
        }
        try {
            return java.net.URI.create(base).getHost();
        } catch (Exception e) {
            return base;
        }
    }

    public String authorizationHeaderValue() {
        if (token == null || token.isBlank()) {
            return "";
        }
        String t = token.trim();
        if (t.regionMatches(true, 0, "Token ", 0, 6)) {
            return t;
        }
        return "Token " + t;
    }
}
