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

    public boolean isConfigured() {
        return url != null && !url.isBlank() && token != null && !token.isBlank();
    }

    public String normalizedBaseUrl() {
        if (url == null || url.isBlank()) {
            return "";
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
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
