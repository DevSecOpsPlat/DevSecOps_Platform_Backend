package com.backend.devsecopsplatform_backend.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security.data-protection")
@Getter
@Setter
public class DataProtectionProperties {

    /** En production : refuser le trafic non HTTPS (via X-Forwarded-Proto derrière Nginx). */
    private boolean requireHttps = false;

    /** Ajouter Strict-Transport-Security quand la requête arrive en HTTPS. */
    private boolean hstsEnabled = true;

    private int hstsMaxAgeSeconds = 31536000;

    /** Refuser les requêtes sans en-tête X-Forwarded-Proto en mode require-https strict. */
    private boolean trustForwardedHeaders = true;
}
