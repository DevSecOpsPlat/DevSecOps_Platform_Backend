package com.backend.devsecopsplatform_backend.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security")
@Getter
@Setter
public class SecurityMonitoringProperties {

    private boolean monitoringEnabled = true;

    /** Ne pas bloquer / limiter localhost (dev). */
    private boolean trustLocalhost = true;

    private BruteForce bruteForce = new BruteForce();
    private RateLimit rateLimit = new RateLimit();
    private Blocklist blocklist = new Blocklist();

    @Getter
    @Setter
    public static class BruteForce {
        /** Échecs de connexion par IP avant alerte force brute. */
        private int ipFailureThreshold = 5;
        /** Fenêtre d'observation (minutes). */
        private int ipWindowMinutes = 1;
        /** Durée de blocage IP après force brute (minutes). */
        private int ipBlockMinutes = 30;
    }

    @Getter
    @Setter
    public static class RateLimit {
        /** Requêtes max par IP sur la fenêtre globale (Bucket4j). */
        private int maxRequests = 200;
        private int windowSeconds = 60;
        /** Limite stricte sur /auth/login. */
        private int loginMaxRequests = 20;
        private int loginWindowSeconds = 60;
        /** Limite sur /api/admin/** (pare-feu applicatif). */
        private int adminMaxRequests = 100;
        private int adminWindowSeconds = 60;
    }

    @Getter
    @Setter
    public static class Blocklist {
        private boolean enabled = true;
        /** Minutes de blocage après honeypot / payload malveillant. */
        private int honeypotBlockMinutes = 60;
        /** Minutes de blocage après rate limit répété. */
        private int rateLimitBlockMinutes = 15;
        /** Intervalle de nettoyage des blocages expirés (ms). */
        private long cleanupIntervalMs = 300_000L;
    }
}
