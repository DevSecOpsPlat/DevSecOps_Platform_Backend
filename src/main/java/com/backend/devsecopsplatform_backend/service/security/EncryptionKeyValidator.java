package com.backend.devsecopsplatform_backend.service.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Vérifie au démarrage que la clé de chiffrement au repos n'est pas la valeur par défaut.
 */
@Component
@Slf4j
public class EncryptionKeyValidator {

    private static final String DEFAULT_KEY = "MySecretKey12345MySecretKey12345";

    @Value("${encryption.secret-key}")
    private String secretKey;

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
        if (secretKey == null || secretKey.isBlank()) {
            log.error("══════════════════════════════════════════════════════════");
            log.error("ENCRYPTION_SECRET_KEY manquante — chiffrement au repos désactivé.");
            log.error("Générez une clé : openssl rand -base64 32");
            log.error("══════════════════════════════════════════════════════════");
            return;
        }
        if (secretKey.length() < 32) {
            log.warn("ENCRYPTION_SECRET_KEY trop courte ({} car.) — utilisez au moins 32 caractères pour AES-256.",
                    secretKey.length());
        }
        if (DEFAULT_KEY.equals(secretKey)) {
            log.warn("══════════════════════════════════════════════════════════");
            log.warn("ENCRYPTION_SECRET_KEY = valeur par défaut (dev uniquement).");
            log.warn("En production bancaire : variable d'environnement ENCRYPTION_SECRET_KEY unique.");
            log.warn("══════════════════════════════════════════════════════════");
        } else {
            log.info("Clé de chiffrement au repos configurée (AES-256-GCM).");
        }
    }
}
