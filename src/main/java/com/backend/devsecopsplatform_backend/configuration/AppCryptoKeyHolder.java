package com.backend.devsecopsplatform_backend.configuration;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Détient la clé de chiffrement au repos utilisée par {@link AppCryptoConverter}.
 *
 * <p>Un {@link jakarta.persistence.AttributeConverter} est instancié par Hibernate (hors
 * conteneur Spring dans le cas général), il ne peut donc pas recevoir la clé par injection.
 * Ce composant Spring lit la clé une fois au démarrage et l'expose de façon statique au
 * convertisseur.</p>
 *
 * <p>Clé lue depuis {@code app.encryption.key} ; à défaut on retombe sur la clé historique
 * ({@code encryption.secret-key} / {@code ENCRYPTION_SECRET_KEY}) pour ne pas casser
 * l'existant.</p>
 */
@Component
@Slf4j
public class AppCryptoKeyHolder {

    private static volatile String key = "MySecretKey12345MySecretKey12345";

    @Value("${app.encryption.key:${encryption.secret-key:MySecretKey12345MySecretKey12345}}")
    private String configuredKey;

    @PostConstruct
    void init() {
        if (configuredKey != null && !configuredKey.isBlank()) {
            key = configuredKey;
        }
        if ("MySecretKey12345MySecretKey12345".equals(key)) {
            log.warn("⚠️ app.encryption.key non défini : clé de chiffrement par défaut utilisée. " +
                    "Définir ENCRYPTION_SECRET_KEY / app.encryption.key en production.");
        } else {
            log.info("🔐 Clé de chiffrement au repos (app.encryption.key) chargée.");
        }
    }

    static String currentKey() {
        return key;
    }
}
