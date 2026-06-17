package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.configuration.DataProtectionProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Inventaire « coffre-fort » : chiffrement en transit et au repos. */
@Service
@RequiredArgsConstructor
public class DataProtectionService {

    private static final String DEFAULT_ENCRYPTION_KEY = "MySecretKey12345MySecretKey12345";

    private final DataProtectionProperties dataProtectionProperties;

    @Value("${encryption.secret-key:}")
    private String encryptionSecretKey;

    public Map<String, Object> getProtectionSummary() {
        Map<String, Object> summary = new LinkedHashMap<>();

        Map<String, Object> inTransit = new LinkedHashMap<>();
        inTransit.put("protocol", "TLS 1.2+ (HTTPS)");
        inTransit.put("description", "Chiffrement entre navigateur/app et serveur (cadenas vert)");
        inTransit.put("termination", "Nginx reverse proxy (recommandé) ou certificat Spring Boot");
        inTransit.put("hstsEnabled", dataProtectionProperties.isHstsEnabled());
        inTransit.put("requireHttpsEnforced", dataProtectionProperties.isRequireHttps());
        inTransit.put("headers", List.of(
                "Strict-Transport-Security (si HTTPS)",
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: DENY",
                "Referrer-Policy",
                "Cache-Control: no-store (API)"
        ));

        Map<String, Object> atRest = new LinkedHashMap<>();
        atRest.put("algorithm", "AES-256-GCM (application)");
        atRest.put("keySource", "Variable ENCRYPTION_SECRET_KEY (32+ caractères)");
        atRest.put("productionKeyConfigured", isProductionKeyConfigured());
        atRest.put("encryptedFields", List.of(
                Map.of("table", "applications", "column", "encrypted_github_token", "label", "Tokens GitHub"),
                Map.of("table", "users", "column", "totp_secret_enc", "label", "Secret 2FA (TOTP)"),
                Map.of("table", "users", "column", "password_hash", "label", "Mot de passe (bcrypt, hash irréversible)")
        ));
        atRest.put("databaseNote",
                "PostgreSQL : chiffrement disque complet (TDE) = couche infrastructure / hébergeur (optionnel).");

        Map<String, Object> notStored = new LinkedHashMap<>();
        notStored.put("otpEmailCodes", "En mémoire uniquement (5–10 min), jamais en BDD");
        notStored.put("jwtAccessToken", "Côté client (localStorage), signé HS256, expiration 24h");

        summary.put("inTransit", inTransit);
        summary.put("atRest", atRest);
        summary.put("ephemeralSecrets", notStored);
        summary.put("complianceNote",
                "Modèle bancaire : TLS obligatoire en prod + secrets applicatifs chiffrés + mots de passe hashés.");

        return summary;
    }

    private boolean isProductionKeyConfigured() {
        return encryptionSecretKey != null
                && !encryptionSecretKey.isBlank()
                && !DEFAULT_ENCRYPTION_KEY.equals(encryptionSecretKey)
                && encryptionSecretKey.length() >= 32;
    }
}
