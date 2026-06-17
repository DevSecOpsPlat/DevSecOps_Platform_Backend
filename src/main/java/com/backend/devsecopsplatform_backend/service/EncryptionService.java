package com.backend.devsecopsplatform_backend.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Coffre-fort applicatif : chiffrement AES-256-GCM des données sensibles au repos
 * (tokens GitHub, secrets TOTP). Clé : ENCRYPTION_SECRET_KEY (32+ caractères).
 */
@Service
@Slf4j
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits

    @Value("${encryption.secret-key}")
    private String secretKey;

    /**
     * Chiffre un token GitHub
     *
     * @param plainToken Token en clair (ex: ghp_xxxxxxxxxxxx)
     * @return Token chiffré encodé en Base64
     */
    public String encrypt(String plainToken) {
        try {
            if (plainToken == null || plainToken.isEmpty()) {
                return null;
            }

            // Générer un IV aléatoire (Initialization Vector)
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Créer la clé secrète à partir de la chaîne configurée
            byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // Configurer le chiffrement
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            // Chiffrer le token
            byte[] encryptedBytes = cipher.doFinal(plainToken.getBytes(StandardCharsets.UTF_8));

            // Concaténer IV + Données chiffrées
            byte[] encryptedIvAndText = new byte[GCM_IV_LENGTH + encryptedBytes.length];
            System.arraycopy(iv, 0, encryptedIvAndText, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedBytes, 0, encryptedIvAndText, GCM_IV_LENGTH, encryptedBytes.length);

            // Encoder en Base64 pour stockage en BDD
            String encrypted = Base64.getEncoder().encodeToString(encryptedIvAndText);

            log.debug("✅ Token chiffré avec succès");
            return encrypted;

        } catch (Exception e) {
            log.error("❌ Erreur lors du chiffrement du token: {}", e.getMessage());
            throw new RuntimeException("Impossible de chiffrer le token", e);
        }
    }

    /**
     * Déchiffre un token GitHub
     *
     * @param encryptedToken Token chiffré (Base64)
     * @return Token en clair
     */
    public String decrypt(String encryptedToken) {
        try {
            if (encryptedToken == null || encryptedToken.isEmpty()) {
                return null;
            }

            // Décoder depuis Base64
            byte[] encryptedIvAndText = Base64.getDecoder().decode(encryptedToken);

            // Extraire IV et données chiffrées
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encryptedIvAndText, 0, iv, 0, GCM_IV_LENGTH);

            byte[] encryptedBytes = new byte[encryptedIvAndText.length - GCM_IV_LENGTH];
            System.arraycopy(encryptedIvAndText, GCM_IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

            // Créer la clé secrète
            byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // Configurer le déchiffrement
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            // Déchiffrer
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);

            log.debug("✅ Token déchiffré avec succès");
            return decrypted;

        } catch (Exception e) {
            log.error("❌ Erreur lors du déchiffrement du token: {}", e.getMessage());
            throw new RuntimeException("Impossible de déchiffrer le token", e);
        }
    }

    /**
     * Vérifie si un token est valide (pour tests)
     */
    public boolean isTokenValid(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        // Les tokens GitHub commencent par "ghp_", "gho_", "github_pat_"
        return token.startsWith("ghp_") ||
                token.startsWith("gho_") ||
                token.startsWith("github_pat_");
    }
}