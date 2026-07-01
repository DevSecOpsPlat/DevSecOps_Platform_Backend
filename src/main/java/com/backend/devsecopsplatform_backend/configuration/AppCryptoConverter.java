package com.backend.devsecopsplatform_backend.configuration;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Convertisseur JPA chiffrant/déchiffrant des colonnes String au repos (AES-256-GCM).
 *
 * <p>Utilisé pour {@code app_service.git_token}, {@code app_database.root_password} et
 * {@code service_env_var.var_value}. La clé provient de {@link AppCryptoKeyHolder}
 * (config {@code app.encryption.key}). Les valeurs stockées sont Base64(IV || ciphertext).</p>
 *
 * <p>Ces valeurs ne sont jamais renvoyées en clair par l'API : les DTO les masquent
 * (••••••) et un endpoint dédié permet de révéler ponctuellement un secret.</p>
 */
@Converter
public class AppCryptoConverter implements AttributeConverter<String, String> {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String ENC_PREFIX = "enc::";

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] encrypted = cipher.doFinal(attribute.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[GCM_IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, GCM_IV_LENGTH);
            System.arraycopy(encrypted, 0, combined, GCM_IV_LENGTH, encrypted.length);

            return ENC_PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new IllegalStateException("Échec du chiffrement de la valeur", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        // Rétro-compatibilité : valeur non préfixée = donnée en clair héritée, renvoyée telle quelle.
        if (!dbData.startsWith(ENC_PREFIX)) {
            return dbData;
        }
        try {
            byte[] combined = Base64.getDecoder().decode(dbData.substring(ENC_PREFIX.length()));

            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Échec du déchiffrement de la valeur", e);
        }
    }

    private static SecretKeySpec keySpec() throws Exception {
        // SHA-256 de la clé configurée → 32 octets (AES-256), tolère toute longueur de clé.
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(AppCryptoKeyHolder.currentKey().getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(digest, "AES");
    }
}
