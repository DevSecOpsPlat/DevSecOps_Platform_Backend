package com.backend.devsecopsplatform_backend.service.auth;

import com.backend.devsecopsplatform_backend.service.EncryptionService;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class TotpService {

    private final EncryptionService encryptionService;

    @Value("${app.two-factor.issuer:EnviroTest}")
    private String issuer;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public String generatePlainSecret() {
        return secretGenerator.generate();
    }

    public String buildOtpAuthUrl(String username, String plainSecret) {
        String label = URLEncoder.encode(issuer + ":" + username, StandardCharsets.UTF_8);
        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label + "?secret=" + plainSecret + "&issuer=" + encodedIssuer + "&digits=6&period=30";
    }

    public boolean verifyPlainSecret(String plainSecret, String code) {
        if (plainSecret == null || code == null) {
            return false;
        }
        String normalized = code.replaceAll("\\s", "");
        if (!normalized.matches("\\d{6}")) {
            return false;
        }
        return codeVerifier.isValidCode(plainSecret, normalized);
    }

    public boolean verifyEncryptedSecret(String encryptedSecret, String code) {
        if (encryptedSecret == null || encryptedSecret.isBlank()) {
            return false;
        }
        String plain = encryptionService.decrypt(encryptedSecret);
        return verifyPlainSecret(plain, code);
    }

    public String encryptSecret(String plainSecret) {
        return encryptionService.encrypt(plainSecret);
    }
}
