package com.backend.devsecopsplatform_backend.service.auth;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Codes OTP e-mail en mémoire (activation, changement de méthode). TTL 10 min. */
@Service
public class TwoFactorEmailOtpService {

    private static final int TTL_MINUTES = 10;
    private final SecureRandom random = new SecureRandom();
    private final Map<UUID, PendingEmailOtp> pendingByUser = new ConcurrentHashMap<>();

    public String createForUser(UUID userId) {
        String code = generateCode();
        pendingByUser.put(userId, new PendingEmailOtp(code, LocalDateTime.now().plusMinutes(TTL_MINUTES)));
        return code;
    }

    public boolean verifyForUser(UUID userId, String code) {
        PendingEmailOtp pending = pendingByUser.get(userId);
        if (pending == null || pending.expiresAt().isBefore(LocalDateTime.now())) {
            pendingByUser.remove(userId);
            return false;
        }
        if (!pending.code().equals(normalize(code))) {
            return false;
        }
        pendingByUser.remove(userId);
        return true;
    }

    public boolean peekForUser(UUID userId, String code) {
        PendingEmailOtp pending = pendingByUser.get(userId);
        if (pending == null || pending.expiresAt().isBefore(LocalDateTime.now())) {
            pendingByUser.remove(userId);
            return false;
        }
        return pending.code().equals(normalize(code));
    }

    public void clearForUser(UUID userId) {
        pendingByUser.remove(userId);
    }

    public Optional<PendingEmailOtp> findForUser(UUID userId) {
        PendingEmailOtp pending = pendingByUser.get(userId);
        if (pending == null || pending.expiresAt().isBefore(LocalDateTime.now())) {
            pendingByUser.remove(userId);
            return Optional.empty();
        }
        return Optional.of(pending);
    }

    public String generateCode() {
        return String.format("%06d", random.nextInt(1_000_000));
    }

    private String normalize(String code) {
        return code == null ? "" : code.replaceAll("\\s", "");
    }

    public record PendingEmailOtp(String code, LocalDateTime expiresAt) {}
}
