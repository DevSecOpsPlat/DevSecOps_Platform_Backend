package com.backend.devsecopsplatform_backend.service.auth;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session intermédiaire après mot de passe valide, en attente du second facteur (5 min).
 */
@Service
public class PendingLoginService {

    private static final int TTL_MINUTES = 5;

    private final Map<String, PendingLogin> pending = new ConcurrentHashMap<>();

    public String create(UUID userId, String ip) {
        return create(userId, ip, null);
    }

    public String create(UUID userId, String ip, String emailOtpCode) {
        String id = UUID.randomUUID().toString();
        pending.put(id, new PendingLogin(userId, ip, LocalDateTime.now().plusMinutes(TTL_MINUTES), emailOtpCode));
        return id;
    }

    public void updateEmailOtp(String pendingLoginId, String emailOtpCode) {
        PendingLogin entry = pending.get(pendingLoginId);
        if (entry != null) {
            pending.put(pendingLoginId, new PendingLogin(
                    entry.userId(), entry.ip(), entry.expiresAt(), emailOtpCode));
        }
    }

    public Optional<PendingLogin> findValid(String pendingLoginId) {
        if (pendingLoginId == null || pendingLoginId.isBlank()) {
            return Optional.empty();
        }
        PendingLogin entry = pending.get(pendingLoginId);
        if (entry == null || entry.expiresAt().isBefore(LocalDateTime.now())) {
            pending.remove(pendingLoginId);
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    public void remove(String pendingLoginId) {
        if (pendingLoginId != null) {
            pending.remove(pendingLoginId);
        }
    }

    public record PendingLogin(UUID userId, String ip, LocalDateTime expiresAt, String emailOtpCode) {}
}
