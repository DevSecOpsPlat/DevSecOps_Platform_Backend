package com.backend.devsecopsplatform_backend.service.security.monitoring;

import com.backend.devsecopsplatform_backend.configuration.SecurityMonitoringProperties;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.LoginAttemptRepository;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@RequiredArgsConstructor
public class IpBruteForceService {

    private final SecurityMonitoringProperties properties;
    private final LoginAttemptRepository loginAttemptRepository;
    private final SecurityMonitoringService monitoringService;
    private final SecurityEventService securityEventService;
    private final IpBlocklistService blocklistService;

    private final Map<String, AnonWindow> anonymousFailures = new ConcurrentHashMap<>();

    public void checkIpBlockedBeforeLogin(String ip) {
        if (blocklistService.isBlocked(ip)) {
            throw new IpBlockedException("Adresse IP temporairement bloquée pour activité suspecte.");
        }
    }

    public void recordKnownUserFailure(String ip, User user) {
        if (monitoringService.shouldBypassMonitoring(ip)) {
            return;
        }
        evaluateIp(ip, user != null ? user.getUsername() : null);
    }

    public void recordAnonymousFailure(String ip, String attemptedIdentifier) {
        if (monitoringService.shouldBypassMonitoring(ip)) {
            return;
        }
        incrementAnonymous(normalizeIpKey(ip));

        String message = String.format(
                "Connexion échouée — identifiant inconnu « %s » — IP : %s",
                maskIdentifier(attemptedIdentifier),
                ip
        );
        securityEventService.createAlert(AlertType.LOGIN_FAILED, message, null, ip);

        evaluateIp(ip, "identifiant inconnu : " + maskIdentifier(attemptedIdentifier));
    }

    private void incrementAnonymous(String key) {
        int windowMinutes = properties.getBruteForce().getIpWindowMinutes();
        long windowMs = windowMinutes * 60_000L;
        long now = System.currentTimeMillis();
        AnonWindow window = anonymousFailures.computeIfAbsent(key, k -> new AnonWindow(now));
        synchronized (window) {
            if (now - window.startMs > windowMs) {
                window.startMs = now;
                window.count.set(0);
            }
            window.count.incrementAndGet();
        }
    }

    private void evaluateIp(String ip, String lastDetail) {
        SecurityMonitoringProperties.BruteForce cfg = properties.getBruteForce();
        LocalDateTime since = LocalDateTime.now().minusMinutes(cfg.getIpWindowMinutes());

        long dbFailures = loginAttemptRepository.countBySuccessFalseAndIpAddressAndAttemptedAtAfter(ip, since);
        int anonFailures = currentAnonymousCount(ip, cfg.getIpWindowMinutes());
        long total = dbFailures + anonFailures;

        if (total >= cfg.getIpFailureThreshold()) {
            monitoringService.handleBruteForceDetected(
                    ip,
                    total,
                    "Dernière tentative : " + (lastDetail != null ? lastDetail : "—")
            );
            anonymousFailures.remove(normalizeIpKey(ip));
        }
    }

    private int currentAnonymousCount(String ip, int windowMinutes) {
        String key = normalizeIpKey(ip);
        AnonWindow window = anonymousFailures.get(key);
        if (window == null) {
            return 0;
        }
        long windowMs = windowMinutes * 60_000L;
        synchronized (window) {
            if (System.currentTimeMillis() - window.startMs > windowMs) {
                return 0;
            }
            return window.count.get();
        }
    }

    private String maskIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return "—";
        }
        if (identifier.length() <= 3) {
            return "***";
        }
        return identifier.substring(0, 2) + "***";
    }

    private String normalizeIpKey(String ip) {
        return ip != null ? ip.replace(" (localhost)", "").trim() : "unknown";
    }

    private static final class AnonWindow {
        volatile long startMs;
        final AtomicInteger count = new AtomicInteger(0);

        AnonWindow(long startMs) {
            this.startMs = startMs;
        }
    }

    public static class IpBlockedException extends RuntimeException {
        public IpBlockedException(String message) {
            super(message);
        }
    }
}
