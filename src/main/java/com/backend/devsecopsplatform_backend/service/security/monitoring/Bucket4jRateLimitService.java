package com.backend.devsecopsplatform_backend.service.security.monitoring;

import com.backend.devsecopsplatform_backend.configuration.SecurityMonitoringProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiting avancé par IP avec Bucket4j (token bucket / fenêtre glissante).
 */
@Service
@RequiredArgsConstructor
public class Bucket4jRateLimitService {

    public enum Scope {
        GLOBAL,
        LOGIN,
        ADMIN
    }

    private final SecurityMonitoringProperties properties;
    private final Map<String, Bucket> globalBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> adminBuckets = new ConcurrentHashMap<>();

    public RateLimitResult tryConsume(String ip, Scope scope) {
        SecurityMonitoringProperties.RateLimit cfg = properties.getRateLimit();
        return switch (scope) {
            case GLOBAL -> consume(globalBuckets, ip, cfg.getMaxRequests(), cfg.getWindowSeconds());
            case LOGIN -> consume(loginBuckets, ip, cfg.getLoginMaxRequests(), cfg.getLoginWindowSeconds());
            case ADMIN -> consume(adminBuckets, ip, cfg.getAdminMaxRequests(), cfg.getAdminWindowSeconds());
        };
    }

    private RateLimitResult consume(Map<String, Bucket> store, String ip, int capacity, int windowSeconds) {
        String key = normalizeIp(ip);
        Bucket bucket = store.computeIfAbsent(key, k -> newBucket(capacity, windowSeconds));
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return new RateLimitResult(
                probe.isConsumed(),
                probe.getRemainingTokens(),
                capacity,
                windowSeconds
        );
    }

    private Bucket newBucket(int capacity, int windowSeconds) {
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillIntervally(capacity, Duration.ofSeconds(Math.max(1, windowSeconds)))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        return ip.replace(" (localhost)", "").trim();
    }

    public record RateLimitResult(
            boolean allowed,
            long remainingTokens,
            int limit,
            int windowSeconds
    ) {}
}
