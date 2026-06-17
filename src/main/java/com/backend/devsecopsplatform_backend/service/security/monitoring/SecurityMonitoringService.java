package com.backend.devsecopsplatform_backend.service.security.monitoring;

import com.backend.devsecopsplatform_backend.configuration.SecurityMonitoringProperties;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringService {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    private static final int ALERT_COOLDOWN_MINUTES = 5;

    private final SecurityMonitoringProperties properties;
    private final IpBlocklistService blocklistService;
    private final SecurityEventService securityEventService;
    private final Map<String, LocalDateTime> alertCooldown = new ConcurrentHashMap<>();

    public boolean shouldBypassMonitoring(String ip) {
        if (!properties.isMonitoringEnabled()) {
            return true;
        }
        return properties.isTrustLocalhost() && isLocalhost(ip);
    }

    public void handleThreat(String ip, String method, String uri, ThreatScanResult threat, String detailsJson) {
        if (shouldBypassMonitoring(ip)) {
            return;
        }
        AlertType alertType = mapThreatToAlert(threat.category());
        String message = String.format(
                "%s — %s %s — IP : %s — %s",
                labelFor(threat.category()),
                method,
                uri,
                ip,
                threat.detail()
        );

        if (shouldEmitAlert(ip, alertType.name())) {
            securityEventService.createAlert(alertType, message, null, ip, detailsJson);
            securityEventService.recordAudit(
                    AuditAction.SUSPICIOUS_ACTIVITY,
                    null,
                    message,
                    "system",
                    ip
            );
        }

        if (threat.blockImmediately()) {
            int minutes = properties.getBlocklist().getHoneypotBlockMinutes();
            blocklistService.block(ip, minutes, threat.detail());
            notifyIpBlocked(ip, minutes, threat.detail());
        }
    }

    public void handleRateLimitExceeded(String ip, String scope, int limit, int windowSeconds) {
        if (shouldBypassMonitoring(ip)) {
            return;
        }
        String message = String.format(
                "Pic de requêtes — %d max / %ds (%s) — IP : %s",
                limit,
                windowSeconds,
                scope,
                ip
        );
        if (shouldEmitAlert(ip, AlertType.RATE_LIMIT_EXCEEDED.name())) {
            securityEventService.createAlert(AlertType.RATE_LIMIT_EXCEEDED, message, null, ip);
        }
        blocklistService.block(ip, properties.getBlocklist().getRateLimitBlockMinutes(), "Rate limit dépassé");
        notifyIpBlocked(ip, properties.getBlocklist().getRateLimitBlockMinutes(), "Rate limit dépassé");
    }

    public void handleBruteForceDetected(String ip, long failureCount, String detail) {
        if (shouldBypassMonitoring(ip)) {
            return;
        }
        int blockMinutes = properties.getBruteForce().getIpBlockMinutes();
        String message = String.format(
                "Force brute détectée — %d échec(s) de connexion en %d min — IP : %s%n%s",
                failureCount,
                properties.getBruteForce().getIpWindowMinutes(),
                ip,
                detail
        );
        if (shouldEmitAlert(ip, AlertType.BRUTE_FORCE_DETECTED.name())) {
            securityEventService.createAlert(AlertType.BRUTE_FORCE_DETECTED, message, null, ip);
            securityEventService.recordAudit(
                    AuditAction.SUSPICIOUS_ACTIVITY,
                    null,
                    message,
                    "system",
                    ip
            );
        }
        blocklistService.block(ip, blockMinutes, "Force brute détectée");
        notifyIpBlocked(ip, blockMinutes, "Force brute détectée");
    }

    public void notifyIpBlocked(String ip, int minutes, String reason) {
        LocalDateTime until = LocalDateTime.now().plusMinutes(minutes);
        String message = String.format(
                "IP bloquée automatiquement — %s — jusqu'au %s — %s",
                ip,
                until.format(FMT),
                reason
        );
        if (shouldEmitAlert(ip, AlertType.IP_BLOCKED.name())) {
            securityEventService.createAlert(AlertType.IP_BLOCKED, message, null, ip);
            securityEventService.recordAudit(
                    AuditAction.IP_BLOCKED,
                    null,
                    message,
                    "system",
                    ip
            );
        }
    }

    private boolean shouldEmitAlert(String ip, String alertKey) {
        String key = ip + ":" + alertKey;
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime last = alertCooldown.get(key);
        if (last != null && last.plusMinutes(ALERT_COOLDOWN_MINUTES).isAfter(now)) {
            return false;
        }
        alertCooldown.put(key, now);
        return true;
    }

    private AlertType mapThreatToAlert(ThreatCategory category) {
        return switch (category) {
            case HONEYPOT -> AlertType.HONEYPOT_TRIGGERED;
            case SUSPICIOUS_URL -> AlertType.SUSPICIOUS_REQUEST;
            case SQL_INJECTION, XSS -> AlertType.MALICIOUS_PAYLOAD;
            case SUSPICIOUS_USER_AGENT -> AlertType.SUSPICIOUS_USER_AGENT;
        };
    }

    private String labelFor(ThreatCategory category) {
        return switch (category) {
            case HONEYPOT -> "Honeypot déclenché";
            case SUSPICIOUS_URL -> "URL suspecte";
            case SQL_INJECTION -> "Injection SQL suspecte";
            case XSS -> "XSS suspect";
            case SUSPICIOUS_USER_AGENT -> "User-Agent suspect";
        };
    }

    private boolean isLocalhost(String ip) {
        if (ip == null) {
            return false;
        }
        return ip.contains("127.0.0.1")
                || ip.contains("localhost")
                || "::1".equals(ip)
                || "0:0:0:0:0:0:0:1".equals(ip);
    }
}
