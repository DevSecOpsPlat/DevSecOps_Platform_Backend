package com.backend.devsecopsplatform_backend.service.auth;

import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.LoginAttempt;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.LoginAttemptRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminFailedLoginEntry;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminLoginDayStats;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityAlert;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityAttempt;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUsersDashboardStats;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class LoginAuditService {

    private static final int ALERT_THRESHOLD = 3;
    private static final int LOCKOUT_MINUTES = 15;
    private static final int STATS_WINDOW_DAYS = 30;
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;
    private final SecurityEventService securityEventService;

    @Transactional
    public void recordSuccess(User user, String ipAddress) {
        user.setLastLoginAt(LocalDateTime.now());
        user.setLockedUntil(null);
        userRepository.save(user);
        saveAttempt(user, true, ipAddress);
        securityEventService.recordAudit(
                AuditAction.LOGIN_SUCCESS,
                user,
                "Connexion réussie",
                user.getUsername(),
                ipAddress
        );
    }

    @Transactional
    public void recordFailure(User user, String ipAddress) {
        saveAttempt(user, false, ipAddress);
        securityEventService.recordAudit(
                AuditAction.LOGIN_FAILED,
                user,
                "Tentative de connexion échouée",
                user.getUsername(),
                ipAddress
        );

        if (user.isAdmin()) {
            return;
        }

        long consecutive = countRecentFailuresSinceLastSuccess(user);
        if (consecutive >= ALERT_THRESHOLD && !user.isLocked()) {
            LocalDateTime lockedUntil = LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES);
            user.setLockedUntil(lockedUntil);
            userRepository.save(user);

            String message = String.format(
                    "Utilisateur : %s%nDate : %s%nÉchec de connexion : %d tentatives consécutives%nAdresse IP : %s",
                    user.getEmail(),
                    LocalDateTime.now().format(FMT),
                    consecutive,
                    ipAddress != null ? ipAddress : "—"
            );
            securityEventService.createAlert(AlertType.FAILED_LOGIN_REPEATED, message, user, ipAddress);
            securityEventService.createAlert(AlertType.ACCOUNT_LOCKED, message, user, ipAddress);
            securityEventService.recordAudit(
                    AuditAction.ACCOUNT_LOCKED,
                    user,
                    consecutive + " échecs consécutifs — verrouillage 15 min",
                    "system",
                    ipAddress
            );
        }
    }

    @Transactional(readOnly = true)
    public long countRecentFailuresSinceLastSuccess(User user) {
        LocalDateTime since = loginAttemptRepository
                .findTopByUserAndSuccessTrueOrderByAttemptedAtDesc(user)
                .map(LoginAttempt::getAttemptedAt)
                .orElse(LocalDateTime.of(1970, 1, 1, 0, 0));
        return loginAttemptRepository
                .findByUserAndSuccessFalseAndAttemptedAtAfterOrderByAttemptedAtAsc(user, since)
                .size();
    }

    @Transactional(readOnly = true)
    public AdminUsersDashboardStats getDashboardStats() {
        LocalDateTime since = LocalDateTime.now().minusDays(STATS_WINDOW_DAYS);

        List<LoginAttempt> failedNonAdmin = loginAttemptRepository.findFailedSinceWithUser(since).stream()
                .filter(a -> !a.getUser().isAdmin())
                .toList();

        List<AdminFailedLoginEntry> failedDetail = failedNonAdmin.stream()
                .map(a -> new AdminFailedLoginEntry(
                        a.getUser().getId(),
                        a.getUser().getUsername(),
                        a.getUser().getEmail(),
                        a.getAttemptedAt(),
                        a.getIpAddress()
                ))
                .toList();

        return new AdminUsersDashboardStats(
                failedDetail.size(),
                buildLoginChart(since),
                buildSecurityAlerts(failedNonAdmin),
                failedDetail
        );
    }

    private void saveAttempt(User user, boolean success, String ipAddress) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUser(user);
        attempt.setSuccess(success);
        attempt.setIpAddress(ipAddress);
        loginAttemptRepository.save(attempt);
    }

    private List<AdminLoginDayStats> buildLoginChart(LocalDateTime since) {
        Map<LocalDate, long[]> byDay = new HashMap<>();
        LocalDate start = since.toLocalDate();
        LocalDate end = LocalDate.now();
        for (LocalDate d = start; !d.isAfter(end); d = d.plusDays(1)) {
            byDay.put(d, new long[]{0, 0});
        }
        for (Object[] row : loginAttemptRepository.countByDaySinceNonAdmin(since)) {
            LocalDate day = toLocalDate(row[0]);
            if (day == null || !byDay.containsKey(day)) {
                continue;
            }
            boolean success = Boolean.TRUE.equals(row[1]);
            long count = ((Number) row[2]).longValue();
            long[] acc = byDay.get(day);
            if (success) {
                acc[0] += count;
            } else {
                acc[1] += count;
            }
        }
        List<AdminLoginDayStats> out = new ArrayList<>();
        for (LocalDate d = start; !d.isAfter(end); d = d.plusDays(1)) {
            long[] acc = byDay.get(d);
            out.add(new AdminLoginDayStats(d.toString(), acc[0], acc[1]));
        }
        return out;
    }

    private List<AdminSecurityAlert> buildSecurityAlerts(List<LoginAttempt> failedNonAdmin) {
        Map<User, List<LoginAttempt>> byUser = failedNonAdmin.stream()
                .collect(Collectors.groupingBy(
                        LoginAttempt::getUser,
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        List<AdminSecurityAlert> alerts = new ArrayList<>();
        for (Map.Entry<User, List<LoginAttempt>> entry : byUser.entrySet()) {
            List<LoginAttempt> failures = entry.getValue();
            if (failures.size() < ALERT_THRESHOLD) {
                continue;
            }
            List<AdminSecurityAttempt> attempts = failures.stream()
                    .sorted((a, b) -> a.getAttemptedAt().compareTo(b.getAttemptedAt()))
                    .map(a -> new AdminSecurityAttempt(a.getAttemptedAt(), a.getIpAddress()))
                    .toList();
            User user = entry.getKey();
            alerts.add(new AdminSecurityAlert(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    failures.size(),
                    attempts
            ));
        }
        alerts.sort((a, b) -> Integer.compare(b.failedCount(), a.failedCount()));
        return alerts;
    }

    private LocalDate toLocalDate(Object value) {
        if (value instanceof LocalDate ld) {
            return ld;
        }
        if (value instanceof java.sql.Date sd) {
            return sd.toLocalDate();
        }
        if (value instanceof java.util.Date ud) {
            return ud.toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDate();
        }
        return null;
    }
}
