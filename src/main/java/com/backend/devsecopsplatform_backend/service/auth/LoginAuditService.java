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
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
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
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class LoginAuditService {

    public static final int ALERT_THRESHOLD = 3;
    public static final int LOCKOUT_MINUTES = 15;
    private static final int STATS_WINDOW_DAYS = 30;
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;
    private final SecurityEventService securityEventService;

    @Transactional
    public void recordSuccess(User user, String ipAddress) {
        String ip = IpAddressUtils.normalize(ipAddress);
        user.setLastLoginAt(LocalDateTime.now());
        user.setLockedUntil(null);
        userRepository.save(user);
        saveAttempt(user, true, ip);
        securityEventService.recordAudit(
                AuditAction.LOGIN_SUCCESS,
                user,
                "Connexion réussie",
                user.getUsername(),
                ip
        );
    }

    /**
     * Enregistre un échec de connexion. Une alerte est créée à chaque tentative.
     * Verrouillage 15 min après 3 échecs consécutifs (utilisateurs non-admin actifs).
     */
    @Transactional
    public LoginFailureResult recordFailure(User user, String ipAddress) {
        String ip = IpAddressUtils.normalize(ipAddress);
        saveAttempt(user, false, ip);

        long consecutive = countRecentFailuresSinceLastSuccess(user);
        recordLoginFailedAudit(user, ip, consecutive);

        if (user.isPendingActivation()) {
            return LoginFailureResult.notApplicable();
        }

        createLoginFailedAlert(user, ip, consecutive);

        if (user.isAdmin() || !user.isActive()) {
            return LoginFailureResult.notApplicable();
        }

        int remaining = (int) Math.max(0, ALERT_THRESHOLD - consecutive);

        if (consecutive >= ALERT_THRESHOLD && !user.isLocked()) {
            LocalDateTime lockedUntil = LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES);
            user.setLockedUntil(lockedUntil);
            userRepository.save(user);

            String message = String.format(
                    "Compte verrouillé 15 min après %d tentatives incorrectes.%nUtilisateur : %s (%s)%nIP : %s%nDéverrouillage : %s",
                    consecutive,
                    user.getUsername(),
                    user.getEmail(),
                    ip,
                    lockedUntil.format(FMT)
            );
            securityEventService.createAlert(AlertType.ACCOUNT_LOCKED, message, user, ip);
            return new LoginFailureResult(consecutive, true, lockedUntil, 0);
        }

        return new LoginFailureResult(consecutive, false, null, remaining);
    }

    private void createLoginFailedAlert(User user, String ip, long consecutive) {
        StringBuilder message = new StringBuilder();
        message.append(String.format(
                "Connexion échouée — %s (%s) — %d échec(s) consécutif(s) — IP : %s",
                user.getUsername(),
                user.getEmail(),
                consecutive,
                ip
        ));
        securityEventService.createAlert(AlertType.LOGIN_FAILED, message.toString(), user, ip);
    }

    private void recordLoginFailedAudit(User user, String ip, long consecutive) {
        String details = String.format(
                "Connexion échouée — %d échec(s) consécutif(s) — IP : %s",
                consecutive,
                ip
        );
        securityEventService.recordAudit(
                AuditAction.LOGIN_FAILED,
                user,
                details,
                user.getUsername(),
                ip
        );
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
                        IpAddressUtils.normalize(a.getIpAddress())
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
        Map<UUID, User> usersById = new LinkedHashMap<>();
        for (LoginAttempt attempt : failedNonAdmin) {
            User user = attempt.getUser();
            if (user != null && user.getId() != null) {
                usersById.putIfAbsent(user.getId(), user);
            }
        }

        List<AdminSecurityAlert> alerts = new ArrayList<>();
        for (User user : usersById.values()) {
            if (user.isAdmin()) {
                continue;
            }
            List<LoginAttempt> consecutiveFailures = findConsecutiveFailures(user);
            if (consecutiveFailures.size() < ALERT_THRESHOLD && !user.isLocked()) {
                continue;
            }
            List<AdminSecurityAttempt> attempts = consecutiveFailures.stream()
                    .map(a -> new AdminSecurityAttempt(
                            a.getAttemptedAt(),
                            IpAddressUtils.normalize(a.getIpAddress())))
                    .toList();
            alerts.add(new AdminSecurityAlert(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    consecutiveFailures.size(),
                    attempts
            ));
        }
        alerts.sort((a, b) -> Integer.compare(b.failedCount(), a.failedCount()));
        return alerts;
    }

    private List<LoginAttempt> findConsecutiveFailures(User user) {
        LocalDateTime since = loginAttemptRepository
                .findTopByUserAndSuccessTrueOrderByAttemptedAtDesc(user)
                .map(LoginAttempt::getAttemptedAt)
                .orElse(LocalDateTime.of(1970, 1, 1, 0, 0));
        return loginAttemptRepository
                .findByUserAndSuccessFalseAndAttemptedAtAfterOrderByAttemptedAtAsc(user, since);
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
