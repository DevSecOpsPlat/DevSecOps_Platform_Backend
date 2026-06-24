package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.AuditLog;
import com.backend.devsecopsplatform_backend.repository.AuditLogRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditAnalyticsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDayCount;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditLogResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditPageResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditStatsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditTopActor;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditAdminVsUsers;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditEnhancedKpis;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditLoginHourPoint;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditSuspiciousIp;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditTopUser;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditKpiPanel;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditKpiPanelItem;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private static final int TREND_DAYS = 30;
    private static final int TREND_MONTHS = 12;
    private static final int SUSPICIOUS_IP_WINDOW_MINUTES = 5;
    private static final int SUSPICIOUS_IP_FAILURE_THRESHOLD = 3;
    private static final Set<AuditAction> SUSPICIOUS_PANEL_ACTIONS = Set.of(
            AuditAction.LOGIN_FAILED,
            AuditAction.ACCOUNT_LOCKED,
            AuditAction.IP_BLOCKED
    );
    private static final DateTimeFormatter HOUR_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:00");
    private static final DateTimeFormatter DISPLAY_DT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    private static final Set<AuditAction> ADMIN_ACTIONS = Set.of(
            AuditAction.ACCOUNT_CREATED,
            AuditAction.ACCOUNT_DELETED,
            AuditAction.ACCOUNT_ENABLED,
            AuditAction.ACCOUNT_DISABLED,
            AuditAction.ADMIN_PASSWORD_RESET,
            AuditAction.ADMIN_EMAIL_CHANGED,
            AuditAction.ACTIVATION_EMAIL_SENT
    );
    private static final Set<AuditAction> INFO_ACTIONS = Set.of(
            AuditAction.LOGIN_SUCCESS,
            AuditAction.ACCOUNT_ACTIVATED,
            AuditAction.ACTIVATION_EMAIL_SENT,
            AuditAction.ACCOUNT_ENABLED
    );

    private final AuditLogRepository auditLogRepository;

    @Transactional(readOnly = true)
    public AdminAuditPageResponse getPage(
            int page,
            int size,
            UUID userId,
            AuditAction action,
            String search,
            LocalDate from,
            LocalDate to,
            String severity,
            String performedBy,
            LocalTime timeFrom,
            LocalTime timeTo,
            String loginOutcome) {
        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );
        Specification<AuditLog> spec = buildSpecification(
                userId, action, search, from, to, severity, performedBy, timeFrom, timeTo, loginOutcome);
        Page<AuditLog> result = auditLogRepository.findAll(spec, pageable);
        return new AdminAuditPageResponse(
                result.getContent().stream().map(this::toResponse).toList(),
                result.getTotalElements(),
                result.getTotalPages(),
                result.getNumber(),
                result.getSize()
        );
    }

    @Transactional(readOnly = true)
    public AdminAuditStatsResponse getStats() {
        Map<String, Long> byAction = new LinkedHashMap<>();
        for (AuditAction a : AuditAction.values()) {
            byAction.put(a.name(), 0L);
        }
        for (Object[] row : auditLogRepository.countGroupByAction()) {
            AuditAction action = (AuditAction) row[0];
            long count = ((Number) row[1]).longValue();
            byAction.put(action.name(), count);
        }
        long total = byAction.values().stream().mapToLong(Long::longValue).sum();
        return new AdminAuditStatsResponse(total, byAction);
    }

    @Transactional(readOnly = true)
    public AdminAuditAnalyticsResponse getAnalytics() {
        List<AdminAuditDayCount> dailyTrend = buildDailyTrend(TREND_DAYS);
        List<AdminAuditDayCount> monthlyTrend = buildMonthlyTrend(TREND_MONTHS);
        List<AdminAuditDayCount> allTimeTrend = buildAllTimeMonthlyTrend();

        List<AdminAuditTopActor> topAdmins = auditLogRepository.topAdminPerformers().stream()
                .map(row -> new AdminAuditTopActor(String.valueOf(row[0]), ((Number) row[1]).longValue()))
                .toList();

        long total = auditLogRepository.count();
        return new AdminAuditAnalyticsResponse(total, dailyTrend, monthlyTrend, allTimeTrend, topAdmins);
    }

    @Transactional(readOnly = true)
    public AdminAuditDashboardResponse getDashboard() {
        Map<String, Long> byAction = loadCountByAction();
        List<AdminAuditSuspiciousIp> suspicious = getSuspiciousIps();
        AdminAuditEnhancedKpis enhancedKpis = buildEnhancedKpis(byAction, suspicious);
        return new AdminAuditDashboardResponse(
                enhancedKpis,
                getTopUsers(5),
                getLoginComparison(24),
                getAdminVsUsers(byAction),
                suspicious,
                buildKpiPanels(byAction, enhancedKpis, suspicious)
        );
    }

    @Transactional(readOnly = true)
    public List<AdminAuditTopUser> getTopUsers(int limit) {
        return auditLogRepository.topActors(Math.min(Math.max(limit, 1), 20)).stream()
                .map(row -> {
                    String username = String.valueOf(row[0]);
                    long count = ((Number) row[1]).longValue();
                    LocalDateTime lastAt = toLocalDateTime(row[2]);
                    String lastAction = row[3] != null ? String.valueOf(row[3]) : "";
                    String tooltip = String.format(
                            "Utilisateur '%s' : %d action(s). Dernière action : %s le %s.",
                            username,
                            count,
                            lastAction,
                            lastAt != null ? lastAt.format(DISPLAY_DT) : "—"
                    );
                    return new AdminAuditTopUser(username, count, tooltip, lastAction, lastAt);
                })
                .toList();
    }

    @Transactional(readOnly = true)
    public List<AdminAuditLoginHourPoint> getLoginComparison(int hours) {
        int h = Math.min(Math.max(hours, 1), 168);
        LocalDateTime since = LocalDateTime.now().minusHours(h);
        Map<LocalDateTime, long[]> buckets = new LinkedHashMap<>();
        LocalDateTime cursor = since.truncatedTo(ChronoUnit.HOURS);
        LocalDateTime end = LocalDateTime.now().truncatedTo(ChronoUnit.HOURS);
        while (!cursor.isAfter(end)) {
            buckets.put(cursor, new long[]{0, 0});
            cursor = cursor.plusHours(1);
        }
        for (Object[] row : auditLogRepository.loginSuccessFailedByHour(since)) {
            LocalDateTime hour = toLocalDateTime(row[0]);
            if (hour != null) {
                long[] bucket = buckets.computeIfAbsent(hour.truncatedTo(ChronoUnit.HOURS), k -> new long[]{0, 0});
                bucket[0] = ((Number) row[1]).longValue();
                bucket[1] = ((Number) row[2]).longValue();
            }
        }
        long peakFailed = buckets.values().stream().mapToLong(b -> b[1]).max().orElse(0);
        return buckets.entrySet().stream()
                .map(e -> {
                    long success = e.getValue()[0];
                    long failed = e.getValue()[1];
                    long total = success + failed;
                    double rate = total > 0 ? (success * 100.0 / total) : 0;
                    String timeLabel = e.getKey().format(DateTimeFormatter.ofPattern("HH:mm"));
                    String tooltip = String.format(
                            "%s — Succès : %d, Échecs : %d. Taux de succès : %.0f%%.%s",
                            timeLabel,
                            success,
                            failed,
                            rate,
                            failed == peakFailed && peakFailed > 0
                                    ? String.format(" Pic d'échecs (%d échec(s)).", peakFailed)
                                    : ""
                    );
                    return new AdminAuditLoginHourPoint(e.getKey().format(HOUR_FMT), success, failed, tooltip);
                })
                .toList();
    }

    @Transactional(readOnly = true)
    public AdminAuditAdminVsUsers getAdminVsUsers() {
        return getAdminVsUsers(loadCountByAction());
    }

    private AdminAuditAdminVsUsers getAdminVsUsers(Map<String, Long> byAction) {
        long admin = ADMIN_ACTIONS.stream().mapToLong(a -> byAction.getOrDefault(a.name(), 0L)).sum();
        long total = byAction.values().stream().mapToLong(Long::longValue).sum();
        long user = Math.max(0, total - admin);
        double adminPct = total > 0 ? (admin * 100.0 / total) : 0;
        String adminTooltip = String.format(
                "Actions Admin : %.0f%%. %d action(s) effectuées par les administrateurs (connexions, réinitialisations, gestions de comptes).",
                adminPct,
                admin
        );
        String userTooltip = String.format(
                "Actions Utilisateurs : %.0f%%. %d action(s) (connexions, activations, 2FA…).",
                total > 0 ? (100 - adminPct) : 0,
                user
        );
        return new AdminAuditAdminVsUsers(admin, user, adminPct, adminTooltip, userTooltip);
    }

    @Transactional(readOnly = true)
    public List<AdminAuditSuspiciousIp> getSuspiciousIps() {
        Map<String, AdminAuditSuspiciousIp> byIp = new LinkedHashMap<>();

        for (Object[] row : auditLogRepository.suspiciousLoginIpsAllTime(SUSPICIOUS_IP_FAILURE_THRESHOLD)) {
            String ip = String.valueOf(row[0]);
            long burstCount = ((Number) row[1]).longValue();
            LocalDateTime lastAt = toLocalDateTime(row[2]);
            byIp.put(ip, new AdminAuditSuspiciousIp(
                    ip,
                    burstCount,
                    String.format(
                            "IP %s : %d échec(s) max en une fenêtre de %d min (historique complet). Dernière tentative : %s.",
                            ip,
                            burstCount,
                            SUSPICIOUS_IP_WINDOW_MINUTES,
                            lastAt != null ? lastAt.format(DISPLAY_DT) : "—"
                    ),
                    lastAt
            ));
        }

        for (Object[] row : auditLogRepository.lockedAccountIpsAllTime()) {
            String ip = String.valueOf(row[0]);
            long lockCount = ((Number) row[1]).longValue();
            LocalDateTime lastAt = toLocalDateTime(row[2]);
            AdminAuditSuspiciousIp existing = byIp.get(ip);
            if (existing != null) {
                byIp.put(ip, new AdminAuditSuspiciousIp(
                        ip,
                        existing.failureCount(),
                        existing.tooltip() + String.format(
                                " Compte verrouillé %d fois — dernier verrouillage : %s.",
                                lockCount,
                                lastAt != null ? lastAt.format(DISPLAY_DT) : "—"
                        ),
                        lastAt != null && (existing.lastFailureAt() == null || lastAt.isAfter(existing.lastFailureAt()))
                                ? lastAt
                                : existing.lastFailureAt()
                ));
            } else {
                byIp.put(ip, new AdminAuditSuspiciousIp(
                        ip,
                        lockCount,
                        String.format(
                                "IP %s : compte verrouillé %d fois (historique complet). Dernier verrouillage : %s.",
                                ip,
                                lockCount,
                                lastAt != null ? lastAt.format(DISPLAY_DT) : "—"
                        ),
                        lastAt
                ));
            }
        }

        return new ArrayList<>(byIp.values());
    }

    private AdminAuditEnhancedKpis buildEnhancedKpis(Map<String, Long> byAction, List<AdminAuditSuspiciousIp> suspicious) {
        long loginSuccess = byAction.getOrDefault(AuditAction.LOGIN_SUCCESS.name(), 0L);
        long loginFailed = byAction.getOrDefault(AuditAction.LOGIN_FAILED.name(), 0L);
        long loginTotal = loginSuccess + loginFailed;
        double rate = loginTotal > 0 ? (loginSuccess * 100.0 / loginTotal) : 100.0;

        long activeUsers = auditLogRepository.countDistinctActorsSince(LocalDateTime.now().minusHours(24));
        long adminActions = ADMIN_ACTIONS.stream().mapToLong(a -> byAction.getOrDefault(a.name(), 0L)).sum();

        return new AdminAuditEnhancedKpis(
                Math.round(rate * 10) / 10.0,
                "Taux de connexions réussies vs échouées. Un taux bas peut indiquer une attaque par force brute.",
                activeUsers,
                "Utilisateurs distincts ayant généré au moins une entrée d'audit dans les dernières 24 h.",
                adminActions,
                "Total des actions admin : réinitialisations, changements e-mail, activation/désactivation de comptes.",
                suspicious.size(),
                "IPs suspectes : rafales de connexions échouées (> "
                        + SUSPICIOUS_IP_FAILURE_THRESHOLD + " en " + SUSPICIOUS_IP_WINDOW_MINUTES
                        + " min) ou impliquées dans un verrouillage de compte — historique complet."
        );
    }

    private List<AdminAuditKpiPanel> buildKpiPanels(
            Map<String, Long> byAction,
            AdminAuditEnhancedKpis kpis,
            List<AdminAuditSuspiciousIp> suspicious) {
        long total = byAction.values().stream().mapToLong(Long::longValue).sum();
        long loginSuccess = byAction.getOrDefault(AuditAction.LOGIN_SUCCESS.name(), 0L);
        long loginFailed = byAction.getOrDefault(AuditAction.LOGIN_FAILED.name(), 0L);
        AdminAuditAdminVsUsers adminVsUsers = getAdminVsUsers(byAction);

        return List.of(
                buildLogPanel(
                        "total",
                        "Total entrées",
                        "Nombre total d'événements enregistrés dans le journal d'audit (historique complet).",
                        total,
                        total + " entrée(s) — historique complet",
                        auditLogRepository.findAllByOrderByCreatedAtDesc()
                ),
                buildLoginPanel(
                        "loginRate",
                        "Taux succès login",
                        kpis.loginSuccessTooltip(),
                        Math.round(kpis.loginSuccessRatePercent()),
                        String.format("%.1f%% · %d succès / %d échecs", kpis.loginSuccessRatePercent(), loginSuccess, loginFailed),
                        auditLogRepository.findByActionInOrderByCreatedAtDesc(
                                List.of(AuditAction.LOGIN_SUCCESS, AuditAction.LOGIN_FAILED))
                ),
                buildActiveUsersPanel(kpis.activeUsers24h()),
                buildLogPanel(
                        "adminActions",
                        "Actions admin",
                        kpis.adminActionsTooltip(),
                        kpis.adminActionsCount(),
                        kpis.adminActionsCount() + " action(s) admin — historique complet",
                        auditLogRepository.findByActionInOrderByCreatedAtDesc(new ArrayList<>(ADMIN_ACTIONS))
                ),
                buildSuspiciousPanel(suspicious),
                buildLogPanel(
                        "loginSuccess",
                        "Connexions réussies",
                        "Connexions authentifiées avec succès (historique complet).",
                        loginSuccess,
                        loginSuccess + " connexion(s) réussie(s)",
                        auditLogRepository.findByActionOrderByCreatedAtDesc(AuditAction.LOGIN_SUCCESS)
                ),
                buildLogPanel(
                        "loginFailed",
                        "Connexions échouées",
                        "Tentatives de connexion refusées — indicateur de force brute potentielle.",
                        loginFailed,
                        loginFailed + " connexion(s) échouée(s)",
                        auditLogRepository.findByActionOrderByCreatedAtDesc(AuditAction.LOGIN_FAILED)
                ),
                buildLogPanel(
                        "adminShare",
                        "Part actions admin",
                        adminVsUsers.adminTooltip(),
                        Math.round(adminVsUsers.adminPercent()),
                        String.format("%.0f%% admin · %d admin / %d utilisateur(s)",
                                adminVsUsers.adminPercent(),
                                adminVsUsers.adminActions(),
                                adminVsUsers.userActions()),
                        auditLogRepository.findByActionInOrderByCreatedAtDesc(new ArrayList<>(ADMIN_ACTIONS))
                )
        );
    }

    private AdminAuditKpiPanel buildLogPanel(
            String key,
            String title,
            String hover,
            long count,
            String hint,
            List<AuditLog> logs) {
        List<AdminAuditKpiPanelItem> items = logs.stream()
                .map(this::toPanelItem)
                .toList();
        return new AdminAuditKpiPanel(key, title, hover, count, hint, items);
    }

    private AdminAuditKpiPanel buildLoginPanel(
            String key,
            String title,
            String hover,
            long count,
            String hint,
            List<AuditLog> logs) {
        return buildLogPanel(key, title, hover, count, hint, logs);
    }

    private AdminAuditKpiPanel buildActiveUsersPanel(long activeCount) {
        List<AdminAuditKpiPanelItem> items = auditLogRepository.allActiveUsersLastActivity().stream()
                .map(row -> {
                    String actor = String.valueOf(row[0]);
                    String action = row[1] != null ? String.valueOf(row[1]) : "";
                    String details = row[2] != null ? String.valueOf(row[2]) : "";
                    String ip = row[3] != null ? String.valueOf(row[3]) : null;
                    LocalDateTime at = toLocalDateTime(row[4]);
                    String performer = row[5] != null ? String.valueOf(row[5]) : null;
                    return new AdminAuditKpiPanelItem(
                            actor,
                            actionLabel(action) + (StringUtils.hasText(details) ? " — " + truncate(details, 80) : ""),
                            "Effectué par : " + (StringUtils.hasText(performer) ? performer : actor)
                                    + " · IP : " + formatIp(ip),
                            ip,
                            at
                    );
                })
                .toList();
        return new AdminAuditKpiPanel(
                "activeUsers",
                "Utilisateurs actifs (24 h)",
                "Utilisateurs distincts ayant généré au moins une entrée d'audit dans les dernières 24 h.",
                activeCount,
                activeCount + " utilisateur(s) actif(s) — détail : dernière activité de chaque compte (historique complet)",
                items
        );
    }

    private AdminAuditKpiPanel buildSuspiciousPanel(List<AdminAuditSuspiciousIp> suspicious) {
        List<AuditLog> events = auditLogRepository.findByActionInOrderByCreatedAtDesc(
                new ArrayList<>(SUSPICIOUS_PANEL_ACTIONS));
        List<AdminAuditKpiPanelItem> items = events.stream()
                .map(this::toPanelItem)
                .toList();
        return new AdminAuditKpiPanel(
                "suspicious",
                "IP suspectes",
                "Échecs de connexion, verrouillages de compte et IP bloquées — analyse sur l'historique complet.",
                suspicious.size(),
                suspicious.size() + " IP suspecte(s) · " + events.size() + " événement(s) liés — historique complet",
                items
        );
    }

    private AdminAuditKpiPanelItem toPanelItem(AuditLog log) {
        String actor = StringUtils.hasText(log.getUsername())
                ? log.getUsername()
                : (StringUtils.hasText(log.getPerformedBy()) ? log.getPerformedBy() : "—");
        return new AdminAuditKpiPanelItem(
                actionLabel(log.getAction().name()),
                actor + (StringUtils.hasText(log.getDetails()) ? " — " + truncate(log.getDetails(), 100) : ""),
                "IP : " + formatIp(log.getIpAddress()) + " · " + log.getCreatedAt().format(DISPLAY_DT),
                log.getIpAddress(),
                log.getCreatedAt()
        );
    }

    private Map<String, Long> loadCountByAction() {
        Map<String, Long> byAction = new LinkedHashMap<>();
        for (AuditAction a : AuditAction.values()) {
            byAction.put(a.name(), 0L);
        }
        for (Object[] row : auditLogRepository.countGroupByAction()) {
            byAction.put(((AuditAction) row[0]).name(), ((Number) row[1]).longValue());
        }
        return byAction;
    }

    private String actionLabel(String action) {
        return switch (action) {
            case "LOGIN_SUCCESS" -> "Connexion réussie";
            case "LOGIN_FAILED" -> "Connexion échouée";
            case "ACCOUNT_CREATED" -> "Compte créé (admin)";
            case "ACCOUNT_DELETED" -> "Compte supprimé (admin)";
            case "ACCOUNT_ACTIVATED" -> "Compte activé (1ère connexion)";
            case "ACTIVATION_EMAIL_SENT" -> "E-mail d'activation envoyé";
            case "ACCOUNT_ENABLED" -> "Compte réactivé (admin)";
            case "ACCOUNT_DISABLED" -> "Compte désactivé (admin)";
            case "ADMIN_PASSWORD_RESET" -> "Mot de passe réinitialisé (admin)";
            case "ADMIN_EMAIL_CHANGED" -> "E-mail modifié (admin)";
            case "PASSWORD_CHANGED" -> "Mot de passe modifié";
            case "EMAIL_CHANGED" -> "E-mail modifié";
            case "ACCOUNT_LOCKED" -> "Verrouillage compte";
            case "SUSPICIOUS_ACTIVITY" -> "Activité suspecte";
            case "IP_BLOCKED" -> "IP bloquée";
            case "TWO_FACTOR_ENABLED" -> "2FA activée";
            case "TWO_FACTOR_DISABLED" -> "2FA désactivée";
            case "TWO_FACTOR_FAILED" -> "2FA échouée";
            case "TWO_FACTOR_METHOD_CHANGED" -> "Méthode 2FA changée";
            default -> action;
        };
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max - 1) + "…";
    }

    private String formatIp(String ip) {
        return StringUtils.hasText(ip) ? ip.trim() : "—";
    }

    private List<AdminAuditDayCount> buildDailyTrend(int days) {
        LocalDateTime since = LocalDate.now().minusDays(days - 1L).atStartOfDay();
        Map<LocalDate, Long> byDay = new LinkedHashMap<>();
        LocalDate start = since.toLocalDate();
        LocalDate end = LocalDate.now();
        for (LocalDate d = start; !d.isAfter(end); d = d.plusDays(1)) {
            byDay.put(d, 0L);
        }
        for (Object[] row : auditLogRepository.countByDaySince(since)) {
            LocalDate day = toLocalDate(row[0]);
            if (day != null && byDay.containsKey(day)) {
                byDay.put(day, ((Number) row[1]).longValue());
            }
        }
        return byDay.entrySet().stream()
                .map(e -> new AdminAuditDayCount(e.getKey().toString(), e.getValue()))
                .toList();
    }

    private List<AdminAuditDayCount> buildMonthlyTrend(int months) {
        LocalDate firstMonth = LocalDate.now().minusMonths(months - 1L).withDayOfMonth(1);
        LocalDateTime since = firstMonth.atStartOfDay();
        Map<LocalDate, Long> byMonth = new LinkedHashMap<>();
        LocalDate cursor = firstMonth;
        LocalDate endMonth = LocalDate.now().withDayOfMonth(1);
        while (!cursor.isAfter(endMonth)) {
            byMonth.put(cursor, 0L);
            cursor = cursor.plusMonths(1);
        }
        for (Object[] row : auditLogRepository.countByMonthSince(since)) {
            LocalDate month = toLocalDate(row[0]);
            if (month != null && byMonth.containsKey(month)) {
                byMonth.put(month, ((Number) row[1]).longValue());
            }
        }
        return byMonth.entrySet().stream()
                .map(e -> new AdminAuditDayCount(e.getKey().toString(), e.getValue()))
                .toList();
    }

    private List<AdminAuditDayCount> buildAllTimeMonthlyTrend() {
        Map<LocalDate, Long> byMonth = new LinkedHashMap<>();
        for (Object[] row : auditLogRepository.countAllByMonth()) {
            LocalDate month = toLocalDate(row[0]);
            if (month != null) {
                byMonth.put(month, ((Number) row[1]).longValue());
            }
        }
        return byMonth.entrySet().stream()
                .map(e -> new AdminAuditDayCount(e.getKey().toString(), e.getValue()))
                .toList();
    }

    private Specification<AuditLog> buildSpecification(
            UUID userId,
            AuditAction action,
            String search,
            LocalDate from,
            LocalDate to,
            String severity,
            String performedBy,
            LocalTime timeFrom,
            LocalTime timeTo,
            String loginOutcome) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (userId != null) {
                predicates.add(cb.equal(root.get("userId"), userId));
            }
            if (action != null) {
                predicates.add(cb.equal(root.get("action"), action));
            }
            if (StringUtils.hasText(search)) {
                String pattern = "%" + search.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("username")), pattern),
                        cb.like(cb.lower(root.get("details")), pattern),
                        cb.like(cb.lower(root.get("ipAddress")), pattern),
                        cb.like(cb.lower(root.get("performedBy")), pattern)
                ));
            }
            if (StringUtils.hasText(performedBy)) {
                String p = "%" + performedBy.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("performedBy")), p),
                        cb.like(cb.lower(root.get("username")), p)
                ));
            }
            LocalDateTime fromDt = from != null ? from.atStartOfDay() : null;
            if (from != null && timeFrom != null) {
                fromDt = from.atTime(timeFrom);
            }
            if (fromDt != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), fromDt));
            } else if (timeFrom != null && from == null) {
                predicates.add(cb.greaterThanOrEqualTo(
                        root.get("createdAt"),
                        LocalDate.now().atTime(timeFrom)));
            }
            LocalDateTime toDt = to != null ? to.atTime(LocalTime.MAX) : null;
            if (to != null && timeTo != null) {
                toDt = to.atTime(timeTo);
            }
            if (toDt != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), toDt));
            } else if (timeTo != null && to == null) {
                predicates.add(cb.lessThanOrEqualTo(
                        root.get("createdAt"),
                        LocalDate.now().atTime(timeTo)));
            }
            if (StringUtils.hasText(severity)) {
                String sev = severity.trim().toUpperCase(Locale.ROOT);
                if ("INFO".equals(sev)) {
                    predicates.add(root.get("action").in(INFO_ACTIONS));
                } else if ("ATTENTION".equals(sev)) {
                    predicates.add(cb.not(root.get("action").in(INFO_ACTIONS)));
                }
            }
            if (StringUtils.hasText(loginOutcome)) {
                String outcome = loginOutcome.trim().toUpperCase(Locale.ROOT);
                if ("SUCCESS".equals(outcome)) {
                    predicates.add(cb.equal(root.get("action"), AuditAction.LOGIN_SUCCESS));
                } else if ("FAILED".equals(outcome)) {
                    predicates.add(cb.equal(root.get("action"), AuditAction.LOGIN_FAILED));
                }
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private AdminAuditLogResponse toResponse(AuditLog log) {
        return new AdminAuditLogResponse(
                log.getId(),
                log.getCreatedAt(),
                log.getUsername(),
                log.getUserId(),
                log.getAction().name(),
                log.getDetails(),
                log.getPerformedBy(),
                log.getIpAddress()
        );
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

    private LocalDateTime toLocalDateTime(Object value) {
        if (value instanceof LocalDateTime ldt) {
            return ldt;
        }
        if (value instanceof java.sql.Timestamp ts) {
            return ts.toLocalDateTime();
        }
        if (value instanceof java.util.Date ud) {
            return ud.toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDateTime();
        }
        return null;
    }
}
