package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.repository.AlertRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertPageResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertStatsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminAlertHourPoint;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminAlertTypeSlice;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminBlockedIpDetail;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminKpiPanel;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminKpiPanelItem;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminSecurityKpis;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse.AdminTopMaliciousIp;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBlocklistService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBlocklistService.BlockedIpView;
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

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AlertService {

    private static final DateTimeFormatter DAY_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter DISPLAY_DAY = DateTimeFormatter.ofPattern("dd/MM/yyyy");
    private static final DateTimeFormatter DISPLAY_DT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    private static final int TOP_IP_LIMIT = 5;
    private static final int KPI_DETAIL_LIMIT = 50;

    private final AlertRepository alertRepository;
    private final IpBlocklistService blocklistService;

    @Transactional(readOnly = true)
    public List<AdminAlertResponse> listAlerts(AlertStatus status, AlertType type) {
        List<Alert> alerts;
        if (status != null && type != null) {
            alerts = alertRepository.findByDeletedFalseAndStatusAndTypeOrderByCreatedAtDesc(status, type);
        } else if (status != null) {
            alerts = alertRepository.findByDeletedFalseAndStatusOrderByCreatedAtDesc(status);
        } else if (type != null) {
            alerts = alertRepository.findByDeletedFalseAndTypeOrderByCreatedAtDesc(type);
        } else {
            alerts = alertRepository.findByDeletedFalseOrderByCreatedAtDesc();
        }
        return alerts.stream().map(this::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public AdminAlertPageResponse listAlertsPage(
            int page,
            int size,
            AlertStatus status,
            AlertType type,
            String ip,
            LocalDate from,
            LocalDate to) {
        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );
        Specification<Alert> spec = buildSpecification(status, type, ip, from, to);
        Page<Alert> result = alertRepository.findAll(spec, pageable);
        return new AdminAlertPageResponse(
                result.getContent().stream().map(this::toResponse).toList(),
                result.getTotalElements(),
                result.getTotalPages(),
                result.getNumber(),
                result.getSize()
        );
    }

    @Transactional(readOnly = true)
    public AdminAlertResponse getById(UUID id) {
        return toResponse(findOrThrow(id));
    }

    @Transactional(readOnly = true)
    public long countUnread() {
        return alertRepository.countByDeletedFalseAndStatus(AlertStatus.NON_LUE);
    }

    @Transactional(readOnly = true)
    public AdminAlertStatsResponse getStats() {
        List<Alert> all = alertRepository.findByDeletedFalseOrderByCreatedAtDesc();
        long unread = all.stream().filter(a -> a.getStatus() == AlertStatus.NON_LUE).count();
        Map<String, Long> byType = new LinkedHashMap<>();
        for (AlertType t : AlertType.values()) {
            byType.put(t.name(), 0L);
        }
        for (Alert a : all) {
            byType.merge(a.getType().name(), 1L, Long::sum);
        }
        return new AdminAlertStatsResponse(unread, all.size(), byType);
    }

    @Transactional(readOnly = true)
    public AdminSecurityDashboardResponse getSecurityDashboard() {
        List<Alert> allAlerts = alertRepository.findByDeletedFalseOrderByCreatedAtDesc();

        List<BlockedIpView> blockedViews = blocklistService.listBlockedDetailed();
        long activeBlocked = blocklistService.countCurrentlyBlocked();
        List<AdminBlockedIpDetail> blockedDetails = blockedViews.stream()
                .map(v -> new AdminBlockedIpDetail(
                        v.ip(),
                        v.reason(),
                        v.source(),
                        v.currentlyActive(),
                        v.blockedUntil(),
                        v.createdAt()
                ))
                .toList();

        long bruteCount = countBruteForce(allAlerts);
        long honeypotCount = countHoneypot(allAlerts);
        long rateLimitCount = countRateLimit(allAlerts);
        long xssSqlCount = countMaliciousPayload(allAlerts);

        AdminSecurityKpis kpis = new AdminSecurityKpis(
                allAlerts.size(),
                activeBlocked,
                bruteCount,
                honeypotCount,
                rateLimitCount,
                xssSqlCount,
                rateLimitCount
        );

        List<AdminKpiPanel> kpiPanels = List.of(
                buildAlertsPanel(allAlerts),
                buildBlockedPanel(blockedDetails, activeBlocked),
                buildCategoryPanel("brute", "Force brute", HOVER_BRUTE, bruteCount, allAlerts, this::isBruteForceCategory),
                buildCategoryPanel("honeypot", "Honeypot", HOVER_HONEYPOT, honeypotCount, allAlerts, this::isHoneypotCategory),
                buildCategoryPanel("ratelimit", "Rate limit / DDoS applicatif", HOVER_RATE_LIMIT, rateLimitCount, allAlerts, this::isRateLimitCategory),
                buildCategoryPanel("xsssql", "XSS / Injection SQL", HOVER_XSS_SQL, xssSqlCount, allAlerts, this::isXssSqlCategory)
        );

        List<AdminAlertHourPoint> dailyTrend = buildDailyTrend(allAlerts);
        List<AdminAlertTypeSlice> distribution = buildTypeDistribution(allAlerts);
        List<AdminTopMaliciousIp> topIps = buildTopIps(allAlerts);

        return new AdminSecurityDashboardResponse(kpis, kpiPanels, blockedDetails, dailyTrend, distribution, topIps);
    }

    private static final String HOVER_ALERTS =
            "Nombre total d'alertes de sécurité enregistrées (historique complet, hors alertes supprimées).";

    private static final String HOVER_BRUTE =
            "Tentatives répétées de connexion depuis la même IP (≥5 échecs/min). "
                    + "Compte les alertes force brute, verrouillages de compte et blocages IP associés.";
    private static final String HOVER_HONEYPOT =
            "Accès à des URLs pièges (.env, wp-admin, /admin/secret…). Indique un scan ou une reconnaissance malveillante.";
    private static final String HOVER_RATE_LIMIT =
            "Pic de requêtes HTTP depuis une IP (200/min global, 20/min login). "
                    + "Équivalent DDoS applicatif : saturation de l'API avant blocage automatique.";
    private static final String HOVER_XSS_SQL =
            "Payloads XSS ou injection SQL détectés dans l'URL ou les paramètres de la requête.";
    private static final String HOVER_BLOCKED =
            "IP actuellement bloquées + historique des blocages en base (table blocked_ips).";

    private AdminKpiPanel buildAlertsPanel(List<Alert> allAlerts) {
        List<AdminKpiPanelItem> items = allAlerts.stream()
                .limit(KPI_DETAIL_LIMIT)
                .map(a -> new AdminKpiPanelItem(
                        typeLabelForAlert(a),
                        truncate(a.getMessage(), 100),
                        a.getStatus().name() + " · " + a.getCreatedAt().format(DISPLAY_DT),
                        a.getIpAddress(),
                        a.getCreatedAt()
                ))
                .toList();
        return new AdminKpiPanel(
                "alerts",
                "Total alertes",
                HOVER_ALERTS,
                allAlerts.size(),
                allAlerts.size() + " alerte(s) — historique complet",
                items
        );
    }

    private AdminKpiPanel buildBlockedPanel(List<AdminBlockedIpDetail> blocked, long activeCount) {
        List<AdminKpiPanelItem> items = blocked.stream()
                .map(b -> new AdminKpiPanelItem(
                        b.ip(),
                        b.reason(),
                        (b.currentlyActive() ? "Actif — jusqu'au " : "Expiré — était jusqu'au ")
                                + b.blockedUntil().format(DISPLAY_DT),
                        b.ip(),
                        b.createdAt()
                ))
                .toList();
        String hint = activeCount + " IP active(s) · " + blocked.size() + " entrée(s) récente(s) en base";
        return new AdminKpiPanel("blocked", "IP bloquées", HOVER_BLOCKED, activeCount, hint, items);
    }

    private AdminKpiPanel buildCategoryPanel(
            String key,
            String title,
            String hover,
            long count,
            List<Alert> allAlerts,
            java.util.function.Predicate<Alert> filter) {
        List<AdminKpiPanelItem> items = allAlerts.stream()
                .filter(filter)
                .limit(KPI_DETAIL_LIMIT)
                .map(a -> new AdminKpiPanelItem(
                        typeLabelForAlert(a),
                        truncate(a.getMessage(), 120),
                        "IP : " + formatIp(a.getIpAddress()) + " · " + a.getCreatedAt().format(DISPLAY_DT),
                        a.getIpAddress(),
                        a.getCreatedAt()
                ))
                .toList();
        String hint = count + " événement(s) — historique complet";
        return new AdminKpiPanel(key, title, hover, count, hint, items);
    }

    private String typeLabelForAlert(Alert a) {
        return dashboardTypeLabel(mapDashboardType(a));
    }

    private long countBruteForce(List<Alert> alerts) {
        return alerts.stream().filter(this::isBruteForceCategory).count();
    }

    private long countHoneypot(List<Alert> alerts) {
        return alerts.stream().filter(this::isHoneypotCategory).count();
    }

    private long countRateLimit(List<Alert> alerts) {
        return alerts.stream().filter(this::isRateLimitCategory).count();
    }

    private boolean isBruteForceCategory(Alert a) {
        if (a.getType() == AlertType.BRUTE_FORCE_DETECTED || a.getType() == AlertType.ACCOUNT_LOCKED) {
            return true;
        }
        if (a.getType() == AlertType.IP_BLOCKED) {
            return messageContains(a.getMessage(), "force brute");
        }
        return false;
    }

    private boolean isHoneypotCategory(Alert a) {
        if (a.getType() == AlertType.HONEYPOT_TRIGGERED) {
            return true;
        }
        if (a.getType() == AlertType.SUSPICIOUS_REQUEST) {
            return messageContains(a.getMessage(), "honeypot") || messageContains(a.getMessage(), "piège");
        }
        if (a.getType() == AlertType.IP_BLOCKED) {
            String msg = a.getMessage() != null ? a.getMessage().toLowerCase(Locale.ROOT) : "";
            return msg.contains("honeypot") || msg.contains("payload") || msg.contains("scan");
        }
        return false;
    }

    private boolean isRateLimitCategory(Alert a) {
        if (a.getType() == AlertType.RATE_LIMIT_EXCEEDED) {
            return true;
        }
        if (a.getType() == AlertType.IP_BLOCKED) {
            return messageContains(a.getMessage(), "rate limit");
        }
        return false;
    }

    private boolean isXssSqlCategory(Alert a) {
        if (a.getType() == AlertType.MALICIOUS_PAYLOAD) {
            return true;
        }
        return messageIndicatesXssOrSql(a.getMessage());
    }

    private boolean messageContains(String message, String needle) {
        return message != null && message.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    @Transactional
    public AdminAlertResponse markAsRead(UUID id) {
        Alert alert = findOrThrow(id);
        alert.setStatus(AlertStatus.LUE);
        return toResponse(alertRepository.save(alert));
    }

    @Transactional
    public void softDelete(UUID id) {
        Alert alert = findOrThrow(id);
        alert.setDeleted(true);
        alertRepository.save(alert);
    }

    private Specification<Alert> buildSpecification(
            AlertStatus status,
            AlertType type,
            String ip,
            LocalDate from,
            LocalDate to) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.isFalse(root.get("deleted")));
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (type != null) {
                predicates.add(cb.equal(root.get("type"), type));
            }
            if (StringUtils.hasText(ip)) {
                predicates.add(cb.like(cb.lower(root.get("ipAddress")), "%" + ip.trim().toLowerCase(Locale.ROOT) + "%"));
            }
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), from.atStartOfDay()));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), to.atTime(LocalTime.MAX)));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private List<AdminAlertHourPoint> buildDailyTrend(List<Alert> all) {
        if (all.isEmpty()) {
            return List.of();
        }
        LocalDate start = all.stream()
                .map(a -> a.getCreatedAt().toLocalDate())
                .min(LocalDate::compareTo)
                .orElse(LocalDate.now());
        LocalDate end = LocalDate.now();
        Map<LocalDate, List<Alert>> byDay = new LinkedHashMap<>();
        for (LocalDate d = start; !d.isAfter(end); d = d.plusDays(1)) {
            byDay.put(d, new ArrayList<>());
        }
        for (Alert alert : all) {
            LocalDate day = alert.getCreatedAt().toLocalDate();
            byDay.computeIfAbsent(day, k -> new ArrayList<>()).add(alert);
        }
        return byDay.entrySet().stream()
                .map(e -> {
                    List<Alert> bucket = e.getValue();
                    long count = bucket.size();
                    String tooltip = count == 0
                            ? "Aucune alerte ce jour-là."
                            : buildDayTooltip(e.getKey(), bucket);
                    return new AdminAlertHourPoint(e.getKey().format(DAY_FMT), count, tooltip);
                })
                .toList();
    }

    private String buildDayTooltip(LocalDate day, List<Alert> bucket) {
        String date = day.format(DISPLAY_DAY);
        if (bucket.size() == 1) {
            Alert a = bucket.get(0);
            return String.format(
                    "Le %s : 1 alerte (%s) — IP %s.",
                    date,
                    summarizeType(a.getType()),
                    formatIp(a.getIpAddress())
            );
        }
        Map<String, Long> byIp = bucket.stream()
                .filter(a -> a.getIpAddress() != null)
                .collect(Collectors.groupingBy(Alert::getIpAddress, Collectors.counting()));
        String topIp = byIp.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("inconnue");
        Set<String> types = bucket.stream()
                .map(a -> summarizeType(a.getType()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return String.format(
                "Le %s : %d alerte(s). IP la plus active : %s. Types : %s.",
                date,
                bucket.size(),
                formatIp(topIp),
                String.join(", ", types)
        );
    }

    private List<AdminAlertTypeSlice> buildTypeDistribution(List<Alert> recent) {
        Map<String, Long> grouped = new LinkedHashMap<>();
        grouped.put("HONEYPOT", 0L);
        grouped.put("BRUTE_FORCE", 0L);
        grouped.put("RATE_LIMIT", 0L);
        grouped.put("XSS", 0L);
        grouped.put("SQL_INJECTION", 0L);
        grouped.put("SUSPICIOUS_ACTIVITY", 0L);
        grouped.put("MALICIOUS_PAYLOAD", 0L);

        for (Alert alert : recent) {
            String key = mapDashboardType(alert);
            grouped.merge(key, 1L, Long::sum);
        }

        return grouped.entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .map(e -> new AdminAlertTypeSlice(
                        e.getKey(),
                        dashboardTypeLabel(e.getKey()),
                        e.getValue(),
                        buildTypeTooltip(e.getKey(), e.getValue(), recent)
                ))
                .toList();
    }

    private String buildTypeTooltip(String dashboardType, long count, List<Alert> recent) {
        List<Alert> matching = recent.stream()
                .filter(a -> mapDashboardType(a).equals(dashboardType))
                .toList();
        Set<String> paths = matching.stream()
                .map(this::extractPathFromMessage)
                .filter(StringUtils::hasText)
                .limit(5)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        String pathsText = paths.isEmpty()
                ? "chemins variés"
                : String.join(", ", paths);
        return String.format(
                "%s : %d alerte(s). Exemples de cibles : %s.",
                dashboardTypeLabel(dashboardType),
                count,
                pathsText
        );
    }

    private List<AdminTopMaliciousIp> buildTopIps(List<Alert> alerts) {
        Map<String, List<Alert>> byIp = alerts.stream()
                .filter(a -> StringUtils.hasText(a.getIpAddress()))
                .collect(Collectors.groupingBy(Alert::getIpAddress));

        return byIp.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().size(), a.getValue().size()))
                .limit(TOP_IP_LIMIT)
                .map(e -> {
                    List<Alert> ipAlerts = e.getValue();
                    Alert latest = ipAlerts.stream()
                            .max((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()))
                            .orElse(ipAlerts.get(0));
                    String rel = formatRelativeTime(latest.getCreatedAt());
                    String activity = String.format(
                            "%s — %s",
                            summarizeType(latest.getType()),
                            truncate(latest.getMessage(), 120)
                    );
                    String tooltip = String.format(
                            "IP %s : %d alerte(s). Dernière activité : %s il y a %s.",
                            formatIp(e.getKey()),
                            ipAlerts.size(),
                            activity,
                            rel
                    );
                    return new AdminTopMaliciousIp(e.getKey(), ipAlerts.size(), tooltip, activity);
                })
                .toList();
    }

    private long countType(List<Alert> alerts, AlertType type) {
        return alerts.stream().filter(a -> a.getType() == type).count();
    }

    private long countMaliciousPayload(List<Alert> alerts) {
        return alerts.stream()
                .filter(a -> a.getType() == AlertType.MALICIOUS_PAYLOAD
                        || messageIndicatesXssOrSql(a.getMessage()))
                .count();
    }

    private boolean messageIndicatesXssOrSql(String message) {
        if (message == null) {
            return false;
        }
        String m = message.toLowerCase(Locale.ROOT);
        return m.contains("xss") || m.contains("injection sql") || m.contains("sqli");
    }

    private String mapDashboardType(Alert alert) {
        return switch (alert.getType()) {
            case HONEYPOT_TRIGGERED -> "HONEYPOT";
            case BRUTE_FORCE_DETECTED -> "BRUTE_FORCE";
            case RATE_LIMIT_EXCEEDED -> "RATE_LIMIT";
            case SUSPICIOUS_REQUEST, SUSPICIOUS_USER_AGENT, IP_BLOCKED, UNAUTHORIZED_ACCESS -> "SUSPICIOUS_ACTIVITY";
            case MALICIOUS_PAYLOAD -> {
                String msg = alert.getMessage() != null ? alert.getMessage().toLowerCase(Locale.ROOT) : "";
                if (msg.contains("xss")) {
                    yield "XSS";
                }
                if (msg.contains("injection sql") || msg.contains("sqli")) {
                    yield "SQL_INJECTION";
                }
                yield "MALICIOUS_PAYLOAD";
            }
            default -> "SUSPICIOUS_ACTIVITY";
        };
    }

    private String dashboardTypeLabel(String key) {
        return switch (key) {
            case "HONEYPOT" -> "Honeypot";
            case "BRUTE_FORCE" -> "Force brute";
            case "RATE_LIMIT" -> "Rate limit";
            case "XSS" -> "XSS";
            case "SQL_INJECTION" -> "Injection SQL";
            case "MALICIOUS_PAYLOAD" -> "Payload malveillant";
            case "SUSPICIOUS_ACTIVITY" -> "Activité suspecte";
            default -> key;
        };
    }

    private String summarizeType(AlertType type) {
        return dashboardTypeLabel(mapDashboardType(typePlaceholder(type)));
    }

    private Alert typePlaceholder(AlertType type) {
        Alert a = new Alert();
        a.setType(type);
        a.setMessage("");
        return a;
    }

    private String extractPathFromMessage(Alert alert) {
        String msg = alert.getMessage();
        if (msg == null) {
            return "";
        }
        int getIdx = msg.indexOf("GET ");
        int postIdx = msg.indexOf("POST ");
        int putIdx = msg.indexOf("PUT ");
        int delIdx = msg.indexOf("DELETE ");
        int start = Math.max(getIdx, Math.max(postIdx, Math.max(putIdx, delIdx)));
        if (start < 0) {
            return "";
        }
        int methodEnd = msg.indexOf(' ', start);
        if (methodEnd < 0) {
            return "";
        }
        int pathEnd = msg.indexOf(' ', methodEnd + 1);
        if (pathEnd < 0) {
            pathEnd = msg.indexOf('—', methodEnd + 1);
        }
        if (pathEnd < 0) {
            return msg.substring(methodEnd + 1).trim();
        }
        return msg.substring(methodEnd + 1, pathEnd).trim();
    }

    private String formatRelativeTime(LocalDateTime at) {
        Duration d = Duration.between(at, LocalDateTime.now());
        long minutes = d.toMinutes();
        if (minutes < 1) {
            return "moins d'une minute";
        }
        if (minutes < 60) {
            return minutes + " minute(s)";
        }
        long hours = d.toHours();
        return hours + " heure(s)";
    }

    private String formatIp(String ip) {
        return ip == null || ip.isBlank() ? "—" : ip;
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max) + "…";
    }

    private Alert findOrThrow(UUID id) {
        return alertRepository.findById(id)
                .filter(a -> !a.isDeleted())
                .orElseThrow(() -> new IllegalArgumentException("Alerte introuvable."));
    }

    private AdminAlertResponse toResponse(Alert a) {
        return new AdminAlertResponse(
                a.getId(),
                a.getType().name(),
                a.getMessage(),
                a.getStatus().name(),
                a.getRelatedUserId(),
                a.getRelatedUsername(),
                a.getIpAddress(),
                a.getDetailsJson(),
                a.getCreatedAt()
        );
    }
}
