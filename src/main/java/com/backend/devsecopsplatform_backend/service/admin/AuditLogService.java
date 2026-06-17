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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private static final int TREND_DAYS = 30;
    private static final int TREND_MONTHS = 12;
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
            String severity) {
        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );
        Specification<AuditLog> spec = buildSpecification(userId, action, search, from, to, severity);
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
            String severity) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (userId != null) {
                predicates.add(cb.equal(root.get("userId"), userId));
            }
            if (action != null) {
                predicates.add(cb.equal(root.get("action"), action));
            }
            if (StringUtils.hasText(search)) {
                String pattern = "%" + search.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("username")), pattern),
                        cb.like(cb.lower(root.get("details")), pattern),
                        cb.like(cb.lower(root.get("ipAddress")), pattern),
                        cb.like(cb.lower(root.get("performedBy")), pattern)
                ));
            }
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), from.atStartOfDay()));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), to.atTime(LocalTime.MAX)));
            }
            if (StringUtils.hasText(severity)) {
                String sev = severity.trim().toUpperCase();
                if ("INFO".equals(sev)) {
                    predicates.add(root.get("action").in(INFO_ACTIONS));
                } else if ("ATTENTION".equals(sev)) {
                    predicates.add(cb.not(root.get("action").in(INFO_ACTIONS)));
                }
            }
            return cb.and(predicates.toArray(Predicate[]::new));
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
}
