package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.service.admin.AuditLogService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditAnalyticsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditAdminVsUsers;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditLoginHourPoint;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditSuspiciousIp;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditDashboardResponse.AdminAuditTopUser;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditPageResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditStatsResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/audit-log")
@RequiredArgsConstructor
public class AdminAuditController {

    private final AuditLogService auditLogService;

    @GetMapping
    public ResponseEntity<AdminAuditPageResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String performedBy,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime timeFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime timeTo,
            @RequestParam(required = false) String loginOutcome) {
        AuditAction auditAction = parseAction(action);
        return ResponseEntity.ok(auditLogService.getPage(
                page, size, userId, auditAction, search, from, to, severity,
                performedBy, timeFrom, timeTo, loginOutcome));
    }

    @GetMapping("/stats")
    public ResponseEntity<AdminAuditStatsResponse> stats() {
        return ResponseEntity.ok(auditLogService.getStats());
    }

    @GetMapping("/analytics")
    public ResponseEntity<AdminAuditAnalyticsResponse> analytics() {
        return ResponseEntity.ok(auditLogService.getAnalytics());
    }

    @GetMapping("/dashboard")
    public ResponseEntity<AdminAuditDashboardResponse> dashboard() {
        return ResponseEntity.ok(auditLogService.getDashboard());
    }

    @GetMapping("/top-users")
    public ResponseEntity<List<AdminAuditTopUser>> topUsers(
            @RequestParam(defaultValue = "5") int limit) {
        return ResponseEntity.ok(auditLogService.getTopUsers(limit));
    }

    @GetMapping("/login-comparison")
    public ResponseEntity<List<AdminAuditLoginHourPoint>> loginComparison(
            @RequestParam(defaultValue = "24") int hours) {
        return ResponseEntity.ok(auditLogService.getLoginComparison(hours));
    }

    @GetMapping("/admin-vs-users")
    public ResponseEntity<AdminAuditAdminVsUsers> adminVsUsers() {
        return ResponseEntity.ok(auditLogService.getAdminVsUsers());
    }

    @GetMapping("/suspicious-ips")
    public ResponseEntity<List<AdminAuditSuspiciousIp>> suspiciousIps() {
        return ResponseEntity.ok(auditLogService.getSuspiciousIps());
    }

    private AuditAction parseAction(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return AuditAction.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Action d'audit invalide : " + value);
        }
    }
}
