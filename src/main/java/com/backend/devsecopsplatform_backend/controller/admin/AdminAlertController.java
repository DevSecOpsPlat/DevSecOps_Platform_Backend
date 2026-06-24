package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.service.admin.AlertService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertStatsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminSecurityDashboardResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/alerts")
@RequiredArgsConstructor
public class AdminAlertController {

    private final AlertService alertService;

    @GetMapping
    public ResponseEntity<?> list(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @RequestParam(required = false) Integer page,
            @RequestParam(required = false) Integer size) {
        AlertStatus alertStatus = parseStatus(status);
        AlertType alertType = parseType(type);
        if (page != null || size != null) {
            return ResponseEntity.ok(alertService.listAlertsPage(
                    page != null ? page : 0,
                    size != null ? size : 20,
                    alertStatus,
                    alertType,
                    ip,
                    from,
                    to
            ));
        }
        return ResponseEntity.ok(alertService.listAlerts(alertStatus, alertType));
    }

    @GetMapping("/dashboard")
    public ResponseEntity<AdminSecurityDashboardResponse> dashboard() {
        return ResponseEntity.ok(alertService.getSecurityDashboard());
    }

    @GetMapping("/stats")
    public ResponseEntity<AdminAlertStatsResponse> stats() {
        return ResponseEntity.ok(alertService.getStats());
    }

    @GetMapping("/unread-count")
    public ResponseEntity<Map<String, Long>> unreadCount() {
        return ResponseEntity.ok(Map.of("count", alertService.countUnread()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<AdminAlertResponse> getById(@PathVariable UUID id) {
        return ResponseEntity.ok(alertService.getById(id));
    }

    @PatchMapping("/{id}/read")
    public ResponseEntity<AdminAlertResponse> markRead(@PathVariable UUID id) {
        return ResponseEntity.ok(alertService.markAsRead(id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> delete(@PathVariable UUID id) {
        alertService.softDelete(id);
        return ResponseEntity.ok(Map.of("message", "Alerte supprimée."));
    }

    private AlertStatus parseStatus(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return AlertStatus.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Statut d'alerte invalide : " + value);
        }
    }

    private AlertType parseType(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return AlertType.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Type d'alerte invalide : " + value);
        }
    }
}
