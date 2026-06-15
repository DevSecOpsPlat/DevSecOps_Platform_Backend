package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.service.admin.AuditLogService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditPageResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditStatsResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
            @RequestParam(required = false) String action) {
        AuditAction auditAction = parseAction(action);
        return ResponseEntity.ok(auditLogService.getPage(page, size, userId, auditAction));
    }

    @GetMapping("/stats")
    public ResponseEntity<AdminAuditStatsResponse> stats() {
        return ResponseEntity.ok(auditLogService.getStats());
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
