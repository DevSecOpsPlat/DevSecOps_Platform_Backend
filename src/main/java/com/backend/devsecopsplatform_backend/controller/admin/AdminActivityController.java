package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.service.admin.AdminActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Fil d'activité admin fusionné (pipelines + alertes + activité de compte) — alimente la timeline
 * de la Vue d'ensemble et des pages détail Application/Environnement de la refonte du dashboard
 * admin (Phase 1). Protégé globalement par {@code hasAuthority("ROLE_ADMIN")} sur
 * {@code /api/admin/**} (SecurityConfig), comme le reste de la console admin.
 */
@RestController
@RequestMapping("/api/admin/activity")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class AdminActivityController {

    private final AdminActivityService adminActivityService;

    @GetMapping
    public ResponseEntity<?> getActivity(
            @RequestParam(defaultValue = "30") int limit,
            @RequestParam(required = false) UUID applicationId,
            @RequestParam(required = false) UUID environmentId,
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to
    ) {
        try {
            return ResponseEntity.ok(
                    adminActivityService.getActivity(limit, applicationId, environmentId, userId, from, to));
        } catch (Exception e) {
            log.warn("AdminActivityController: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erreur activité admin: " + e.getMessage()));
        }
    }
}
