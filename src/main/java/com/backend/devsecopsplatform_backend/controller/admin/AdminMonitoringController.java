package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.service.admin.AdminMonitoringService;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Monitoring cluster-wide (tous nœuds, tous environnements de tous utilisateurs) — réservé admin.
 * Protégé globalement par {@code hasAuthority("ROLE_ADMIN")} sur {@code /api/admin/**}
 * (SecurityConfig), comme le reste de la console admin.
 */
@RestController
@RequestMapping("/api/admin/monitoring")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200", "https://envirotest.cloud"})
public class AdminMonitoringController {

    private final AdminMonitoringService adminMonitoringService;

    /** Capacité de tous les nœuds du cluster (CPU/MEM/disque). */
    @GetMapping("/nodes")
    public ResponseEntity<?> nodes() {
        return handle(() -> ResponseEntity.ok(adminMonitoringService.getClusterNodes()));
    }

    /** Résumé (une ligne par environnement RUNNING, tous utilisateurs) — pods, alertes, propriétaire. */
    @GetMapping("/namespaces")
    public ResponseEntity<?> namespaces() {
        return handle(() -> ResponseEntity.ok(adminMonitoringService.getNamespacesSummary()));
    }

    /** Détail complet d'un namespace (au clic depuis le résumé) — même donnée que le monitoring utilisateur. */
    @GetMapping("/namespaces/{namespace}")
    public ResponseEntity<?> namespaceDetail(@PathVariable String namespace) {
        return handle(() -> ResponseEntity.ok(adminMonitoringService.getNamespaceDetail(namespace)));
    }

    private ResponseEntity<?> handle(java.util.function.Supplier<ResponseEntity<?>> action) {
        try {
            return action.get();
        } catch (AppValidationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.warn("AdminMonitoringController: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erreur monitoring admin: " + e.getMessage()));
        }
    }
}
