package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppDeploymentService;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Callback de statut appelé par le pipeline de déploiement (pas de JWT — secret partagé
 * {@code X-Pipeline-Secret}, même mécanisme que le snapshot interne du quality-gate).
 *
 * <p>Placé sous {@code /api/webhooks/**}, préfixe déjà en {@code permitAll} dans la config de
 * sécurité existante : aucun changement de {@code SecurityConfig} n'est nécessaire (règle de
 * non-régression).</p>
 */
@RestController
@RequestMapping("/api/webhooks/managed-deployments")
@RequiredArgsConstructor
@Slf4j
public class ManagedDeploymentWebhookController {

    private final AppDeploymentService deploymentService;

    @Value("${pipeline.secret}")
    private String pipelineSecret;

    /**
     * POST /api/webhooks/managed-deployments/{deploymentId}/status
     * Body : { status, namespace?, readyServices? }
     */
    @PostMapping("/{deploymentId}/status")
    public ResponseEntity<?> updateStatus(
            @PathVariable UUID deploymentId,
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret,
            @RequestBody DeploymentStatusCallbackRequest request) {

        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(403).body(Map.of("message", "Secret invalide"));
        }
        try {
            Set<String> ready = request.getReadyServices() != null
                    ? new HashSet<>(request.getReadyServices()) : null;
            AppDeployment deployment = deploymentService.applyStatusCallback(
                    deploymentId, request.getStatus(), request.getNamespace(), ready);
            return ResponseEntity.ok(Map.of(
                    "id", deployment.getId(),
                    "status", deployment.getStatus().name()));
        } catch (AppValidationException e) {
            return ResponseEntity.status(404).body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Erreur callback statut déploiement {}: {}", deploymentId, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("message", "Erreur interne"));
        }
    }
}
