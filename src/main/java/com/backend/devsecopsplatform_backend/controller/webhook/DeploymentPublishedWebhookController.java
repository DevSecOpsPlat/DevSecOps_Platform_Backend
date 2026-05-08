package com.backend.devsecopsplatform_backend.controller.webhook;

import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Appelé par le job GitLab après déploiement K8s pour enregistrer l’URL publique de l’app
 * (aperçu + lien « Visiter » côté plateforme).
 */
@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200","http://envirotest.local", "http://envirotest.local:4200"})
public class DeploymentPublishedWebhookController {

    private final EnvironmentService environmentService;

    @Value("${deployment.callback.token:}")
    private String deploymentCallbackToken;

    public record DeploymentPublishedRequest(UUID environmentId, String publicUrl) {}

    @PostMapping("/deployment-published")
    public ResponseEntity<Void> deploymentPublished(
            @RequestHeader(value = "X-Deploy-Token", required = false) String token,
            @RequestBody DeploymentPublishedRequest body
    ) {
        if (deploymentCallbackToken == null || deploymentCallbackToken.isBlank()) {
            log.warn("deployment.callback.token non configuré — refus du callback");
            return ResponseEntity.status(503).build();
        }
        if (token == null || !deploymentCallbackToken.equals(token)) {
            log.warn("Callback déploiement refusé : token invalide ou absent");
            return ResponseEntity.status(403).build();
        }
        if (body == null || body.environmentId() == null || body.publicUrl() == null || body.publicUrl().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            environmentService.publishDeploymentPublicUrl(body.environmentId(), body.publicUrl().trim());
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Erreur enregistrement URL déploiement: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}
