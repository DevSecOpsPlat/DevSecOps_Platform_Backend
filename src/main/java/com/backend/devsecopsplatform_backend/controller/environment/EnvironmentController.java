package com.backend.devsecopsplatform_backend.controller.environment;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import com.fasterxml.jackson.databind.JsonNode;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppDeploymentService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local","http://envirotest.local:4200"})
public class EnvironmentController {

    private final EnvironmentService environmentService;
    private final AppDeploymentService appDeploymentService;
    private final GitLabService gitLabService;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Value("${pipeline.secret:}")
    private String pipelineSecret;

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new RuntimeException("Utilisateur non authentifié");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }

    @PostMapping("/deploy")
    public ResponseEntity<?> deploy(
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret,
            @RequestBody JsonNode body
    ) {
        if (body != null && body.hasNonNull("image") && body.hasNonNull("namespace")
                && pipelineSecret != null && !pipelineSecret.isBlank()
                && pipelineSecret.equals(secret)) {
            try {
                CiDeployRequest ciRequest = objectMapper.treeToValue(body, CiDeployRequest.class);
                log.info("📥 CI deploy: namespace={} deploymentId={}", ciRequest.getNamespace(), ciRequest.getDeploymentId());
                return ResponseEntity.ok(appDeploymentService.applyFromCiPipeline(ciRequest));
            } catch (com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException e) {
                return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
            } catch (Exception e) {
                log.error("❌ Erreur CI deploy: {}", e.getMessage(), e);
                return ResponseEntity.internalServerError().body(Map.of("message", e.getMessage()));
            }
        }

        DeployRequest request;
        try {
            request = objectMapper.treeToValue(body, DeployRequest.class);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", "Corps de requête invalide"));
        }
        if (request.getGitRepositoryUrl() == null || request.getGitRepositoryUrl().isBlank()
                || request.getBranch() == null || request.getBranch().isBlank()) {
            return ResponseEntity.status(401).body(Map.of("message", "Authentification requise."));
        }
        log.info("📥 Demande de déploiement: repo={} branch={}", request.getGitRepositoryUrl(), request.getBranch());
        try {
            DeployResponse response = environmentService.deploy(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("❌ Erreur déploiement: {}", e.getMessage());
            throw e;
        }
    }

    @GetMapping("/deploy/status/{deploymentId}")
    public ResponseEntity<?> deployStatus(
            @PathVariable UUID deploymentId,
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret
    ) {
        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(401).body(Map.of("message", "Authentification requise."));
        }
        try {
            return ResponseEntity.ok(appDeploymentService.getCiDeployStatus(deploymentId));
        } catch (com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException e) {
            return ResponseEntity.status(404).body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/environments")
    public ResponseEntity<List<EnvironmentSummaryResponse>> getMyEnvironments(
            @RequestParam(name = "appId", required = false) UUID appId
    ) {
        List<EnvironmentSummaryResponse> list = (appId == null)
                ? environmentService.getMyEnvironments()
                : environmentService.getMyEnvironmentsForApplication(appId);
        return ResponseEntity.ok(list);
    }

    @GetMapping("/environments/{id}")
    public ResponseEntity<EnvironmentSummaryResponse> getEnvironment(@PathVariable UUID id) {
        return environmentService.getEnvironment(id)
                .map(env -> ResponseEntity.ok(env))  // ← CORRIGÉ
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/environments/{id}/pipeline")
    public ResponseEntity<PipelineScanResponse> getPipelineAndScan(@PathVariable UUID id) {
        try {
            PipelineScanResponse response = environmentService.getPipelineAndScan(id);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("❌ Pipeline/scan: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/environments/{id}/security-summary")
    public ResponseEntity<SecuritySummaryResponse> getSecuritySummary(@PathVariable UUID id) {
        try {
            SecuritySummaryResponse response = environmentService.getSecuritySummary(id);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("❌ Résumé de sécurité: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping(value = "/scan-results/{jobId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> getScanResults(@PathVariable Long jobId) {
        try {
            JsonNode report = gitLabService.getScanResults(jobId);
            if (report == null) {
                return ResponseEntity.noContent().build();
            }
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("❌ Erreur récupération scan results job {}: {}", jobId, e.getMessage());
            return ResponseEntity.noContent().build();
        }
    }

    @GetMapping(value = "/pipeline/jobs/{jobId}/logs", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getJobLogs(@PathVariable Long jobId) {
        try {
            String logs = gitLabService.getJobLogs(jobId);
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
            log.error("❌ Erreur récupération logs job {}: {}", jobId, e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/environments/by-id/{envId}")
    public ResponseEntity<EnvironmentSummaryResponse> getEnvironmentById(@PathVariable UUID envId) {
        return environmentService.getEnvironmentById(envId)
                .map(env -> ResponseEntity.ok(env))  // ← CORRIGÉ
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/environments/latest")
    public ResponseEntity<Map<String, Object>> getLatestEnvironment() {
        try {
            User user = getCurrentUser();
            EphemeralEnvironment latest = environmentRepository.findFirstByUserOrderByCreatedAtDesc(user);

            if (latest == null) {
                return ResponseEntity.notFound().build();
            }

            Map<String, Object> response = new HashMap<>();
            response.put("type", "environment");
            response.put("id", latest.getId());
            response.put("pipelineId", latest.getPipelineExecution() != null ?
                    latest.getPipelineExecution().getGitlabPipelineId() : null);
            response.put("createdAt", latest.getCreatedAt());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("❌ Erreur récupération dernier environnement: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}