package com.backend.devsecopsplatform_backend.controller.environment;

import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class EnvironmentController {

    private final EnvironmentService environmentService;
    private final GitLabService gitLabService;

    /**
     * POST /api/deploy
     * Lance un déploiement : crée l'environnement et déclenche le pipeline GitLab.
     * Le token GitHub est chiffré en BDD et déchiffré uniquement pour le pipeline.
     */
    @PostMapping("/deploy")
    public ResponseEntity<DeployResponse> deploy(@Valid @RequestBody DeployRequest request) {
        log.info("📥 Demande de déploiement: repo={} branch={}", request.getGitRepositoryUrl(), request.getBranch());
        try {
            DeployResponse response = environmentService.deploy(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("❌ Erreur déploiement: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * GET /api/environments
     * Liste les environnements de l'utilisateur connecté.
     */
    @GetMapping("/environments")
    public ResponseEntity<List<EnvironmentSummaryResponse>> getMyEnvironments() {
        List<EnvironmentSummaryResponse> list = environmentService.getMyEnvironments();
        return ResponseEntity.ok(list);
    }

    /**
     * GET /api/environments/{id}
     * Détail d'un environnement.
     */
    @GetMapping("/environments/{id}")
    public ResponseEntity<EnvironmentSummaryResponse> getEnvironment(@PathVariable UUID id) {
        return environmentService.getEnvironment(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/environments/{id}/pipeline
     * Statut du pipeline et rapports de scan pour cet environnement.
     */
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

    /**
     * Récupère le résultat du scan (JSON) d'un job GitLab une fois le pipeline terminé.
     * Utilise RestTemplate côté backend pour télécharger l'artefact .json (Trivy, SonarQube, etc.).
     */
    @GetMapping(value = "/scan-results/{jobId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> getScanResults(@PathVariable Long jobId) {
        try {
            JsonNode report = gitLabService.getScanResults(jobId);
            if (report == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("❌ Erreur récupération scan results job {}: {}", jobId, e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Récupère les logs d'un job GitLab (pour affichage type Jenkins : erreurs Dockerfile, etc.).
     */
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
}
