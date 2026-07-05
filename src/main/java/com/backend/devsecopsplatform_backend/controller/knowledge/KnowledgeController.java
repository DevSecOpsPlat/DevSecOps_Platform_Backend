package com.backend.devsecopsplatform_backend.controller.knowledge;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.service.PipelineKnowledgeService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Alimentation automatique des connaissances RAG par le pipeline CI.
 * Le pipeline ne connaît que ENVIRONMENT_ID (UUID de l'environnement éphémère) :
 * on résout l'AppService via la relation EphemeralEnvironment.service.
 *
 * Auth : secret partagé X-Pipeline-Secret (même mécanisme que les snapshots quality gate).
 */
@RestController
@RequestMapping("/api/knowledge")
@RequiredArgsConstructor
@Slf4j
public class KnowledgeController {

    private final PipelineKnowledgeService knowledgeService;
    private final EphemeralEnvironmentRepository environmentRepository;

    @Value("${pipeline.secret:}")
    private String pipelineSecret;

    @Data
    public static class PipelineContextRequest {
        private UUID environmentId;
        private UUID applicationId;
        private String branch;
        private String contextMarkdown;
    }

    @PostMapping("/pipeline-context")
    public ResponseEntity<Map<String, String>> updateContext(
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret,
            @RequestBody PipelineContextRequest req
    ) {
        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(401).body(Map.of("message", "Secret pipeline invalide"));
        }

        UUID appServiceId = req.getApplicationId();
        String branch = req.getBranch();

        if (appServiceId == null) {
            if (req.getEnvironmentId() == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("message", "environmentId ou applicationId requis"));
            }
            EphemeralEnvironment env = environmentRepository.findById(req.getEnvironmentId()).orElse(null);
            if (env == null) {
                log.warn("[KNOWLEDGE] Environnement éphémère introuvable: {}", req.getEnvironmentId());
                return ResponseEntity.status(404)
                        .body(Map.of("message", "Environnement éphémère introuvable"));
            }
            if (env.getService() == null) {
                return ResponseEntity.status(409)
                        .body(Map.of("message", "Environnement sans AppService associé"));
            }
            appServiceId = env.getService().getId();
            if (branch == null || branch.isBlank()) {
                branch = env.getGitBranch();
            }
        }

        knowledgeService.updatePipelineContext(appServiceId, branch, req.getContextMarkdown());
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "applicationId", appServiceId.toString(),
                "branch", branch != null ? branch : "main"
        ));
    }
}
