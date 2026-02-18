package com.backend.devsecopsplatform_backend.controller.webhook;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

/**
 * Endpoint pour les webhooks GitLab.
 * Dans GitLab : Settings → Webhooks → URL = http(s)://votre-serveur:8089/projet/api/webhooks/gitlab
 * Événement à cocher : Pipeline events
 */
@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class GitLabWebhookController {

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final ObjectMapper objectMapper;

    @Value("${gitlab.webhook.secret:}")
    private String webhookSecret;

    @PostMapping(value = "/gitlab", consumes = "application/json")
    public ResponseEntity<Void> gitlabWebhook(
            @RequestHeader(value = "X-Gitlab-Token", required = false) String token,
            @RequestBody String rawBody
    ) {
        if (webhookSecret != null && !webhookSecret.isBlank()) {
            if (token == null || !webhookSecret.equals(token)) {
                log.warn("Webhook GitLab refusé: secret token invalide/absent");
                return ResponseEntity.status(403).build();
            }
        }
        try {
            JsonNode root = objectMapper.readTree(rawBody);
            String objectKind = root.has("object_kind") ? root.path("object_kind").asText("") : "";

            if ("pipeline".equals(objectKind)) {
                JsonNode attrs = root.path("object_attributes");
                int pipelineId = attrs.path("id").asInt(0);
                String statusStr = attrs.path("status").asText(null);
                if (pipelineId > 0 && statusStr != null) {
                    Optional<PipelineExecution> opt = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId);
                    if (opt.isPresent()) {
                        PipelineExecution execution = opt.get();
                        execution.setStatus(PipelineStatus.fromGitLabStatus(statusStr));
                        if (attrs.has("finished_at") && !attrs.path("finished_at").isNull()) {
                            String finishedAt = attrs.path("finished_at").asText(null);
                            if (finishedAt != null) {
                                execution.setFinishedAt(LocalDateTime.ofInstant(
                                        Instant.parse(finishedAt), ZoneId.systemDefault()));
                            }
                        }
                        pipelineExecutionRepository.save(execution);
                        log.info("Webhook GitLab: pipeline #{} mis à jour → {}", pipelineId, statusStr);
                    }
                }
            }
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.warn("Webhook GitLab ignoré ou erreur: {}", e.getMessage());
            return ResponseEntity.ok().build();
        }
    }
}
