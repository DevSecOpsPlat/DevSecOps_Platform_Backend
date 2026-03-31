package com.backend.devsecopsplatform_backend.controller.webhook;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import com.backend.devsecopsplatform_backend.service.finding.FindingIngestionService;
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
import java.time.format.DateTimeParseException;
import java.util.Optional;

@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class GitLabWebhookController {

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final PipelineStageSyncService pipelineStageSyncService;
    private final FindingIngestionService findingIngestionService;
    private final ObjectMapper objectMapper;

    @Value("${gitlab.webhook.secret:}")
    private String webhookSecret;

    @PostMapping(value = "/gitlab", consumes = "application/json")
    public ResponseEntity<Void> gitlabWebhook(
            @RequestHeader(value = "X-Gitlab-Token", required = false) String token,
            @RequestBody String rawBody
    ) {
        // 1. Vérification du token
        if (webhookSecret != null && !webhookSecret.isBlank()) {
            if (token == null || !webhookSecret.equals(token)) {
                log.warn("⛔ Webhook GitLab refusé: secret token invalide/absent");
                return ResponseEntity.status(403).build();
            }
        }

        try {
            JsonNode root = objectMapper.readTree(rawBody);
            log.debug("📦 Webhook reçu: {}", root);

            // 2. Vérifier le type d'événement
            String eventType = root.has("event_type") ? root.path("event_type").asText("") : "";
            String objectKind = root.has("object_kind") ? root.path("object_kind").asText("") : "";

            log.info("📬 Webhook GitLab reçu - event_type: {}, object_kind: {}", eventType, objectKind);

            // 3. Traiter les événements de pipeline
            if ("pipeline".equals(objectKind) || "pipeline_event".equals(eventType)) {
                handlePipelineEvent(root);
            }
            // 4. Optionnel: Traiter les événements de job
            else if ("build".equals(objectKind)) {
                handleJobEvent(root);
            }

            return ResponseEntity.ok().build();

        } catch (Exception e) {
            log.error("❌ Erreur traitement webhook GitLab: {}", e.getMessage(), e);
            // Toujours retourner 200 pour que GitLab ne réessaie pas
            return ResponseEntity.ok().build();
        }
    }


    private void handlePipelineEvent(JsonNode root) {
        JsonNode attrs = root.path("object_attributes");

        long pipelineId = attrs.path("id").asLong(0);
        String statusStr = attrs.path("status").asText(null);

        log.info("========== WEBHOOK DEBUG ==========");
        log.info("Pipeline ID reçu: {}", pipelineId);
        log.info("Statut reçu: {}", statusStr);

        if (pipelineId == 0) {
            log.warn("⚠️ Webhook: pipeline ID manquant");
            return;
        }

        Optional<PipelineExecution> opt = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId);

        if (opt.isPresent()) {
            PipelineExecution execution = opt.get();
            PipelineStatus oldStatus = execution.getStatus();

            // 1. Mettre à jour le statut
            PipelineStatus newStatus = PipelineStatus.fromGitLabStatus(statusStr);
            execution.setStatus(newStatus);

            // 2. Mettre à jour les dates
            if (attrs.has("started_at") && !attrs.path("started_at").isNull()) {
                String startedAt = attrs.path("started_at").asText();
                if (startedAt != null && !startedAt.isEmpty()) {
                    execution.setStartedAt(parseGitLabDate(startedAt));
                }
            }

            if (attrs.has("finished_at") && !attrs.path("finished_at").isNull()) {
                String finishedAt = attrs.path("finished_at").asText();
                if (finishedAt != null && !finishedAt.isEmpty()) {
                    execution.setFinishedAt(parseGitLabDate(finishedAt));
                }
            }

            // 3. SAUVEGARDER EN BASE
            pipelineExecutionRepository.save(execution);

            log.info("✅ Pipeline #{} mis à jour: {} → {}",
                    pipelineId, oldStatus, newStatus);

            // 4. Quand le pipeline est terminé, synchroniser les stages en BDD (stages_json)
            if (newStatus == PipelineStatus.SUCCESS || newStatus == PipelineStatus.FAILED
                    || newStatus == PipelineStatus.CANCELED || newStatus == PipelineStatus.SKIPPED) {
                pipelineStageSyncService.syncStagesForPipeline(pipelineId);

                // 5. Ingestion findings (asynchrone) depuis aggregate-report artifacts
                // Important: le webhook doit rester rapide, on ne bloque pas la réponse.
                java.util.concurrent.CompletableFuture.runAsync(() -> {
                    try {
                        findingIngestionService.ingestFromAggregateArtifacts(pipelineId);
                    } catch (Exception e) {
                        log.warn("⚠️ Ingestion findings échouée pour pipeline {}: {}", pipelineId, e.getMessage());
                    }
                });
            }
        } else {
            log.warn("⚠️ Pipeline #{} non trouvé en base!", pipelineId);
        }
    }

    private void handleJobEvent(JsonNode root) {
        JsonNode attrs = root.path("build_attributes");

        long jobId = attrs.path("id").asLong(0);
        String statusStr = attrs.path("status").asText(null);
        long pipelineId = attrs.path("pipeline_id").asLong(0);

        log.info("🔧 Job #{} (pipeline #{}) - statut: {}", jobId, pipelineId, statusStr);

        // Optionnel: Mettre à jour des informations de job si vous les stockez
    }

    private void updatePipelineDates(PipelineExecution execution, JsonNode attrs) {
        try {
            // Date de début
            if (attrs.has("started_at") && !attrs.path("started_at").isNull()) {
                String startedAt = attrs.path("started_at").asText();
                if (startedAt != null && !startedAt.isEmpty()) {
                    execution.setStartedAt(parseGitLabDate(startedAt));
                }
            }

            // Date de fin
            if (attrs.has("finished_at") && !attrs.path("finished_at").isNull()) {
                String finishedAt = attrs.path("finished_at").asText();
                if (finishedAt != null && !finishedAt.isEmpty()) {
                    execution.setFinishedAt(parseGitLabDate(finishedAt));
                }
            }

            // Durée
            if (attrs.has("duration") && !attrs.path("duration").isNull()) {
                int duration = attrs.path("duration").asInt(0);
                if (duration > 0) {
                    // Si vous avez un champ duration dans votre entité
                    // execution.setDuration(duration);
                }
            }
        } catch (Exception e) {
            log.warn("⚠️ Erreur parsing dates pour pipeline {}: {}",
                    execution.getGitlabPipelineId(), e.getMessage());
        }
    }

    private LocalDateTime parseGitLabDate(String dateStr) {
        try {
            // GitLab envoie des dates au format ISO 8601
            return LocalDateTime.ofInstant(
                    Instant.parse(dateStr), ZoneId.systemDefault());
        } catch (DateTimeParseException e) {
            log.warn("⚠️ Format de date invalide: {}", dateStr);
            return null;
        }
    }
}