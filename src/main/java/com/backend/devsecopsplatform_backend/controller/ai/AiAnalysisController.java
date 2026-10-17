package com.backend.devsecopsplatform_backend.controller.ai;

import com.backend.devsecopsplatform_backend.service.AiAnalysisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;

/**
 * API pour l'analyse des artifacts de pipeline par l'IA (vulnérabilités + remédiations).
 * Tu envoies le contenu de n'importe quel artifact (Trivy, SonarQube, etc.), l'IA renvoie
 * les vulnérabilités détectées, où les trouver et comment les corriger.
 */
@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local","http://envirotest.local:4200", "https://envirotest.cloud"})
public class AiAnalysisController {

    private final AiAnalysisService aiAnalysisService;
    private final ObjectMapper objectMapper;

    /**
     * Analyse un artifact de pipeline (rapport de scan) et renvoie les vulnérabilités
     * avec description, emplacement et remédiation.
     * Corps : { "artifactContent": "<JSON ou texte du rapport>", "artifactSource": "trivy" (optionnel) }
     */
    @PostMapping("/analyze-artifact")
    public ResponseEntity<AnalyzeArtifactResponse> analyzeArtifact(@Valid @RequestBody AnalyzeArtifactRequest request) {
        log.info("Demande d'analyse IA d'artifact (source hint: {})", request.getArtifactSource());
        AnalyzeArtifactResponse response = aiAnalysisService.analyzeArtifact(
                request.getArtifactContent(),
                request.getArtifactSource()
        );
        return ResponseEntity.ok(response);
    }

    /**
     * Explique les logs d'un job CI (causes probables + actions) pour un profil sans accès cluster.
     * Corps : { logs, jobName, stageName, jobStatus, pipelineKind, stagesOverview, projectHint, userQuestion }
     */
    @PostMapping("/explain-pipeline-logs")
    public ResponseEntity<ExplainPipelineLogsResponse> explainPipelineLogs(
            @RequestBody ExplainPipelineLogsRequest request) {
        log.info("Demande d'explication logs IA (job={}, stage={})", request.getJobName(), request.getStageName());
        return ResponseEntity.ok(aiAnalysisService.explainPipelineLogs(request));
    }

    /**
     * Variante streamée (Server-Sent Events) du chat pipeline : le texte de la réponse arrive au
     * fil de l'eau au lieu d'attendre la réponse complète — perçu bien plus réactif quand le
     * secours Ollama local (CPU) est utilisé, cf. {@link AiAnalysisService#streamExplainPipelineLogs}.
     * Événements : "mode" ({"deep":true/false}, une fois, avant la réponse — pour afficher côté UI
     * ce que l'IA est en train de faire), "chunk" ({"t":"..."}) répétés, puis "done" ou "error"
     * ({"message":"..."}).
     */
    @PostMapping(value = "/explain-pipeline-logs/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter explainPipelineLogsStream(@RequestBody ExplainPipelineLogsRequest request) {
        log.info("Demande d'explication logs IA (stream) (job={}, stage={})", request.getJobName(), request.getStageName());
        // Timeout large : le routage « diagnostic » (7B local) peut prendre jusqu'à ~420s.
        SseEmitter emitter = new SseEmitter(480_000L);
        aiAnalysisService.streamExplainPipelineLogs(
                request,
                deep -> {
                    try {
                        emitter.send(SseEmitter.event().name("mode")
                                .data(objectMapper.writeValueAsString(Map.of("deep", deep))));
                    } catch (Exception e) {
                        emitter.completeWithError(e);
                    }
                },
                chunk -> {
                    try {
                        emitter.send(SseEmitter.event().name("chunk")
                                .data(objectMapper.writeValueAsString(Map.of("t", chunk))));
                    } catch (Exception e) {
                        emitter.completeWithError(e);
                    }
                },
                () -> {
                    try {
                        emitter.send(SseEmitter.event().name("done").data("{}"));
                        emitter.complete();
                    } catch (Exception e) {
                        emitter.completeWithError(e);
                    }
                },
                message -> {
                    try {
                        emitter.send(SseEmitter.event().name("error")
                                .data(objectMapper.writeValueAsString(Map.of("message", message))));
                        emitter.complete();
                    } catch (Exception e) {
                        emitter.completeWithError(e);
                    }
                }
        );
        return emitter;
    }
}
