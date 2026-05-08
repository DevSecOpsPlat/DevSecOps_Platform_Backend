package com.backend.devsecopsplatform_backend.controller.ai;

import com.backend.devsecopsplatform_backend.service.AiAnalysisService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * API pour l'analyse des artifacts de pipeline par l'IA (vulnérabilités + remédiations).
 * Tu envoies le contenu de n'importe quel artifact (Trivy, SonarQube, etc.), l'IA renvoie
 * les vulnérabilités détectées, où les trouver et comment les corriger.
 */
@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local","http://envirotest.local:4200"})
public class AiAnalysisController {

    private final AiAnalysisService aiAnalysisService;

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
}
