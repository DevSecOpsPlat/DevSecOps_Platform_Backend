package com.backend.devsecopsplatform_backend.controller.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.QualityGateService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Compatibilité avec le job CI security-validation (POST /api/security-gate).
 * Authentification via {@code X-Pipeline-Secret} (pas de JWT).
 */
@RestController
@RequestMapping("/api/security-gate")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class SecurityGateCompatController {

    private final QualityGateService qualityGateService;

    @Value("${pipeline.secret}")
    private String pipelineSecret;

    @PostMapping
    public ResponseEntity<?> ingest(
            @RequestBody SecurityGateIngestRequest request,
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret
    ) {
        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Secret pipeline invalide ou manquant (header X-Pipeline-Secret)."));
        }
        qualityGateService.ingestFromPipeline(request);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
