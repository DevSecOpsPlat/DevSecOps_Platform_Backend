package com.backend.devsecopsplatform_backend.controller.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.QualityGateService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Compatibilité avec le job CI security-validation (POST /api/security-gate).
 */
@RestController
@RequestMapping("/api/security-gate")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class SecurityGateCompatController {

    private final QualityGateService qualityGateService;

    @PostMapping
    public ResponseEntity<Map<String, String>> ingest(@RequestBody SecurityGateIngestRequest request) {
        qualityGateService.ingestFromPipeline(request);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
