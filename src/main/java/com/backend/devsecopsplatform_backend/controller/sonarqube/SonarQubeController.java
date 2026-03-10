package com.backend.devsecopsplatform_backend.controller.sonarqube;

import com.backend.devsecopsplatform_backend.service.GitLabService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/sonarqube")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class SonarQubeController {

    private final GitLabService gitLabService;

    @GetMapping("/results")
    public ResponseEntity<?> getSonarQubeResults() {
        try {
            Map<String, Object> results = gitLabService.getSonarQubeResults();
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            log.error("❌ Impossible de récupérer les résultats SonarQube", e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de récupérer les résultats SonarQube",
                    "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/quality-gate")
    public ResponseEntity<?> getQualityGateStatus() {
        try {
            Map<String, Object> status = gitLabService.getQualityGateStatus();
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            log.error("❌ Impossible de récupérer le Quality Gate", e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de récupérer le Quality Gate",
                    "message", e.getMessage()
            ));
        }
    }
}

