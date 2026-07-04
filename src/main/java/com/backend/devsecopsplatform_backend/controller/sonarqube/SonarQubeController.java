package com.backend.devsecopsplatform_backend.controller.sonarqube;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.qualitygate.SonarProjectKeyUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/sonarqube")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local","http://envirotest.local:4200"})
public class SonarQubeController {

    private final GitLabService gitLabService;
    private final AppServiceRepository appServiceRepository;

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

    @GetMapping("/branches")
    public ResponseEntity<?> listBranches(@RequestParam(value = "serviceId", required = false) String serviceId) {
        try {
            String pk = resolveProjectKey(null, serviceId);
            if (pk == null || pk.isBlank()) {
                return ResponseEntity.ok(java.util.List.of("main"));
            }
            java.util.List<String> branches = gitLabService.listSonarProjectBranches(pk);
            if (branches.isEmpty()) {
                branches = java.util.List.of("main");
            }
            return ResponseEntity.ok(branches);
        } catch (Exception e) {
            log.warn("Branches SonarQube indisponibles: {}", e.getMessage());
            return ResponseEntity.ok(java.util.List.of("main"));
        }
    }

    @GetMapping("/results-by-branch")
    public ResponseEntity<?> getSonarQubeResultsByBranch(
            @RequestParam("branch") String branch,
            @RequestParam(value = "projectKey", required = false) String projectKey,
            @RequestParam(value = "serviceId", required = false) String serviceId) {
        try {
            String resolvedKey = resolveProjectKey(projectKey, serviceId);
            Map<String, Object> results = gitLabService.getSonarQubeResultsForBranch(branch, resolvedKey);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            log.error("❌ Impossible de récupérer les résultats SonarQube pour la branche {}", branch, e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de récupérer les résultats SonarQube pour la branche",
                    "message", e.getMessage()
            ));
        }
    }

    private String resolveProjectKey(String explicitKey, String serviceId) {
        if (explicitKey != null && !explicitKey.isBlank()) {
            return explicitKey;
        }
        if (serviceId != null && !serviceId.isBlank()) {
            AppService svc = appServiceRepository.findById(UUID.fromString(serviceId)).orElse(null);
            if (svc != null && svc.getGitRepositoryUrl() != null) {
                return SonarProjectKeyUtil.deriveSonarProjectKey(svc.getGitRepositoryUrl());
            }
        }
        return null;
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

    @GetMapping("/duplications")
    public ResponseEntity<?> getDuplications(@RequestParam("componentKey") String componentKey) {
        try {
            Map<String, Object> details = gitLabService.getSonarFileDuplications(componentKey);
            return ResponseEntity.ok(details);
        } catch (Exception e) {
            log.error("❌ Impossible de récupérer les duplications pour {}", componentKey, e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de récupérer les duplications pour ce fichier",
                    "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/hotspots/detail")
    public ResponseEntity<?> getHotspotDetail(@RequestParam("hotspotKey") String hotspotKey) {
        try {
            Map<String, Object> details = gitLabService.getHotspotDetails(hotspotKey);
            return ResponseEntity.ok(details);
        } catch (Exception e) {
            log.error("❌ Impossible de récupérer le détail du hotspot {}", hotspotKey, e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de récupérer le détail du hotspot",
                    "message", e.getMessage()
            ));
        }
    }

    /**
     * Change le statut d'une issue (persisté dans SonarCloud).
     * Transitions: confirm, unconfirm, resolve, reopen, falsepositive, wontfix, accept.
     */
    @PostMapping("/issues/transition")
    public ResponseEntity<?> issueTransition(
            @RequestParam("issueKey") String issueKey,
            @RequestParam("transition") String transition) {
        try {
            gitLabService.sonarIssueDoTransition(issueKey, transition);
            return ResponseEntity.ok(Map.of("success", true, "issueKey", issueKey, "transition", transition));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("❌ Transition issue {} vers {}: {}", issueKey, transition, e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de changer le statut de l'issue",
                    "message", e.getMessage()
            ));
        }
    }

    /**
     * Assigne une issue au compte SonarCloud par défaut (vue \"Assign to me\" dans la plateforme).
     */
    @PostMapping("/issues/assign/me")
    public ResponseEntity<?> issueAssignMe(@RequestParam("issueKey") String issueKey) {
        try {
            gitLabService.sonarIssueAssignToDefault(issueKey);
            return ResponseEntity.ok(Map.of("success", true, "issueKey", issueKey, "mode", "me"));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("❌ Assignation (me) issue {}: {}", issueKey, e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible d'assigner l'issue",
                    "message", e.getMessage()
            ));
        }
    }

    /**
     * Désassigne complètement une issue (équivalent Not assigned).
     */
    @PostMapping("/issues/assign/unassign")
    public ResponseEntity<?> issueUnassign(@RequestParam("issueKey") String issueKey) {
        try {
            gitLabService.sonarIssueUnassign(issueKey);
            return ResponseEntity.ok(Map.of("success", true, "issueKey", issueKey, "mode", "unassign"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("❌ Désassignation issue {}: {}", issueKey, e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Impossible de désassigner l'issue",
                    "message", e.getMessage()
            ));
        }
    }
}

