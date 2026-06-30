package com.backend.devsecopsplatform_backend.controller.defectdojo;

import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationRequest;
import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import com.backend.devsecopsplatform_backend.controller.finding.FindingChatRequest;
import com.backend.devsecopsplatform_backend.service.AiAnalysisService;
import com.backend.devsecopsplatform_backend.service.defectdojo.DefectDojoService;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoDashboard2Response;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoDashboardCharts;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoDashboardResponse;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoFindingDetailResponse;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoFindingsPageResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/defectdojo")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class DefectDojoController {

    private final DefectDojoService defectDojoService;
    private final AiAnalysisService aiAnalysisService;

    @GetMapping("/dashboard2")
    public ResponseEntity<DefectDojoDashboard2Response> dashboard2(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.getDashboard2(applicationId, branch));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Erreur dashboard2 DefectDojo app={} branch={}", applicationId, branch, e);
            return ResponseEntity.internalServerError().body(
                    DefectDojoDashboard2Response.builder()
                            .configured(false)
                            .scope("global")
                            .message("Erreur lors de la récupération du dashboard : " + e.getMessage())
                            .bySeverity(Map.of("Critical", 0, "High", 0, "Medium", 0, "Low", 0, "Info", 0))
                            .byTool(Map.of())
                            .topRecurrent(List.of())
                            .trendPoints(List.of())
                            .build()
            );
        }
    }

    @GetMapping("/dashboard2/charts")
    public ResponseEntity<DefectDojoDashboardCharts> dashboard2Charts(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.getDashboard2Charts(applicationId, branch));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Erreur graphiques dashboard2 DefectDojo app={} branch={}", applicationId, branch, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/dashboard/charts")
    public ResponseEntity<DefectDojoDashboardCharts> dashboardCharts(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestParam(required = false) String tags
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.getDashboardCharts(applicationId, branch, tags));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Erreur graphiques dashboard DefectDojo app={} branch={}", applicationId, branch, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/dashboard")
    public ResponseEntity<DefectDojoDashboardResponse> dashboard(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestParam(required = false) String tags,
            @RequestParam(defaultValue = "true") boolean includeCharts
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.getDashboard(applicationId, branch, tags, includeCharts));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Erreur dashboard DefectDojo app={} branch={}", applicationId, branch, e);
            return ResponseEntity.internalServerError().body(
                    DefectDojoDashboardResponse.builder()
                            .configured(false)
                            .message("Erreur lors de la récupération du dashboard : " + e.getMessage())
                            .build()
            );
        }
    }

    @GetMapping("/findings")
    public ResponseEntity<DefectDojoFindingsPageResponse> findings(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestParam(defaultValue = "open") String category,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String tags,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.listFindings(applicationId, branch, category, severity, page, size, tags));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/findings/{findingId}")
    public ResponseEntity<?> findingDetail(
            @PathVariable int findingId,
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        try {
            return ResponseEntity.ok(defectDojoService.getFindingDetail(applicationId, findingId, branch));
        } catch (IllegalArgumentException e) {
            log.warn("Finding DefectDojo {} introuvable: {}", findingId, e.getMessage());
            return ResponseEntity.status(404).body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/findings/{findingId}/ai-remediation")
    public ResponseEntity<FindingAiRemediationResponse> aiRemediation(
            @PathVariable int findingId,
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestBody(required = false) FindingAiRemediationRequest request
    ) {
        DefectDojoFindingDetailResponse detail = defectDojoService.getFindingDetail(applicationId, findingId, branch);
        String snippet = "";
        String codeContextSource = "NONE";
        if (request != null && request.getCodeSnippet() != null && !request.getCodeSnippet().isBlank()) {
            snippet = request.getCodeSnippet().strip();
            codeContextSource = "MANUAL";
        } else if (detail.getCodeSnippet() != null && !detail.getCodeSnippet().isBlank()) {
            snippet = detail.getCodeSnippet().strip();
            codeContextSource = detail.getCodeContextSource() != null ? detail.getCodeContextSource() : "REPO";
        }
        String ctx = defectDojoService.buildAiContext(detail);
        FindingAiRemediationResponse out = aiAnalysisService.analyzeFindingRemediation(ctx, snippet);
        return ResponseEntity.ok(out.toBuilder().codeContextSource(codeContextSource).build());
    }

    @PostMapping("/findings/{findingId}/ai-chat")
    public ResponseEntity<Map<String, String>> findingChat(
            @PathVariable int findingId,
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @Valid @RequestBody FindingChatRequest request
    ) {
        DefectDojoFindingDetailResponse detail = defectDojoService.getFindingDetail(applicationId, findingId, branch);
        String ctx = defectDojoService.buildAiContext(detail);
        String snippet = detail.getCodeSnippet() != null ? detail.getCodeSnippet() : "";
        String reply = aiAnalysisService.chatAboutFinding(
                ctx,
                request.getRemediationSummary(),
                snippet,
                request.getMessages() != null
                        ? request.getMessages().stream()
                        .map(m -> new AiAnalysisService.ChatTurn(m.getRole(), m.getContent()))
                        .toList()
                        : List.of()
        );
        return ResponseEntity.ok(Map.of("reply", reply != null ? reply : ""));
    }

    @GetMapping("/branches")
    public ResponseEntity<List<String>> branches(@RequestParam UUID applicationId) {
        try {
            return ResponseEntity.ok(defectDojoService.listBranches(applicationId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/environment-counts")
    public ResponseEntity<Map<String, Integer>> environmentCounts(@RequestParam UUID applicationId) {
        try {
            return ResponseEntity.ok(defectDojoService.getEnvironmentOpenCounts(applicationId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/recommendation")
    public ResponseEntity<Map<String, Object>> recommendation(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        DefectDojoDashboardResponse dash = defectDojoService.getDashboard(applicationId, branch, null);
        if (dash.getDeployRecommendation() == null) {
            return ResponseEntity.ok(Map.of(
                    "status", "INCONNU",
                    "deployRecommended", false,
                    "message", dash.getMessage() != null ? dash.getMessage() : "Données indisponibles"
            ));
        }
        var r = dash.getDeployRecommendation();
        return ResponseEntity.ok(Map.of(
                "status", r.getStatus(),
                "deployRecommended", r.isDeployRecommended(),
                "criticalCount", r.getCriticalCount(),
                "highCount", r.getHighCount(),
                "criticalThreshold", r.getCriticalThreshold(),
                "reason", r.getReason(),
                "source", r.getSource()
        ));
    }
}
