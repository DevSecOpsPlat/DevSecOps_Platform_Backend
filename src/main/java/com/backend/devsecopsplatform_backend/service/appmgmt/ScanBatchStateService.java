package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.SecurityPostureResponse;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.backend.devsecopsplatform_backend.service.appmgmt.dto.ScanBatchStateDto;
import com.backend.devsecopsplatform_backend.service.appmgmt.dto.ScanBatchStateDto.ScanBatchServiceStateDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.HardGateInput;
import com.backend.devsecopsplatform_backend.service.qualitygate.SecurityScoringService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.HardGateViolationDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Lecture / reconstruction de l'état d'un lot de scan (Chantier 1).
 * Aucune orchestration ici — Chantier 2.
 */
@Service
@RequiredArgsConstructor
public class ScanBatchStateService {

    private final ScanBatchRepository scanBatchRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final SecurityScoringService securityScoringService;

    /** Ids des 5 hard gates connus, dans l'ordre d'affichage -- même ensemble que le service unique. */
    private static final List<String> HARD_GATE_IDS = List.of(
            "secrets", "dd_critical", "sonar_blocker", "sonar_qg", "dast");

    @Transactional(readOnly = true)
    public Optional<ScanBatchStateDto> getState(UUID batchId) {
        return scanBatchRepository.findByIdWithDetails(batchId).map(this::toState);
    }

    @Transactional(readOnly = true)
    public Optional<ScanBatchStateDto> getStateForApp(UUID managedAppId, UUID batchId) {
        return scanBatchRepository.findByIdAndAppIdWithDetails(batchId, managedAppId).map(this::toState);
    }

    /**
     * Liste d'états sans N+1 : une requête exécutions pour tous les lots.
     */
    @Transactional(readOnly = true)
    public List<ScanBatchStateDto> getStates(List<ScanBatch> batches) {
        if (batches == null || batches.isEmpty()) {
            return List.of();
        }
        List<UUID> ids = batches.stream().map(ScanBatch::getId).toList();
        List<PipelineExecution> all =
                pipelineExecutionRepository.findByScanBatchIdInWithService(ids);
        Map<UUID, List<PipelineExecution>> byBatch = all.stream()
                .filter(pe -> pe.getScanBatch() != null && pe.getScanBatch().getId() != null)
                .collect(Collectors.groupingBy(
                        pe -> pe.getScanBatch().getId(),
                        LinkedHashMap::new,
                        Collectors.toList()));

        List<ScanBatchStateDto> out = new ArrayList<>(batches.size());
        for (ScanBatch batch : batches) {
            out.add(toState(batch, byBatch.getOrDefault(batch.getId(), Collections.emptyList())));
        }
        return out;
    }

    /**
     * Reconstruit l'état du lot. Private : toujours passer par {@link #getState(UUID)}
     * / {@link #getStateForApp} (transaction + FETCH) — jamais sur une entité détachée
     * après save() (LAZY triggeredBy / managedApplication).
     */
    private ScanBatchStateDto toState(ScanBatch batch) {
        List<PipelineExecution> executions =
                pipelineExecutionRepository.findByScanBatchIdWithService(batch.getId());
        return toState(batch, executions);
    }

    private ScanBatchStateDto toState(ScanBatch batch, List<PipelineExecution> executions) {
        List<ScanBatchServiceStateDto> services = executions.stream()
                .map(this::toServiceState)
                .toList();

        int finished = (int) services.stream().filter(ScanBatchServiceStateDto::finished).count();
        int expected = batch.getExpectedServiceCount();

        UUID triggeredById = batch.getTriggeredBy() != null ? batch.getTriggeredBy().getId() : null;
        UUID appId = batch.getManagedApplication() != null ? batch.getManagedApplication().getId() : null;

        return new ScanBatchStateDto(
                batch.getId(),
                appId,
                batch.getStatus() != null ? batch.getStatus() : ScanBatchStatus.PENDING,
                batch.getGitlabPipelineId(),
                triggeredById,
                batch.getCreatedAt(),
                batch.getFinishedAt(),
                batch.getVerdict(),
                batch.getSecurityScore(),
                batch.getGrade(),
                batch.getVerdictPayloadJson(),
                expected,
                finished,
                services,
                ManagedAppScanService.extractQualityGates(batch, executions)
        );
    }

    private ScanBatchServiceStateDto toServiceState(PipelineExecution pe) {
        AppService svc = pe.getAppService();
        Map<String, Object> gate = pe.getQualityGateJson() != null ? pe.getQualityGateJson() : Map.of();
        return new ScanBatchServiceStateDto(
                pe.getId(),
                svc != null ? svc.getId() : null,
                svc != null ? svc.getName() : null,
                svc != null && svc.getRole() != null ? svc.getRole().name() : null,
                pe.getGitBranch(),
                pe.getCommitSha(),
                pe.getStatus(),
                pe.isFinished(),
                pe.getQualityGateJson(),
                buildQualityGates(gate)
        );
    }

    /**
     * Checklist des hard gates pour un service, dérivée du même {@link HardGateInput} déjà
     * corrigé pour l'agrégation multi-services ({@link ScanBatchAggregationService#buildHardGateInput}) --
     * évite de réimplémenter une 3ᵉ fois la logique déjà correcte côté service unique et batch.
     */
    private List<SecurityPostureResponse.QualityGateItem> buildQualityGates(Map<String, Object> gate) {
        HardGateInput hardIn = ScanBatchAggregationService.buildHardGateInput(gate);
        SecurityScoringService.HardGateEvaluation hard = securityScoringService.evaluateHardGates(hardIn);

        Map<String, HardGateViolationDto> violationsById = hard.violations().stream()
                .collect(Collectors.toMap(HardGateViolationDto::getId, v -> v, (a, b) -> a));
        Map<String, HardGateViolationDto> indeterminateById = hard.indeterminate().stream()
                .collect(Collectors.toMap(HardGateViolationDto::getId, v -> v, (a, b) -> a));

        List<SecurityPostureResponse.QualityGateItem> items = new ArrayList<>();
        for (String id : HARD_GATE_IDS) {
            if ("dast".equals(id) && !hardIn.isDastApplicable()) {
                // Pipeline scan-only pour ce service : ZAP n'y tourne jamais, ne pas afficher
                // l'item du tout (comme pour la vue service unique).
                continue;
            }
            HardGateViolationDto violated = violationsById.get(id);
            HardGateViolationDto indeterminate = indeterminateById.get(id);
            if (violated != null) {
                items.add(SecurityPostureResponse.QualityGateItem.builder()
                        .id(id).label(violated.getLabel()).status("FAIL").message(violated.getMessage())
                        .build());
            } else if (indeterminate != null) {
                items.add(SecurityPostureResponse.QualityGateItem.builder()
                        .id(id).label(indeterminate.getLabel()).status("UNKNOWN").message(indeterminate.getMessage())
                        .build());
            } else {
                items.add(SecurityPostureResponse.QualityGateItem.builder()
                        .id(id).label(hardGateLabel(id)).status("PASS").message(null)
                        .build());
            }
        }
        return items;
    }

    private static String hardGateLabel(String id) {
        return switch (id) {
            case "secrets" -> "Secrets exposés (Gitleaks)";
            case "dd_critical" -> "Vulnérabilités critiques";
            case "sonar_blocker" -> "Issues Blocker (SonarQube)";
            case "sonar_qg" -> "Quality Gate SonarQube";
            case "dast" -> "Vulnérabilités élevées (DAST / ZAP)";
            default -> id;
        };
    }
}
