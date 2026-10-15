package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineExecutionKind;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Écritures lot de scan en transactions distinctes et commitées
 * (proxy Spring — pas d'auto-invocation depuis {@link ManagedAppScanService}).
 */
@Service
@RequiredArgsConstructor
public class ScanBatchWriteService {

    private final ScanBatchRepository scanBatchRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final ObjectMapper objectMapper;

    public record PreparedScan(UUID batchId, List<UUID> executionIds, String servicesJson) {}

    /**
     * Crée et <strong>commit</strong> le lot PENDING + ses exécutions avant tout appel GitLab.
     */
    @Transactional
    public PreparedScan createPendingBatch(
            ManagedApplication app,
            User user,
            List<AppService> selected,
            Map<UUID, String> branchByService,
            Map<UUID, String> commitByService,
            Map<UUID, String> tokenByService
    ) {
        ScanBatch batch = new ScanBatch();
        batch.setManagedApplication(app);
        batch.setTriggeredBy(user);
        batch.setStatus(ScanBatchStatus.PENDING);
        batch.setExpectedServiceCount(selected.size());
        batch = scanBatchRepository.save(batch);

        List<UUID> executionIds = new ArrayList<>();
        List<Map<String, Object>> servicesJsonEntries = new ArrayList<>();

        for (AppService svc : selected) {
            String branch = branchByService.get(svc.getId());
            String token = tokenByService.getOrDefault(svc.getId(), "");
            String commitSha = commitByService.get(svc.getId());

            PipelineExecution pe = new PipelineExecution();
            pe.setAppService(svc);
            pe.setScanBatch(batch);
            pe.setExecutionKind(PipelineExecutionKind.SCAN);
            pe.setGitBranch(branch);
            pe.setCommitSha(commitSha);
            pe.setStatus(PipelineStatus.PENDING);
            pe.setStartedAt(LocalDateTime.now());
            pe = pipelineExecutionRepository.save(pe);
            executionIds.add(pe.getId());

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("serviceId", svc.getId().toString());
            entry.put("serviceName", AppNaming.k8sName(svc.getName()));
            entry.put("role", svc.getRole() != null ? svc.getRole().name() : "BACKEND");
            entry.put("gitRepo", svc.getGitRepositoryUrl());
            entry.put("gitToken", token != null ? token : "");
            entry.put("gitBranch", branch);
            entry.put("dockerfilePath",
                    svc.getDockerfilePath() != null && !svc.getDockerfilePath().isBlank()
                            ? svc.getDockerfilePath() : "./Dockerfile");
            entry.put("buildContext",
                    svc.getBuildContext() != null && !svc.getBuildContext().isBlank()
                            ? svc.getBuildContext() : ".");
            entry.put("commitSha", commitSha != null ? commitSha : "");
            entry.put("exposedPort", svc.getExposedPort());
            servicesJsonEntries.add(entry);
        }

        String servicesJson;
        try {
            servicesJson = objectMapper.writeValueAsString(servicesJsonEntries);
        } catch (Exception e) {
            throw new AppValidationException("Impossible de sérialiser SERVICES_JSON: " + e.getMessage());
        }

        return new PreparedScan(batch.getId(), executionIds, servicesJson);
    }

    /** Attache l'id pipeline GitLab et passe le lot en RUNNING (2ᵉ transaction). */
    @Transactional
    public void attachGitlabPipeline(UUID batchId, List<UUID> executionIds, Long pipelineId, PipelineStatus status) {
        ScanBatch batch = scanBatchRepository.findById(batchId)
                .orElseThrow(() -> new AppValidationException("Lot introuvable après déclenchement GitLab."));
        batch.setGitlabPipelineId(pipelineId);
        batch.setStatus(ScanBatchStatus.RUNNING);
        scanBatchRepository.save(batch);
        for (UUID peId : executionIds) {
            pipelineExecutionRepository.findById(peId).ifPresent(pe -> {
                pe.setGitlabPipelineId(pipelineId);
                pe.setStatus(status);
                pipelineExecutionRepository.save(pe);
            });
        }
    }

    /**
     * Met à jour le cache HEAD. Si {@code headSha} est null (échec GitHub),
     * ne touche pas à {@code checkedHeadSha} — actualise seulement {@code headCheckedAt}
     * pour respecter le TTL sans effacer une valeur correcte.
     */
    @Transactional
    public void updateHeadCache(UUID pipelineExecutionId, String headSha) {
        pipelineExecutionRepository.findById(pipelineExecutionId).ifPresent(pe -> {
            if (headSha != null && !headSha.isBlank()) {
                pe.setCheckedHeadSha(headSha);
            }
            pe.setHeadCheckedAt(LocalDateTime.now());
            pipelineExecutionRepository.save(pe);
        });
    }
}
