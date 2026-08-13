package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Après ingest security-gate / pipeline GitLab terminal : met à jour le statut du lot
 * et fige le verdict officiel via {@link ScanBatchAggregationService} (D4/D5/D6).
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ScanBatchCompletionService {

    private final ScanBatchRepository scanBatchRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final ScanBatchAggregationService scanBatchAggregationService;

    @Transactional
    public void onSecurityGateIngested(SecurityGateIngestRequest request, PipelineExecution execution) {
        if (execution == null) {
            return;
        }
        UUID batchId = request.getScanBatchId();
        ScanBatch batch = null;
        if (batchId != null) {
            batch = scanBatchRepository.findById(batchId).orElse(null);
        }
        if (batch == null && execution.getScanBatch() != null) {
            batch = execution.getScanBatch();
        }
        if (batch == null) {
            return;
        }

        // Ingest reçu = exécution technique OK. Le verdict métier vit dans qualityGateJson.
        if (!execution.isFinished()) {
            execution.markAsSuccess();
            pipelineExecutionRepository.save(execution);
        }

        refreshBatchStatus(batch);
    }

    /**
     * Appelé par le scheduler quand le pipeline GitLab du lot est terminal.
     * @return true si le lot a changé de statut
     */
    @Transactional
    public boolean onGitlabPipelineTerminal(UUID batchId, String gitlabStatusRaw) {
        ScanBatch batch = scanBatchRepository.findById(batchId).orElse(null);
        if (batch == null) {
            return false;
        }
        if (batch.getStatus() == ScanBatchStatus.COMPLETE
                || batch.getStatus() == ScanBatchStatus.FAILED
                || batch.getStatus() == ScanBatchStatus.PARTIAL) {
            return false;
        }

        List<PipelineExecution> executions =
                pipelineExecutionRepository.findByScanBatchIdOrderByCreatedAtAsc(batch.getId());
        int expected = batch.getExpectedServiceCount();
        int finished = (int) executions.stream().filter(PipelineExecution::isFinished).count();

        if (finished >= expected && expected > 0) {
            ScanBatchStatus before = batch.getStatus();
            refreshBatchStatus(batch);
            return batch.getStatus() != before;
        }

        PipelineStatus gl = PipelineStatus.fromGitLabStatus(gitlabStatusRaw);
        Map<String, Object> payload = batch.getVerdictPayloadJson() != null
                ? new LinkedHashMap<>(batch.getVerdictPayloadJson())
                : new LinkedHashMap<>();
        payload.put("expectedServiceCount", expected);
        payload.put("finishedServiceCount", finished);
        payload.put("gitlabTerminalStatus", gitlabStatusRaw);
        payload.put("updatedAt", LocalDateTime.now().toString());

        // Pipeline mort sans aucun résultat → échec technique global
        if (finished == 0 && (gl == PipelineStatus.FAILED || gl == PipelineStatus.CANCELED)) {
            batch.setStatus(ScanBatchStatus.FAILED);
            batch.setVerdict("INDETERMINE");
            batch.setSecurityScore(null);
            batch.setGrade(null);
            payload.put("reason", "Pipeline GitLab terminé en échec/annulation sans security-gate.");
            for (PipelineExecution pe : executions) {
                if (!pe.isFinished()) {
                    pe.markAsFailed();
                    pipelineExecutionRepository.save(pe);
                }
            }
        } else {
            // Pipeline terminé, résultats manquants → PARTIAL (terminal)
            batch.setStatus(ScanBatchStatus.PARTIAL);
            batch.setVerdict("INDETERMINE");
            batch.setSecurityScore(null);
            batch.setGrade(null);
            payload.put("reason", "Pipeline GitLab terminal alors qu'il manque des security-gate.");
        }

        batch.setFinishedAt(LocalDateTime.now());
        batch.setVerdictPayloadJson(payload);
        scanBatchRepository.save(batch);
        log.info("Lot {} → {} (gitlab={}, finished={}/{})",
                batch.getId(), batch.getStatus(), gitlabStatusRaw, finished, expected);
        return true;
    }

    /**
     * Annulation utilisateur : ferme le lot associé (si scan managé) pour permettre un nouveau scan.
     */
    @Transactional
    public void onUserCanceledGitlabPipeline(Long gitlabPipelineId) {
        if (gitlabPipelineId == null || gitlabPipelineId <= 0) {
            return;
        }

        List<PipelineExecution> executions =
                pipelineExecutionRepository.findAllByGitlabPipelineIdOrderByCreatedAtAsc(gitlabPipelineId);

        UUID batchId = null;
        for (PipelineExecution pe : executions) {
            if (pe.getScanBatch() != null && pe.getScanBatch().getId() != null) {
                batchId = pe.getScanBatch().getId();
                break;
            }
        }
        if (batchId == null) {
            batchId = scanBatchRepository.findByGitlabPipelineId(gitlabPipelineId)
                    .map(ScanBatch::getId)
                    .orElse(null);
        }

        if (batchId != null) {
            onGitlabPipelineTerminal(batchId, "canceled");
            ScanBatch again = scanBatchRepository.findById(batchId).orElse(null);
            if (again != null
                    && (again.getStatus() == ScanBatchStatus.PENDING
                    || again.getStatus() == ScanBatchStatus.RUNNING)) {
                markBatchFailedTechnical(batchId, "Pipeline GitLab annulé par l'utilisateur.");
            }
        }

        // Align local executions even without a managed scan batch (deploy pipelines, etc.)
        for (PipelineExecution pe : executions) {
            if (!pe.isFinished()) {
                pe.setStatus(PipelineStatus.CANCELED);
                pe.setFinishedAt(LocalDateTime.now());
                pipelineExecutionRepository.save(pe);
            }
        }
        log.info("Pipeline #{} annulé côté plateforme (batch={})", gitlabPipelineId, batchId);
    }

    /**
     * Écrit FAILED hors de la transaction appelante (déclenchement GitLab / sérialisation).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markBatchFailedTechnical(UUID batchId, String reason) {
        ScanBatch batch = scanBatchRepository.findById(batchId).orElse(null);
        if (batch == null) {
            return;
        }
        batch.setStatus(ScanBatchStatus.FAILED);
        batch.setFinishedAt(LocalDateTime.now());
        batch.setVerdict("INDETERMINE");
        Map<String, Object> payload = batch.getVerdictPayloadJson() != null
                ? new LinkedHashMap<>(batch.getVerdictPayloadJson())
                : new LinkedHashMap<>();
        payload.put("reason", reason != null ? reason : "Échec technique");
        payload.put("updatedAt", LocalDateTime.now().toString());
        batch.setVerdictPayloadJson(payload);
        scanBatchRepository.save(batch);

        List<PipelineExecution> executions =
                pipelineExecutionRepository.findByScanBatchIdOrderByCreatedAtAsc(batchId);
        for (PipelineExecution pe : executions) {
            if (!pe.isFinished()) {
                pe.markAsFailed();
                pipelineExecutionRepository.save(pe);
            }
        }
        log.warn("Lot {} marqué FAILED (technique): {}", batchId, reason);
    }

    @Transactional
    public void refreshBatchStatus(ScanBatch batch) {
        if (batch == null || batch.getId() == null) {
            return;
        }
        batch = scanBatchRepository.findById(batch.getId()).orElse(batch);
        if (batch.getStatus() == ScanBatchStatus.FAILED) {
            return;
        }

        List<PipelineExecution> executions =
                pipelineExecutionRepository.findByScanBatchIdOrderByCreatedAtAsc(batch.getId());
        int expected = batch.getExpectedServiceCount();
        int finished = (int) executions.stream().filter(PipelineExecution::isFinished).count();

        Map<String, Object> payload = batch.getVerdictPayloadJson() != null
                ? new LinkedHashMap<>(batch.getVerdictPayloadJson())
                : new LinkedHashMap<>();
        payload.put("expectedServiceCount", expected);
        payload.put("createdExecutionCount", executions.size());
        payload.put("finishedServiceCount", finished);
        payload.put("updatedAt", LocalDateTime.now().toString());

        if (finished < expected) {
            // PARTIAL n'est posé que via onGitlabPipelineTerminal (pipeline GitLab fini).
            // Un ingest partiel laisse RUNNING ; un late-ingest peut remonter PARTIAL → COMPLETE.
            if (batch.getStatus() != ScanBatchStatus.PARTIAL) {
                batch.setStatus(ScanBatchStatus.RUNNING);
                batch.setFinishedAt(null);
            }
            batch.setVerdictPayloadJson(payload);
            scanBatchRepository.save(batch);
            return;
        }

        // finished >= expected — y compris late-ingest après PARTIAL
        batch.setStatus(ScanBatchStatus.COMPLETE);
        batch.setFinishedAt(LocalDateTime.now());

        List<PipelineExecution> withService =
                pipelineExecutionRepository.findByScanBatchIdWithService(batch.getId());
        freezeOfficialVerdict(batch, withService.isEmpty() ? executions : withService, payload);

        batch.setVerdictPayloadJson(payload);
        scanBatchRepository.save(batch);
        log.info("Lot {} → {} verdict={} score={} (finished={}/{})",
                batch.getId(), batch.getStatus(), batch.getVerdict(), batch.getSecurityScore(),
                finished, expected);
    }

    /**
     * Fige le verdict officiel (D4/D5) depuis les qualityGateJson — mono ou multi.
     */
    private void freezeOfficialVerdict(
            ScanBatch batch,
            List<PipelineExecution> executions,
            Map<String, Object> payload
    ) {
        ScanBatchAggregationService.AggregationResult agg =
                scanBatchAggregationService.aggregate(batch, executions);

        batch.setVerdict(agg.verdict());
        batch.setSecurityScore(agg.securityScore());
        batch.setGrade(agg.grade());

        payload.putAll(agg.payloadExtras());
        payload.remove("verdictDeferred");
        List<Map<String, Object>> services = new ArrayList<>();
        for (ScanBatchAggregationService.ServiceContribution c : agg.services()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pipelineExecutionId", c.pipelineExecutionId());
            row.put("serviceId", c.serviceId());
            row.put("serviceName", c.serviceName());
            row.put("serviceRole", c.serviceRole());
            row.put("publiclyExposed", c.publiclyExposed());
            row.put("verdict", c.verdict());
            row.put("securityScore", c.securityScore());
            row.put("grade", c.grade());
            row.put("hardGateViolated", c.hardGateViolated());
            row.put("indeterminate", c.indeterminate());
            row.put("hardGateIds", c.hardGateIds());
            row.put("indeterminateSources", c.indeterminateSources());
            services.add(row);
        }
        payload.put("services", services);
        payload.put("singleService", executions.size() == 1);
        ScanBatchAggregationService.attachDefectDojoAppRollup(executions, payload);
    }

    /**
     * Re-fige verdict + rollup DD après snapshot CI (ddBySeverity disponible).
     * No-op si le lot n'est pas encore COMPLETE / PARTIAL avec tous les ingest.
     */
    @Transactional
    public void refreshAfterDefectDojoSnapshot(UUID pipelineExecutionId) {
        if (pipelineExecutionId == null) {
            return;
        }
        PipelineExecution pe = pipelineExecutionRepository.findById(pipelineExecutionId).orElse(null);
        if (pe == null || pe.getScanBatch() == null || pe.getScanBatch().getId() == null) {
            return;
        }
        ScanBatch batch = scanBatchRepository.findById(pe.getScanBatch().getId()).orElse(null);
        if (batch == null) {
            return;
        }
        if (batch.getStatus() != ScanBatchStatus.COMPLETE && batch.getStatus() != ScanBatchStatus.PARTIAL) {
            // RUNNING : refreshBatchStatus décidera COMPLETE si finished >= expected
            refreshBatchStatus(batch);
            return;
        }
        List<PipelineExecution> withService =
                pipelineExecutionRepository.findByScanBatchIdWithService(batch.getId());
        Map<String, Object> payload = batch.getVerdictPayloadJson() != null
                ? new LinkedHashMap<>(batch.getVerdictPayloadJson())
                : new LinkedHashMap<>();
        if (batch.getStatus() == ScanBatchStatus.COMPLETE) {
            freezeOfficialVerdict(batch, withService, payload);
            batch.setVerdictPayloadJson(payload);
            scanBatchRepository.save(batch);
        } else {
            ScanBatchAggregationService.attachDefectDojoAppRollup(withService, payload);
            batch.setVerdictPayloadJson(payload);
            scanBatchRepository.save(batch);
        }
    }
}
