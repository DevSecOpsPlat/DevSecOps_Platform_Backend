package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.List;

/**
 * Empêche les lots de rester {@link ScanBatchStatus#RUNNING} indéfiniment :
 * si le pipeline GitLab est terminal et qu'il manque des security-gate,
 * bascule en {@link ScanBatchStatus#PARTIAL} ou {@link ScanBatchStatus#FAILED}.
 * Inversement, un lot {@link ScanBatchStatus#PARTIAL} dont tous les services ont
 * finalement livré leur quality-gate est promu en {@link ScanBatchStatus#COMPLETE}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ScanBatchReconcileScheduler {

    private final ScanBatchRepository scanBatchRepository;
    private final ScanBatchCompletionService scanBatchCompletionService;
    private final GitLabService gitLabService;

    @Scheduled(fixedDelayString = "${scan.batch.reconcile-interval-ms:60000}")
    public void reconcileOpenBatches() {
        reconcileRunningBatches();
        reconcilePartialBatches();
    }

    /** Au démarrage : recalcule une fois les lots COMPLETE figés par l'ancienne agrégation. */
    @EventListener(ApplicationReadyEvent.class)
    public void refreezeLegacyBatchesOnStartup() {
        try {
            List<ScanBatch> complete = scanBatchRepository.findByStatusIn(EnumSet.of(ScanBatchStatus.COMPLETE));
            int refreshed = 0;
            for (ScanBatch batch : complete) {
                try {
                    if (scanBatchCompletionService.refreezeIfLegacy(batch.getId())) {
                        refreshed++;
                    }
                } catch (Exception e) {
                    log.warn("Recalcul lot {} : {}", batch.getId(), e.getMessage());
                }
            }
            if (refreshed > 0) {
                log.info("Agrégation v{} : {} lot(s) COMPLETE recalculé(s)",
                        ScanBatchAggregationService.AGGREGATION_VERSION, refreshed);
            }
        } catch (Exception e) {
            log.warn("Recalcul des lots au démarrage impossible : {}", e.getMessage());
        }
    }

    private void reconcileRunningBatches() {
        List<ScanBatch> open = scanBatchRepository.findByStatusIn(
                EnumSet.of(ScanBatchStatus.PENDING, ScanBatchStatus.RUNNING));
        if (open.isEmpty()) {
            return;
        }

        int updated = 0;
        for (ScanBatch batch : open) {
            Long pipelineId = batch.getGitlabPipelineId();
            if (pipelineId == null || pipelineId <= 0) {
                continue;
            }
            try {
                if (!gitLabService.isPipelineFinished(pipelineId)) {
                    continue;
                }
                org.gitlab4j.api.models.PipelineStatus glStatus = gitLabService.getPipelineStatus(pipelineId);
                String raw = glStatus != null ? glStatus.toString() : "failed";
                if (scanBatchCompletionService.onGitlabPipelineTerminal(batch.getId(), raw)) {
                    updated++;
                }
            } catch (Exception e) {
                log.warn("Reconcile lot {} pipeline #{}: {}", batch.getId(), pipelineId, e.getMessage());
            }
        }
        if (updated > 0) {
            log.info("Reconcile scan batches : {} lot(s) basculé(s) (ouverts={})", updated, open.size());
        }
    }

    /** Lots PARTIAL « 2/2 » : tous les résultats sont là, seul le statut n'a pas suivi. */
    private void reconcilePartialBatches() {
        List<ScanBatch> partial = scanBatchRepository.findByStatusIn(EnumSet.of(ScanBatchStatus.PARTIAL));
        if (partial.isEmpty()) {
            return;
        }
        int promoted = 0;
        for (ScanBatch batch : partial) {
            try {
                if (scanBatchCompletionService.completePartialIfAllFinished(batch.getId())) {
                    promoted++;
                }
            } catch (Exception e) {
                log.warn("Reconcile lot PARTIAL {}: {}", batch.getId(), e.getMessage());
            }
        }
        if (promoted > 0) {
            log.info("Reconcile scan batches : {} lot(s) PARTIAL promu(s) en COMPLETE (partiels={})",
                    promoted, partial.size());
        }
    }
}
