package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.List;

/**
 * Empêche les lots de rester {@link ScanBatchStatus#RUNNING} indéfiniment :
 * si le pipeline GitLab est terminal et qu'il manque des security-gate,
 * bascule en {@link ScanBatchStatus#PARTIAL} ou {@link ScanBatchStatus#FAILED}.
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
}
