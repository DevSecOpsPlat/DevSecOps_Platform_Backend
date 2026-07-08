package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.List;

/**
 * Synchronise périodiquement les pipelines encore ouverts en base (sans webhook GitLab).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PipelineStatusSyncScheduler {

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final PipelineStageSyncService pipelineStageSyncService;

    @Scheduled(fixedDelayString = "${pipeline.sync-interval-ms:120000}")
    public void syncOpenPipelines() {
        List<PipelineExecution> open = pipelineExecutionRepository.findByStatusIn(
                EnumSet.of(PipelineStatus.RUNNING, PipelineStatus.PENDING));

        if (open.isEmpty()) {
            return;
        }

        int synced = 0;
        for (PipelineExecution exec : open) {
            Long pipelineId = exec.getGitlabPipelineId();
            if (pipelineId == null || pipelineId <= 0) {
                continue;
            }
            if (pipelineStageSyncService.syncStagesForPipeline(pipelineId)) {
                synced++;
            }
        }
        if (synced > 0) {
            log.debug("🔄 {} pipeline(s) synchronisé(s) sur {} ouvert(s)", synced, open.size());
        }
    }
}
