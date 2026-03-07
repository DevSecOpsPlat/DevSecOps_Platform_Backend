package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Synchronise les stages/jobs des pipelines GitLab vers la base de données (stages_json).
 * Les stages sont récupérés via l'API GitLab puis persistés dans PipelineExecution.stagesJson.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PipelineStageSyncService {

    private static final DateTimeFormatter ISO_FORMAT = DateTimeFormatter.ISO_INSTANT;

    private final GitLabService gitLabService;
    private final PipelineExecutionRepository pipelineExecutionRepository;

    /**
     * Met à jour les stages en base pour un pipeline donné (appel API GitLab puis sauvegarde).
     * En cas d'erreur API, ne modifie pas la base et log un avertissement.
     *
     * @param pipelineId ID du pipeline GitLab
     * @return true si la synchro a réussi, false sinon
     */
    public boolean syncStagesForPipeline(Long pipelineId) {
        if (pipelineId == null || pipelineId <= 0) {
            return false;
        }
        return pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .map(execution -> doSync(execution, pipelineId))
                .orElse(false);
    }

    /**
     * Construit le map à stocker dans stages_json à partir du résumé renvoyé par getPipelineSummary.
     * Format: jobs (liste), jobStatusCount, lastSyncedAt, status, webUrl, ref, shortSha, duration.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> buildStagesJsonFromSummary(Map<String, Object> summary) {
        Map<String, Object> stages = new HashMap<>();
        stages.put("jobs", summary.get("jobs") != null ? summary.get("jobs") : List.of());
        stages.put("jobStatusCount", summary.get("jobStatusCount") != null ? summary.get("jobStatusCount") : Map.of());
        stages.put("lastSyncedAt", ISO_FORMAT.format(Instant.now()));
        stages.put("status", summary.get("status"));
        stages.put("webUrl", summary.get("webUrl"));
        stages.put("ref", summary.get("ref"));
        stages.put("shortSha", summary.get("shortSha"));
        stages.put("duration", summary.get("duration"));
        stages.put("totalJobs", summary.get("totalJobs") != null ? summary.get("totalJobs") : 0);
        return stages;
    }

    /**
     * Extrait la liste des jobs depuis stagesJson (pour fallback quand l'API GitLab est indisponible).
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> getJobsFromStagesJson(PipelineExecution execution) {
        Map<String, Object> stages = execution.getStagesJson();
        if (stages == null) {
            return List.of();
        }
        Object jobs = stages.get("jobs");
        if (jobs instanceof List) {
            return (List<Map<String, Object>>) jobs;
        }
        return List.of();
    }

    /**
     * Extrait jobStatusCount depuis stagesJson pour le fallback.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Long> getJobStatusCountFromStagesJson(PipelineExecution execution) {
        Map<String, Object> stages = execution.getStagesJson();
        if (stages == null) return Map.of();
        Object count = stages.get("jobStatusCount");
        if (count instanceof Map) {
            return (Map<String, Long>) count;
        }
        return Map.of();
    }

    private boolean doSync(PipelineExecution execution, Long pipelineId) {
        try {
            Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
            Map<String, Object> stagesJson = buildStagesJsonFromSummary(summary);
            execution.setStagesJson(stagesJson);
            pipelineExecutionRepository.save(execution);
            log.info("✅ Stages synchronisés en BDD pour le pipeline #{} ({} jobs)", pipelineId, stagesJson.get("totalJobs"));
            return true;
        } catch (Exception e) {
            log.warn("⚠️ Impossible de synchroniser les stages pour le pipeline #{}: {}", pipelineId, e.getMessage());
            return false;
        }
    }
}
