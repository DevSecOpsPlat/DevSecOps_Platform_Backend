package com.backend.devsecopsplatform_backend.service.ai;

import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Exécution asynchrone Ollama (dernier recours) pour ne pas bloquer l'UI pendant la soutenance.
 */
@Service
@Slf4j
public class AiRemediationJobService {

    public record JobStatus(
            String status,
            FindingAiRemediationResponse result,
            String error
    ) {}

    private final Map<String, JobStatus> jobs = new ConcurrentHashMap<>();

    public String submit(String label, Supplier<FindingAiRemediationResponse> task) {
        String jobId = UUID.randomUUID().toString();
        jobs.put(jobId, new JobStatus("PENDING", null, null));
        log.info("[AI][JOB] {} démarré ({})", jobId, label);
        CompletableFuture.runAsync(() -> {
            try {
                FindingAiRemediationResponse result = task.get();
                jobs.put(jobId, new JobStatus("COMPLETE", result, null));
                log.info("[AI][JOB] {} terminé", jobId);
            } catch (Exception e) {
                log.warn("[AI][JOB] {} échoué: {}", jobId, e.getMessage());
                jobs.put(jobId, new JobStatus("FAILED", null, e.getMessage()));
            }
        });
        return jobId;
    }

    public Optional<JobStatus> get(String jobId) {
        return Optional.ofNullable(jobs.get(jobId));
    }

    public void evict(String jobId) {
        jobs.remove(jobId);
    }
}
