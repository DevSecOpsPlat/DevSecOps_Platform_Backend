package com.backend.devsecopsplatform_backend.service.ai;

/**
 * Levée lorsque la remédiation bascule en job Ollama asynchrone (dernier recours).
 */
public class AsyncRemediationPendingException extends RuntimeException {

    private final String jobId;

    public AsyncRemediationPendingException(String jobId) {
        super("Analyse Ollama asynchrone: " + jobId);
        this.jobId = jobId;
    }

    public String getJobId() {
        return jobId;
    }
}
