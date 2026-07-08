package com.backend.devsecopsplatform_backend.controller.environment;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class PipelineScanResponse {

    private Long pipelineId;
    private String status;
    private String webUrl;
    private String ref;
    private Long durationSeconds;
    private Object jobStatusCount;
    private Object jobs;
    private Map<String, JsonNode> securityReports;
    /** "gitlab" = données en direct depuis l'API GitLab, "database" = fallback depuis la BDD (GitLab indisponible) */
    private String dataSource;
}
