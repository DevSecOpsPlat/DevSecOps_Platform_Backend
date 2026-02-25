package com.backend.devsecopsplatform_backend.controller.environment;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class SecuritySummaryResponse {

    private UUID environmentId;
    private String environmentName;

    private Long pipelineId;
    private String pipelineStatus;

    private int critical;
    private int high;
    private int medium;
    private int low;
    private int info;
}

