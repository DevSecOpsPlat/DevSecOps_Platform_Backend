package com.backend.devsecopsplatform_backend.controller.environment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeployResponse {

    private UUID environmentId;
    private String environmentName;
    private Long gitlabPipelineId;
    private String pipelineStatus;
    private String pipelineWebUrl;
    private String message;
}
