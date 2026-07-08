package com.backend.devsecopsplatform_backend.controller.environment;

import lombok.Data;

@Data
public class CiDeployRequest {
    private String image;
    private String namespace;
    private String deploymentId;
    private String environmentId;
}
