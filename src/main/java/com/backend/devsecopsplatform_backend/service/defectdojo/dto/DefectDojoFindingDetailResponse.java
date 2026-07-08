package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class DefectDojoFindingDetailResponse {

    private int id;
    private String title;
    private String description;
    private String severity;
    private String status;
    private boolean active;
    private boolean verified;
    private boolean mitigated;
    private boolean falsePositive;
    private boolean outOfScope;
    private boolean riskAccepted;

    private String cwe;
    private String cve;
    private Double cvssScore;
    private String filePath;
    private Integer line;
    private Integer lineEnd;
    private String componentName;
    private String scanType;
    private String testTitle;
    private String toolName;

    private String mitigation;
    private String impact;
    private String references;
    private String created;
    private String mitigatedDate;

    private String branch;
    private String engagementName;
    private String productName;

    private String codeSnippet;
    private String codeContextSource;
    /** Message UI : chemin conteneur, fallback Dockerfile, etc. */
    private String codeContextHint;

    private UUID applicationId;
}
