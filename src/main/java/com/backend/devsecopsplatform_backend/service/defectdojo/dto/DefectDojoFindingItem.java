package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoFindingItem {

    private int id;
    private String title;
    private String severity;
    private String status;
    private boolean active;
    private boolean verified;
    private boolean mitigated;
    private boolean falsePositive;
    private boolean outOfScope;
    private boolean riskAccepted;
    private boolean underReview;
    private String cwe;
    private Double cvssScore;
    private String cve;
    private String description;
    private String filePath;
    private Integer line;
    private String componentName;
    /** Nom du scanner (Semgrep, Trivy, …) — test_type_name DefectDojo. */
    private String scanType;
    /** ID du test DefectDojo = un import pipeline (ex. 35). */
    private Integer testId;
    private String testTitle;
    private String toolName;
    private String mitigation;
    private String created;
    private String mitigatedDate;
    private String url;
}
