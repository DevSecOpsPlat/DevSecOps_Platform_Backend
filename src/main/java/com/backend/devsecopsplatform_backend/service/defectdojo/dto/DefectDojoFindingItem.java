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
    private String cwe;
    private Double cvssScore;
    private String cve;
    private String description;
    private String filePath;
    private Integer line;
    private String componentName;
    private String scanType;
    private String testTitle;
    private String toolName;
    private String mitigation;
    private String created;
    private String mitigatedDate;
    private String url;
}
