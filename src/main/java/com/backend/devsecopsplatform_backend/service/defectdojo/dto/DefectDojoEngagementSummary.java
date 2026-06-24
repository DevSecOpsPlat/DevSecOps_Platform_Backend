package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoEngagementSummary {

    private int id;
    private String name;
    private String branchTag;
    private String status;
    private int activeFindings;
    private String url;
}
