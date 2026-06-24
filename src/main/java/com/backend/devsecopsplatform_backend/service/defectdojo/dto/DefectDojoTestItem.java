package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoTestItem {

    private int id;
    private String title;
    private String scanType;
    private String testType;
    private int findingCount;
    private String created;
    private String url;
}
