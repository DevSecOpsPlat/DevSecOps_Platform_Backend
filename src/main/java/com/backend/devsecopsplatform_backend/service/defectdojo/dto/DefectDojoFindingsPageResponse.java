package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class DefectDojoFindingsPageResponse {

    private List<DefectDojoFindingItem> content;
    private int totalElements;
    private int totalPages;
    private int page;
    private int size;
    private String category;
}
