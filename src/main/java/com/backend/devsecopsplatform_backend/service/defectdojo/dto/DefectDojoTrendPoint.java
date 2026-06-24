package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoTrendPoint {

    private String label;
    private String date;
    private int openStock;
    private int newFindings;
    private int resolved;
}
