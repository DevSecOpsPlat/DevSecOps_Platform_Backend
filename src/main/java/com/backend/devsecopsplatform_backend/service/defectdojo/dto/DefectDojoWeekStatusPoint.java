package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoWeekStatusPoint {

    private String week;
    private int opened;
    private int closed;
    private int riskAccepted;
}
