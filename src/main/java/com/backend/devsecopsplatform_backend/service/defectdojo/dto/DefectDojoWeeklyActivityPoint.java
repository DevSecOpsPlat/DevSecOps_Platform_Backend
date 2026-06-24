package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoWeeklyActivityPoint {

    private String week;
    /** 1 = Lundi … 7 = Dimanche. */
    private int dayOfWeek;
    private String dayLabel;
    private int count;
}
