package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoFindingAgeBucket {

    /** Âge en semaines (0 = moins d'une semaine). */
    private int weeks;

    private String label;
    private int count;
}
