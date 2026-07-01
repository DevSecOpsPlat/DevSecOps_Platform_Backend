package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoSecurityScore {

    /** Note lettre : A, B, C, D ou F. */
    private String grade;

    /** Score numérique 0–100. */
    private int score;

    private String summary;
}
