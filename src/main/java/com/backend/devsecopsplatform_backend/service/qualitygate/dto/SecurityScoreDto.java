package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityScoreDto {
    private int score;
    private String grade;
    /** Verdict dérivé du score (enrichit, ne remplace pas le verdict CI). */
    private String derivedVerdict;
    private List<ScoreBreakdownItemDto> breakdown;
    private int rawScoreBeforeCaps;
    private List<String> appliedCaps;
}
