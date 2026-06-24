package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class DefectDojoDashboardResponse {

    private boolean configured;
    private String message;

    private String productName;
    private Integer productId;
    private String productUrl;

    private String engagementName;
    private Integer engagementId;
    private String branch;
    private String engagementUrl;
    private String engagementStatus;

    /** Comptages par sévérité (findings actifs, non mitigés). */
    private Map<String, Integer> bySeverity;

    /** Statuts agrégés (open, mitigated, verified, duplicate, falsePositive). */
    private Map<String, Integer> byStatus;

    private int totalActive;
    private int totalMitigated;
    private int totalFindings;

    /** Findings récents pour le tableau. */
    private List<DefectDojoFindingItem> recentFindings;

    /** Scans (tests) importés dans l'engagement. */
    private List<DefectDojoTestItem> tests;

    /** Branches / engagements disponibles pour ce produit. */
    private List<DefectDojoEngagementSummary> availableEngagements;

    private DefectDojoDeployRecommendation deployRecommendation;

    /** Cartes métriques (Open, Closed, Verified, …) avec répartition sévérité. */
    private List<DefectDojoMetricCard> metricCards;

    /** Données agrégées pour graphiques (tendances, répartitions). */
    private DefectDojoDashboardCharts charts;

    private String defectDojoBaseUrl;
}
