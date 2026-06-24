package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

/** Dashboard sécurité v2 — vue globale produit ou filtrée par branche. */
@Data
@Builder
public class DefectDojoDashboard2Response {

    private boolean configured;
    private String message;

    /** global | branch */
    private String scope;

    private String applicationName;
    private String productName;
    private Integer productId;
    private String productUrl;

    /** Branche sélectionnée ; null si vue globale. */
    private String selectedBranch;

    private Integer engagementId;
    private String engagementName;

    private Map<String, Integer> bySeverity;
    private Map<String, Integer> byTool;
    private Map<String, Integer> byStatus;

    private int totalOpen;
    private int totalClosed;

    private DefectDojoSecurityScore securityScore;
    private List<DefectDojoRecurrentVulnerability> topRecurrent;
    private List<DefectDojoTrendPoint> trendPoints;

    private List<String> branches;
    private List<DefectDojoEngagementSummary> engagements;

    private DefectDojoDashboardCharts charts;
    private String defectDojoBaseUrl;
}
