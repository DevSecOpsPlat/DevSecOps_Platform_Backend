package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class DefectDojoDashboardCharts {

    /** Ouvertes vs fermées (résumé). */
    private int openCount;
    private int closedCount;
    private int totalCount;

    /** Répartition sévérité (findings ouverts). */
    private Map<String, Integer> bySeverity;

    /** Outils / scan_type (findings ouverts). */
    private Map<String, Integer> byTool;

    /** Types d'analyse (SCA, SAST, Secrets, Container, IaC, …). */
    private Map<String, Integer> byAnalysisType;

    /** Statuts DefectDojo. */
    private Map<String, Integer> byStatus;

    /** État par test DefectDojo importé. */
    private List<DefectDojoScanSnapshot> scanSnapshots;

    /** Graphiques détaillés (jour/semaine, CWE, âge…). */
    private DefectDojoDetailedMetrics detailedMetrics;

    private String lastScanDate;
}
