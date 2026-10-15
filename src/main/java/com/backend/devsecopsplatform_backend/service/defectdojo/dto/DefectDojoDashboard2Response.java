package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Dashboard sécurité v2 — vue globale produit ou filtrée par branche. */
@Data
@Builder
public class DefectDojoDashboard2Response {

    private boolean configured;
    private String message;

    /** global | branch | environment | pipeline */
    private String scope;

    /** Tag DefectDojo {@code env-<uuid>} (legacy) quand le filtre environnement est actif. */
    private String environmentTag;

    /** Tag DefectDojo {@code pipeline-<gitlabId>} pour filtrer par exécution CI. */
    private String pipelineTag;

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

    /**
     * Sous-ensemble de {@link #bySeverity} attribuable aux Tests DAST (ZAP), quand le dashboard
     * est scopé à un pipeline précis ({@code filterTag} non nul). Permet au Quality Gate de
     * distinguer le DAST des autres outils au lieu de le fondre dans les compteurs génériques.
     * Clés capitalisées ("Critical"/"High"/"Medium"/"Low"), même convention que {@link #bySeverity}.
     */
    private Map<String, Integer> dastBySeverity;

    /**
     * Sous-ensemble de {@link #bySeverity} attribuable aux Tests de scan de conteneur (Grype/
     * Anchore), même principe et même portée que {@link #dastBySeverity} -- ajouté le 29/08/2026
     * (diagnostic score-à-0 : le conteneur dominait les buckets génériques crit/high/med/low sans
     * lien avec ncloc). Clés capitalisées ("Critical"/"High"/"Medium"/"Low").
     */
    private Map<String, Integer> containerBySeverity;

    /**
     * Outils ayant réellement produit un Test pour ce pipeline, y compris ceux n'ayant rien trouvé
     * (0 finding) -- à utiliser pour "cet outil a-t-il tourné ?", jamais {@link #byTool} qui exclut
     * les entrées à 0 (pensé pour des comptages/badges, pas pour détecter l'exécution).
     */
    private Set<String> toolsExecuted;

    /** CVSS moyen par sévérité, calculé sur l'échantillon de findings ouverts (scopé pipeline). */
    private Map<String, Double> avgCvssBySeverity;

    /** Nombre de findings avec un CVSS connu, par sévérité, dans ce même échantillon. */
    private Map<String, Integer> cvssKnownCountBySeverity;

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
