package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

/** Métriques détaillées alignées sur le dashboard DefectDojo. */
@Data
@Builder
public class DefectDojoDetailedMetrics {

    /** Ouvertes jour par jour, par sévérité. */
    private List<DefectDojoTimeSeriesPoint> openDayToDayBySeverity;

    /** Ouvertes heure par heure, par sévérité. */
    private List<DefectDojoTimeSeriesPoint> openHourToHourBySeverity;

    /** Ouvertes / fermées / risk accepted semaine par semaine. */
    private List<DefectDojoWeekStatusPoint> weekToWeekStatus;

    /** Ouvertes semaine par semaine, par sévérité. */
    private List<DefectDojoTimeSeriesPoint> weekToWeekBySeverity;

    /** Âge des findings ouverts (ex. « 0-7 j », « 8-30 j »). */
    private Map<String, Integer> findingAgeBuckets;

    private int openFindingsForAge;

    /** Activité hebdomadaire (jour × semaine). */
    private List<DefectDojoWeeklyActivityPoint> weeklyActivity;

    /** CWE ouverts (top). */
    private Map<String, Integer> openCwe;

    /** CWE total (top). */
    private Map<String, Integer> totalCwe;
}
