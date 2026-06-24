package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/** Snapshot par outil / test importé (SCA, SAST, …). */
@Data
@Builder
public class DefectDojoScanSnapshot {

    private int testId;
    private String scanType;
    private String label;
    /** Date ISO (yyyy-MM-dd). */
    private String date;
    /** Horodatage ISO8601 complet (created / updated du test). */
    private String timestamp;
    private int totalOpen;
    private Map<String, Integer> bySeverity;
}
