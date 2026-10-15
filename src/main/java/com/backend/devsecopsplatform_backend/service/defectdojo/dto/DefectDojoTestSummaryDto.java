package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Un Test DefectDojo (scan_type + id), pour résoudre le testId exact d'un outil (ex. "ZAP Scan")
 * au sein d'un pipeline -- {@code GET /api/defectdojo/findings?testId=...} isole alors ses findings
 * sans être noyé par un autre outil du même pipeline qui en aurait beaucoup plus (ex. Grype avec
 * des centaines de vulnérabilités face aux quelques dizaines de ZAP -- une page combinée plafonnée
 * à 100 résultats peut sinon exclure entièrement le second outil).
 */
@Data
@AllArgsConstructor
public class DefectDojoTestSummaryDto {
    private int testId;
    private String scanType;
}
