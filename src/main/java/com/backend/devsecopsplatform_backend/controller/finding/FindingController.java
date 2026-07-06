package com.backend.devsecopsplatform_backend.controller.finding;

import com.backend.devsecopsplatform_backend.entity.FindingStatus;
import com.backend.devsecopsplatform_backend.entity.ScanType;
import com.backend.devsecopsplatform_backend.entity.Severity;
import com.backend.devsecopsplatform_backend.repository.FindingOccurrenceRepository;
import com.backend.devsecopsplatform_backend.repository.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * API findings locaux (ingestion pipeline) — conservée pour l’overview projet (fallback KPI / liste).
 * Le dashboard sécurité principal est DefectDojo ({@code /api/defectdojo/**}).
 */
@RestController
@RequestMapping("/api/findings")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class FindingController {

    private final FindingRepository findingRepository;
    private final FindingOccurrenceRepository findingOccurrenceRepository;

    @GetMapping("/by-application/{appId}")
    public ResponseEntity<?> listByApplication(
            @PathVariable UUID appId,
            @RequestParam(required = false) String branch,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String tool,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String scanType,
            @RequestParam(required = false) String status
    ) {
        String branchParam = (branch != null && !branch.isBlank()) ? branch.trim() : null;
        String toolParam = (tool != null && !tool.isBlank()) ? tool.trim() : null;

        Severity severityEnum = parseEnum(severity, Severity.class);
        if (severity != null && !severity.isBlank() && severityEnum == null) {
            return ResponseEntity.badRequest().build();
        }
        ScanType scanTypeEnum = parseEnum(scanType, ScanType.class);
        if (scanType != null && !scanType.isBlank() && scanTypeEnum == null) {
            return ResponseEntity.badRequest().build();
        }
        FindingStatus statusEnum = parseEnum(status, FindingStatus.class);
        if (status != null && !status.isBlank() && statusEnum == null) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(findingRepository.findByApplicationFiltered(
                appId,
                branchParam,
                toolParam,
                severityEnum,
                scanTypeEnum,
                statusEnum,
                PageRequest.of(page, Math.min(size, 200))
        ));
    }

    @GetMapping("/stats/by-application/{appId}")
    public ResponseEntity<Map<String, Object>> statsByApplication(
            @PathVariable UUID appId,
            @RequestParam(required = false) String status
    ) {
        FindingStatus st = null;
        if (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim())) {
            st = parseEnum(status, FindingStatus.class);
            if (st == null) {
                return ResponseEntity.badRequest().build();
            }
        }
        var bySeverity = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsBySeverityForApplication(appId, st));
        var byTool = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsByToolForApplication(appId, st));
        var byScanType = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsByScanTypeForApplication(appId, st));
        long totalDistinct = bySeverity.values().stream().mapToLong(Long::longValue).sum();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("applicationId", appId);
        body.put("statusFilter", st == null ? "ALL" : st.name());
        body.put("openDistinctTotal", totalDistinct);
        body.put("distinctTotal", totalDistinct);
        body.put("bySeverity", bySeverity);
        body.put("byTool", byTool);
        body.put("byScanType", byScanType);
        return ResponseEntity.ok(body);
    }

    private static <E extends Enum<E>> E parseEnum(String raw, Class<E> type) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Enum.valueOf(type, raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Map<String, Long> toCountMap(java.util.List<Object[]> rows) {
        Map<String, Long> out = new java.util.HashMap<>();
        for (Object[] r : rows) {
            if (r == null || r.length < 2) continue;
            Object k = r[0];
            Object v = r[1];
            if (k == null || v == null) continue;
            out.put(String.valueOf(k), ((Number) v).longValue());
        }
        return out;
    }
}
