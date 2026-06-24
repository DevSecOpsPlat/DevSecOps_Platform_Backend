package com.backend.devsecopsplatform_backend.controller.security;

import com.backend.devsecopsplatform_backend.entity.Finding;
import com.backend.devsecopsplatform_backend.entity.FindingOccurrence;
import com.backend.devsecopsplatform_backend.repository.FindingOccurrenceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/security/vulnerabilities")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local:4200"})
public class SecurityVulnerabilitiesController {

    private final FindingOccurrenceRepository findingOccurrenceRepository;

    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> recent(
            @RequestParam(defaultValue = "5") int limit,
            @RequestParam(required = false) UUID appId,
            @RequestParam(required = false) UUID envId
    ) {
        String username = currentUsername();
        int size = Math.max(1, Math.min(limit, 50));

        List<FindingOccurrence> occs;
        if (envId != null) {
            occs = findingOccurrenceRepository.findRecentForUsernameAndEnvironment(username, envId, PageRequest.of(0, size));
        } else if (appId != null) {
            occs = findingOccurrenceRepository.findRecentForUsernameAndApplication(username, appId, PageRequest.of(0, size));
        } else {
            occs = findingOccurrenceRepository.findRecentForUsername(username, PageRequest.of(0, size));
        }
        List<Map<String, Object>> out = occs.stream().map(this::toDashboardItem).toList();
        return ResponseEntity.ok(out);
    }

    private Map<String, Object> toDashboardItem(FindingOccurrence occ) {
        Finding f = occ.getFinding();
        // Map.of(...) n'accepte pas les valeurs null -> utiliser une map mutable.
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("id", f.getId());
        m.put("title", f.getTitle() != null ? f.getTitle() : (f.getRuleId() != null ? f.getRuleId() : f.getFingerprint()));
        m.put("severity", f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM");
        m.put("component", f.getPackageName() != null ? f.getPackageName() : (f.getFilePath() != null ? f.getFilePath() : "N/A"));
        m.put("version", f.getInstalledVersion() != null ? f.getInstalledVersion() : "");
        m.put("fixedVersion", f.getFixedVersion());
        m.put("description", f.getDescription());
        m.put("createdAt", occ.getObservedAt());
        return m;
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            throw new RuntimeException("Utilisateur non authentifié");
        }
        return auth.getName();
    }
}

