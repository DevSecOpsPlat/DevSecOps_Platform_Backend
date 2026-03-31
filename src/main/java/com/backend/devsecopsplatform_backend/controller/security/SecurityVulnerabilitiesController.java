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

@RestController
@RequestMapping("/api/security/vulnerabilities")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class SecurityVulnerabilitiesController {

    private final FindingOccurrenceRepository findingOccurrenceRepository;

    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> recent(@RequestParam(defaultValue = "5") int limit) {
        String username = currentUsername();
        int size = Math.max(1, Math.min(limit, 50));

        List<FindingOccurrence> occs = findingOccurrenceRepository.findRecentForUsername(username, PageRequest.of(0, size));
        List<Map<String, Object>> out = occs.stream().map(this::toDashboardItem).toList();
        return ResponseEntity.ok(out);
    }

    private Map<String, Object> toDashboardItem(FindingOccurrence occ) {
        Finding f = occ.getFinding();
        return Map.of(
                "id", f.getId(),
                "title", f.getTitle() != null ? f.getTitle() : (f.getRuleId() != null ? f.getRuleId() : f.getFingerprint()),
                "severity", f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM",
                "component", f.getPackageName() != null ? f.getPackageName() : (f.getFilePath() != null ? f.getFilePath() : "N/A"),
                "version", f.getInstalledVersion() != null ? f.getInstalledVersion() : "",
                "fixedVersion", f.getFixedVersion(),
                "description", f.getDescription(),
                "createdAt", occ.getObservedAt()
        );
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            throw new RuntimeException("Utilisateur non authentifié");
        }
        return auth.getName();
    }
}

