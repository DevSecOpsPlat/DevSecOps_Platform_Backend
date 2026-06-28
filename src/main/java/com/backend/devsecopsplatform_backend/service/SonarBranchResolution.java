package com.backend.devsecopsplatform_backend.service;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/** Résultat de la résolution branche SonarQube (project_branches/list). */
@Data
@Builder
public class SonarBranchResolution {
    private String requestedBranch;
    private String resolvedBranch;
    private boolean branchFallback;
    private String fallbackMessage;
    private List<String> availableBranches;
    private boolean sonarReachable;
}
