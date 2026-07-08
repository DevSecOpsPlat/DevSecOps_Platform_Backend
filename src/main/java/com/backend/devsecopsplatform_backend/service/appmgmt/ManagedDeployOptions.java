package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.ManagedDeployRequest;

/**
 * Options normalisées pour un déploiement managé (branche + TTL environnement).
 */
public record ManagedDeployOptions(String branch, int ttlHours) {

    private static final int DEFAULT_TTL_HOURS = 4;

    public static ManagedDeployOptions from(ManagedDeployRequest request) {
        if (request == null) {
            return defaults(null);
        }
        return new ManagedDeployOptions(
                normalizeBranch(request.getBranch()),
                resolveTtlHours(request.resolvedTtlHours())
        );
    }

    public static ManagedDeployOptions defaults(String branch) {
        return new ManagedDeployOptions(normalizeBranch(branch), DEFAULT_TTL_HOURS);
    }

    public String resolveBranch(String serviceBranch) {
        if (branch != null && !branch.isBlank()) {
            return branch;
        }
        if (serviceBranch != null && !serviceBranch.isBlank()) {
            return serviceBranch.trim();
        }
        return "main";
    }

    private static String normalizeBranch(String branch) {
        if (branch == null || branch.isBlank()) {
            return null;
        }
        return branch.trim();
    }

    private static int resolveTtlHours(Integer sessionDurationHours) {
        if (sessionDurationHours == null || sessionDurationHours <= 0) {
            return DEFAULT_TTL_HOURS;
        }
        return Math.min(sessionDurationHours, 72);
    }
}
