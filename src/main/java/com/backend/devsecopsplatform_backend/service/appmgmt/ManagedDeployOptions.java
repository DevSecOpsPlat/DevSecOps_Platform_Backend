package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.ManagedDeployRequest;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Options normalisées pour un déploiement managé (branche + TTL + sous-ensemble de services).
 */
public record ManagedDeployOptions(String branch, int ttlHours, List<UUID> serviceIds) {

    private static final int DEFAULT_TTL_HOURS = 4;

    public static ManagedDeployOptions from(ManagedDeployRequest request) {
        if (request == null) {
            return defaults(null);
        }
        return new ManagedDeployOptions(
                normalizeBranch(request.getBranch()),
                resolveTtlHours(request.resolvedTtlHours()),
                normalizeServiceIds(request.getServiceIds())
        );
    }

    public static ManagedDeployOptions defaults(String branch) {
        return new ManagedDeployOptions(normalizeBranch(branch), DEFAULT_TTL_HOURS, List.of());
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

    /** True si un filtre de services a été fourni. */
    public boolean hasServiceFilter() {
        return serviceIds != null && !serviceIds.isEmpty();
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

    private static List<UUID> normalizeServiceIds(List<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return List.copyOf(ids);
    }

    public List<UUID> serviceIdsOrEmpty() {
        return serviceIds != null ? serviceIds : Collections.emptyList();
    }
}
