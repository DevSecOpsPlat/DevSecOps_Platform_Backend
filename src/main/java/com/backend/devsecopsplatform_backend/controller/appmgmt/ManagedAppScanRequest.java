package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.UUID;
/**
 * Corps {@code POST /api/managed-applications/{appId}/scan}.
 */
@Data
public class ManagedAppScanRequest {

    /** Sous-ensemble de services ; null/vide = tous les services de l'app. */
    private List<UUID> serviceIds;

    /**
     * Branche optionnelle par serviceId.
     * Absent → {@code AppService.gitBranch} (sinon {@code main}).
     */
    private Map<UUID, String> branchesByServiceId;

    /** Branche unique appliquée à tous les services sélectionnés si {@code branchesByServiceId} absent. */
    private String branch;
}
