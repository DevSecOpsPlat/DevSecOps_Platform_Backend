package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Résultat d'une synchronisation runtime (variables d'env → cluster RUNNING)
 * sans rebuild CI.
 */
@Data
@Builder
public class RuntimeSyncResponse {
    private boolean synced;
    @Builder.Default
    private List<String> namespaces = new ArrayList<>();
    @Builder.Default
    private List<String> restartedServices = new ArrayList<>();
    private String message;
}
