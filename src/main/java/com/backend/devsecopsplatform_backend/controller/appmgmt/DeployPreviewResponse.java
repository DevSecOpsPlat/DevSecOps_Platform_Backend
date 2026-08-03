package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Aperçu informatif avant déploiement (infos, avertissements, confirmation forte).
 * Aucun message ici n'est bloquant sauf {@code blockingErrors}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeployPreviewResponse {
    @Builder.Default
    private List<String> infos = new ArrayList<>();
    @Builder.Default
    private List<String> warnings = new ArrayList<>();
    @Builder.Default
    private List<String> blockingErrors = new ArrayList<>();
    /** True si un backend sans BD est inclus — l'UI doit demander une confirmation explicite. */
    private boolean requiresConfirmation;
    private int ttlHours;
    private int selectedServiceCount;
    private int selectedDatabaseCount;
    @Builder.Default
    private List<UUID> resolvedServiceIds = new ArrayList<>();
}
