package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Paramètres optionnels d'un déploiement managé (branche Git + durée de vie + sous-ensemble de services).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ManagedDeployRequest {
    private String branch;

    @JsonAlias({"ttlHours", "ttl"})
    private Integer sessionDurationHours;

    /**
     * Sous-ensemble de services à déployer. Null ou vide = tous les services du projet.
     * Les bases liées aux services sélectionnés sont incluses automatiquement.
     * Les dépendances service→service manquantes ne sont pas forcées (avertissement seulement).
     */
    private List<UUID> serviceIds;

    public Integer resolvedTtlHours() {
        if (sessionDurationHours != null && sessionDurationHours > 0) {
            return Math.min(sessionDurationHours, 72);
        }
        return null;
    }
}
