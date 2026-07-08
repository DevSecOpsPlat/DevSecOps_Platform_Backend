package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Paramètres optionnels d'un déploiement managé (branche Git + durée de vie de l'environnement).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ManagedDeployRequest {
    private String branch;

    @JsonAlias({"ttlHours", "ttl"})
    private Integer sessionDurationHours;

    public Integer resolvedTtlHours() {
        if (sessionDurationHours != null && sessionDurationHours > 0) {
            return Math.min(sessionDurationHours, 72);
        }
        return null;
    }
}
