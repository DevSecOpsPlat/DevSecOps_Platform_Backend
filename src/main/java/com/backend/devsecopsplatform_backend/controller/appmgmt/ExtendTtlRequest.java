package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/**
 * Prolongation du TTL d'un déploiement managé (heures supplémentaires).
 */
@Data
public class ExtendTtlRequest {

    /** Heures à ajouter (1–24). Alias JSON : hours, ttlHours. */
    @NotNull
    @Min(1)
    @Max(24)
    @JsonAlias({"hours", "ttlHours"})
    private Integer additionalHours;
}
