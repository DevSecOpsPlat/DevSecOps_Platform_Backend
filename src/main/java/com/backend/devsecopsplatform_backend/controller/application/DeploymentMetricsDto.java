package com.backend.devsecopsplatform_backend.controller.application;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Totaux agrégés des exécutions de pipeline pour une application (toutes pages),
 * pour alimenter le dashboard sans confondre avec la taille d’une page d’historique.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeploymentMetricsDto {

    private long total;
    private long success;
    private long failed;
    private long canceled;
    private long pending;
    private long running;
    private long skipped;
}
