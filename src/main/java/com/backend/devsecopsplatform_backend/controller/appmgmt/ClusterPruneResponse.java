package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Résultat d'un nettoyage cluster après suppression d'un service / d'une base
 * dans le modèle applicatif.
 */
@Data
@Builder
public class ClusterPruneResponse {
    private boolean pruned;
    @Builder.Default
    private List<String> namespaces = new ArrayList<>();
    @Builder.Default
    private List<String> removedResources = new ArrayList<>();
    private String message;
}
