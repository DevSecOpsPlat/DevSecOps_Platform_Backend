package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Data;

import java.util.List;

/** Corps du callback de statut envoyé par le pipeline de déploiement. */
@Data
public class DeploymentStatusCallbackRequest {

    /** « RUNNING »/« SUCCESS » → succès, toute autre valeur → échec. */
    private String status;

    /** Namespace confirmé (optionnel). */
    private String namespace;

    /**
     * Noms des services signalés Ready par le pipeline (optionnel). Si absent et statut =
     * succès, tous les services sont considérés Ready.
     */
    private List<String> readyServices;
}
