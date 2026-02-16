package com.backend.devsecopsplatform_backend.entity;

public enum ResourceType {


    POD,

    SERVICE,

    DEPLOYMENT,

    PVC,

    DATABASE,

    INGRESS,

    SECRET,

    CONFIGMAP;

    public boolean isKubernetesResource() {
        return this == POD ||
                this == SERVICE ||
                this == DEPLOYMENT ||
                this == PVC ||
                this == INGRESS ||
                this == SECRET ||
                this == CONFIGMAP;
    }


    public boolean isDatabaseResource() {
        return this == DATABASE;
    }

    public String getDescription() {
        return switch (this) {
            case POD -> "Conteneur d'application";
            case SERVICE -> "Service réseau";
            case DEPLOYMENT -> "Déploiement applicatif";
            case PVC -> "Volume de stockage";
            case DATABASE -> "Base de données PostgreSQL";
            case INGRESS -> "Point d'entrée HTTPS";
            case SECRET -> "Données sensibles";
            case CONFIGMAP -> "Configuration";
        };
    }
}