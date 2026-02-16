package com.backend.devsecopsplatform_backend.entity;

public enum EnvironmentStatus {


    PENDING,


    BUILDING,


    RUNNING,


    FAILED,

    DESTROYED,


    EXPIRED;

    public boolean isActive() {
        return this == RUNNING;
    }

    public boolean isInProgress() {
        return this == PENDING || this == BUILDING;
    }

    public boolean isTerminated() {
        return this == FAILED || this == DESTROYED || this == EXPIRED;
    }

    public boolean canBeDestroyed() {
        return this != DESTROYED;
    }


    public String getDescription() {
        return switch (this) {
            case PENDING -> "En attente de création";
            case BUILDING -> "Construction en cours";
            case RUNNING -> "Actif et accessible";
            case FAILED -> "Échec du déploiement";
            case DESTROYED -> "Environnement détruit";
            case EXPIRED -> "Temps de vie écoulé";
        };
    }
    public String getColor() {
        return switch (this) {
            case PENDING -> "#FFA500";    // Orange
            case BUILDING -> "#2196F3";   // Bleu
            case RUNNING -> "#4CAF50";    // Vert
            case FAILED -> "#F44336";     // Rouge
            case DESTROYED -> "#9E9E9E";  // Gris
            case EXPIRED -> "#FF9800";    // Orange foncé
        };
    }

    public String getIcon() {
        return switch (this) {
            case PENDING -> "⏳";
            case BUILDING -> "🔨";
            case RUNNING -> "✅";
            case FAILED -> "❌";
            case DESTROYED -> "🗑️";
            case EXPIRED -> "⏰";
        };
    }
}