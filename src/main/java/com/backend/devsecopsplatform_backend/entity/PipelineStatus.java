package com.backend.devsecopsplatform_backend.entity;

public enum PipelineStatus {

    PENDING,

    RUNNING,

    SUCCESS,

    FAILED,

    CANCELED,

    SKIPPED;

    public boolean isFinished() {
        return this == SUCCESS ||
                this == FAILED ||
                this == CANCELED ||
                this == SKIPPED;
    }


    public boolean isRunning() {
        return this == RUNNING;
    }


    public boolean isPending() {
        return this == PENDING;
    }

    public boolean isSuccessful() {
        return this == SUCCESS;
    }

    public boolean hasFailed() {
        return this == FAILED || this == CANCELED;
    }

    public boolean canRetry() {
        return this == FAILED || this == CANCELED;
    }

    public String getDescription() {
        return switch (this) {
            case PENDING -> "En attente";
            case RUNNING -> "En cours d'exécution";
            case SUCCESS -> "Réussi";
            case FAILED -> "Échoué";
            case CANCELED -> "Annulé";
            case SKIPPED -> "Ignoré";
        };
    }

    public String getColor() {
        return switch (this) {
            case PENDING -> "#FFB74D";    // Orange clair
            case RUNNING -> "#42A5F5";    // Bleu
            case SUCCESS -> "#66BB6A";    // Vert
            case FAILED -> "#EF5350";     // Rouge
            case CANCELED -> "#BDBDBD";   // Gris
            case SKIPPED -> "#9E9E9E";    // Gris foncé
        };
    }


    public String getIcon() {
        return switch (this) {
            case PENDING -> "⏱️";
            case RUNNING -> "▶️";
            case SUCCESS -> "✅";
            case FAILED -> "❌";
            case CANCELED -> "⛔";
            case SKIPPED -> "⏭️";
        };
    }


    public String toGitLabStatus() {
        return switch (this) {
            case PENDING -> "pending";
            case RUNNING -> "running";
            case SUCCESS -> "success";
            case FAILED -> "failed";
            case CANCELED -> "canceled";
            case SKIPPED -> "skipped";
        };
    }


    public static PipelineStatus fromGitLabStatus(String gitlabStatus) {
        if (gitlabStatus == null) return PENDING;

        return switch (gitlabStatus.toLowerCase()) {
            case "pending", "created" -> PENDING;
            case "running", "manual" -> RUNNING;
            case "success", "passed" -> SUCCESS;
            case "failed" -> FAILED;
            case "canceled", "cancelled" -> CANCELED;
            case "skipped" -> SKIPPED;
            default -> PENDING;
        };
    }
}