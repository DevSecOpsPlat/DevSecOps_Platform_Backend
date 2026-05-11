package com.backend.devsecopsplatform_backend.entity;

/**
 * Statut d'une réclamation utilisateur.
 */
public enum ComplaintStatus {
    /** Discussion ouverte : nouveaux messages autorisés. */
    OPEN,
    /** Fermée : lecture seule du fil. */
    CLOSED
}
