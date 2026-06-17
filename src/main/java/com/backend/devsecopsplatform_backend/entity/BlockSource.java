package com.backend.devsecopsplatform_backend.entity;

/** Origine d'un blocage IP. */
public enum BlockSource {
    /** Déclenché automatiquement (force brute, honeypot, rate limit…). */
    AUTO,
    /** Débloqué puis re-bloqué manuellement par un admin (extension future). */
    MANUAL
}
