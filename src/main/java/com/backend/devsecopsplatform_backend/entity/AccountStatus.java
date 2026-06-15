package com.backend.devsecopsplatform_backend.entity;

/**
 * Statut du compte : les comptes sont créés par l'administrateur (pas d'auto-inscription),
 * donc seul un état actif / désactivé est nécessaire.
 */
public enum AccountStatus {
    ACTIVE,
    DISABLED
}
