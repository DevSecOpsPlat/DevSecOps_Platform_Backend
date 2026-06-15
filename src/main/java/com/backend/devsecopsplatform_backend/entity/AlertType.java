package com.backend.devsecopsplatform_backend.entity;

/** Type d'alerte affichée dans la console admin (incidents de sécurité uniquement). */
public enum AlertType {
    /** Connexion échouée (chaque tentative). */
    LOGIN_FAILED,
    /** @deprecated conservé pour les anciennes lignes — utiliser ACCOUNT_LOCKED */
    FAILED_LOGIN_REPEATED,
    ACCOUNT_LOCKED,
    PASSWORD_CHANGED,
    EMAIL_CHANGED,
    UNAUTHORIZED_ACCESS,
    /** @deprecated anciennes alertes admin — voir journal d'audit */
    ACCOUNT_CREATED,
    ACCOUNT_DELETED,
    ACCOUNT_ENABLED,
    ACCOUNT_DISABLED,
    ADMIN_PASSWORD_RESET,
    ADMIN_EMAIL_CHANGED
}
