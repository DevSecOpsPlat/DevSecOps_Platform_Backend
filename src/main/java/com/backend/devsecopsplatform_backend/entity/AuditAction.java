package com.backend.devsecopsplatform_backend.entity;

/** Actions tracées dans le journal d'audit global. */
public enum AuditAction {
    ACCOUNT_CREATED,
    ACCOUNT_DELETED,
    ACCOUNT_ENABLED,
    ACCOUNT_DISABLED,
    PASSWORD_CHANGED,
    ADMIN_PASSWORD_RESET,
    EMAIL_CHANGED,
    ADMIN_EMAIL_CHANGED,
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    ACCOUNT_LOCKED,
    ACCOUNT_ACTIVATED,
    ACTIVATION_EMAIL_SENT,
    /** Activité suspecte détectée (scan, payload malveillant, honeypot). */
    SUSPICIOUS_ACTIVITY,
    /** IP bloquée automatiquement par le moniteur de sécurité. */
    IP_BLOCKED,
    /** Double authentification activée. */
    TWO_FACTOR_ENABLED,
    /** Double authentification désactivée. */
    TWO_FACTOR_DISABLED,
    /** Code TOTP incorrect à la connexion. */
    TWO_FACTOR_FAILED,
    /** Changement de méthode 2FA (TOTP ↔ e-mail). */
    TWO_FACTOR_METHOD_CHANGED
}
