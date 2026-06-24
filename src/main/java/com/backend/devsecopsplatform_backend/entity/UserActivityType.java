package com.backend.devsecopsplatform_backend.entity;

/**
 * Type d'événement tracé dans le journal d'activité d'un compte utilisateur.
 */
public enum UserActivityType {
    ACCOUNT_CREATED,
    EMAIL_CHANGED,
    PASSWORD_CHANGED,
    ADMIN_EMAIL_CHANGED,
    ADMIN_PASSWORD_RESET,
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED
}
