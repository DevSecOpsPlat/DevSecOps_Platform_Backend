package com.backend.devsecopsplatform_backend.entity;

/** Type d'alerte affichée dans la console admin. */
public enum AlertType {
    FAILED_LOGIN_REPEATED,
    ACCOUNT_CREATED,
    ACCOUNT_DELETED,
    PASSWORD_CHANGED,
    EMAIL_CHANGED,
    ACCOUNT_LOCKED,
    ACCOUNT_ENABLED,
    ACCOUNT_DISABLED,
    ADMIN_PASSWORD_RESET,
    ADMIN_EMAIL_CHANGED
}
