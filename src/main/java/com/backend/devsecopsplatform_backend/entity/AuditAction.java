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
    ACTIVATION_EMAIL_SENT
}
