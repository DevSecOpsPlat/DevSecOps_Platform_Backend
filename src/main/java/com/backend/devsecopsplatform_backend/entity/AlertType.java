package com.backend.devsecopsplatform_backend.entity;

/** Type d'alerte affichée dans la console admin (incidents de sécurité uniquement). */
public enum AlertType {
    /** Connexion échouée (chaque tentative). */
    LOGIN_FAILED,
    /** @deprecated conservé pour les anciennes lignes — utiliser ACCOUNT_LOCKED */
    FAILED_LOGIN_REPEATED,
    ACCOUNT_LOCKED,
    /** Force brute détectée par IP (plusieurs échecs / comptes). */
    BRUTE_FORCE_DETECTED,
    /** Pic de requêtes HTTP depuis une même IP. */
    RATE_LIMIT_EXCEEDED,
    /** Accès à une URL piège (honeypot). */
    HONEYPOT_TRIGGERED,
    /** Scan de chemins sensibles (.env, wp-admin, etc.). */
    SUSPICIOUS_REQUEST,
    /** Payload SQL / XSS détecté dans la requête. */
    MALICIOUS_PAYLOAD,
    /** User-Agent absent ou typique d'un outil d'attaque. */
    SUSPICIOUS_USER_AGENT,
    /** IP bloquée automatiquement après détection. */
    IP_BLOCKED,
    PASSWORD_CHANGED,
    EMAIL_CHANGED,
    UNAUTHORIZED_ACCESS,
    /** @deprecated anciennes alertes admin — voir journal d'audit */
    ACCOUNT_CREATED,
    ACCOUNT_DELETED,
    ACCOUNT_ENABLED,
    ACCOUNT_DISABLED,
    ADMIN_PASSWORD_RESET,
    ADMIN_EMAIL_CHANGED,
    /** Pod CrashLoopBackOff / ImagePullBackOff sur un déploiement managé. */
    DEPLOYMENT_CRASH_LOOP,
    /** Pod OOMKilled (mémoire insuffisante). */
    DEPLOYMENT_OOM,
    /** Pod Failed. */
    DEPLOYMENT_POD_FAILED,
    /** Health URL publique KO. */
    DEPLOYMENT_HEALTH_FAILED,
    /** Événement Kubernetes Warning (FailedCreate, FailedScheduling, Unhealthy…). */
    DEPLOYMENT_K8S_WARNING,
    /** Application à chaud (env vars, ressources…) sans rebuild CI — traçabilité (audit-deploiement.md, chantier #5). */
    DEPLOYMENT_SYNC_RUNTIME
}
