package com.backend.devsecopsplatform_backend.service.appmgmt;

/**
 * Erreur de validation métier → traduite en HTTP 400 avec un message clair par le
 * contrôleur (architecture.md §3.2).
 */
public class AppValidationException extends RuntimeException {
    public AppValidationException(String message) {
        super(message);
    }
}
