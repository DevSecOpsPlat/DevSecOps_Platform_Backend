package com.backend.devsecopsplatform_backend.service.appmgmt;

import java.util.Locale;
import java.util.UUID;

/** Utilitaires de nommage : slugs et noms de ressources Kubernetes (RFC 1123). */
public final class AppNaming {

    private AppNaming() {
    }

    /**
     * Normalise une chaîne en nom DNS-1123 (minuscules, tirets, 1..63 car.),
     * utilisable comme nom de ressource K8s ou fragment de namespace.
     */
    public static String k8sName(String input) {
        if (input == null || input.isBlank()) {
            return "x";
        }
        String s = input.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-+", "")
                .replaceAll("-+$", "");
        if (s.isEmpty()) {
            s = "x";
        }
        if (s.length() > 50) {
            s = s.substring(0, 50).replaceAll("-+$", "");
        }
        return s;
    }

    /** Slug applicatif (namespace friendly). */
    public static String slug(String name) {
        return k8sName(name);
    }

    /** Fragment court d'un UUID (8 premiers caractères). */
    public static String shortId(UUID id) {
        return id.toString().substring(0, 8);
    }

    /** Namespace d'un déploiement : env-<slug>-<shortid>. */
    public static String namespace(String slug, UUID deploymentId) {
        return "env-" + k8sName(slug) + "-" + shortId(deploymentId);
    }
}
