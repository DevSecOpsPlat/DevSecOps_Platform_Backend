package com.backend.devsecopsplatform_backend.util;

import jakarta.servlet.http.HttpServletRequest;

public final class IpAddressUtils {

    private IpAddressUtils() {}

    /**
     * Retourne l'adresse IP réelle du client à partir de la requête HTTP.
     * Supporte les proxies via X-Forwarded-For, X-Real-IP, etc.
     */
    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        return normalize(extractRaw(request));
    }

    private static String extractRaw(HttpServletRequest request) {
        String forwarded = firstNonBlank(
                request.getHeader("X-Forwarded-For"),
                request.getHeader("X-Real-IP"),
                request.getHeader("CF-Connecting-IP")
        );
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /** Affichage lisible (ex. localhost au lieu de ::1). */
    public static String normalize(String ip) {
        if (ip == null || ip.isBlank()) {
            return "—";
        }
        String trimmed = ip.trim();
        if (isLoopback(trimmed)) {
            return "127.0.0.1 (localhost)";
        }
        return trimmed;
    }

    private static boolean isLoopback(String ip) {
        return "0:0:0:0:0:0:0:1".equals(ip)
                || "::1".equals(ip)
                || "127.0.0.1".equals(ip)
                || ip.startsWith("127.0.0.1%")
                || ip.startsWith("0:0:0:0:0:0:0:1%");
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
