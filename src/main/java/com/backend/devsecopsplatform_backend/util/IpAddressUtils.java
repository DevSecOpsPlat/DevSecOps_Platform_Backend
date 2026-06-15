package com.backend.devsecopsplatform_backend.util;

import jakarta.servlet.http.HttpServletRequest;

public final class IpAddressUtils {

    private IpAddressUtils() {}

    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String forwarded = firstNonBlank(
                request.getHeader("X-Forwarded-For"),
                request.getHeader("X-Real-IP"),
                request.getHeader("CF-Connecting-IP")
        );
        if (forwarded != null) {
            return normalize(forwarded.split(",")[0].trim());
        }
        return normalize(request.getRemoteAddr());
    }

    /** Affichage lisible (ex. localhost au lieu de ::1). */
    public static String normalize(String ip) {
        if (ip == null || ip.isBlank()) {
            return "—";
        }
        String trimmed = ip.trim();
        if ("0:0:0:0:0:0:0:1".equals(trimmed) || "::1".equals(trimmed)) {
            return "127.0.0.1 (localhost)";
        }
        if ("127.0.0.1".equals(trimmed)) {
            return "127.0.0.1 (localhost)";
        }
        if ("0:0:0:0:0:0:0:1%0".equals(trimmed) || trimmed.startsWith("127.0.0.1%")) {
            return "127.0.0.1 (localhost)";
        }
        return trimmed;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
