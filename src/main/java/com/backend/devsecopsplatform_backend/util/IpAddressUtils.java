package com.backend.devsecopsplatform_backend.util;

import jakarta.servlet.http.HttpServletRequest;

public final class IpAddressUtils {

    private IpAddressUtils() {}

    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
