package com.backend.devsecopsplatform_backend.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** En-têtes de sécurité (dont HSTS si HTTPS) — complète Nginx. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 21)
@RequiredArgsConstructor
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final DataProtectionProperties properties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        response.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        response.setHeader("Cache-Control", "no-store");

        if (properties.isHstsEnabled() && isHttps(request)) {
            response.setHeader("Strict-Transport-Security",
                    "max-age=" + properties.getHstsMaxAgeSeconds() + "; includeSubDomains");
        }

        filterChain.doFilter(request, response);
    }

    private boolean isHttps(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-Proto");
        if (forwarded != null && forwarded.toLowerCase().contains("https")) {
            return true;
        }
        return "https".equalsIgnoreCase(request.getScheme());
    }
}
