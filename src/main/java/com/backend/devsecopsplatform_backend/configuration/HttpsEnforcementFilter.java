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

/**
 * Chiffrement en transit : refuse le trafic HTTP lorsque {@code app.security.data-protection.require-https=true}
 * (Nginx doit envoyer {@code X-Forwarded-Proto: https}).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@RequiredArgsConstructor
public class HttpsEnforcementFilter extends OncePerRequestFilter {

    private final DataProtectionProperties properties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.isRequireHttps()) {
            filterChain.doFilter(request, response);
            return;
        }

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String proto = resolveProto(request);
        if (!"https".equalsIgnoreCase(proto)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"message\":\"Connexion HTTPS obligatoire (données chiffrées en transit — TLS).\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String resolveProto(HttpServletRequest request) {
        if (properties.isTrustForwardedHeaders()) {
            String forwarded = request.getHeader("X-Forwarded-Proto");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
        }
        return request.getScheme();
    }
}
