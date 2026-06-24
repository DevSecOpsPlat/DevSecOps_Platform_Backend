package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Bloque l'accès API tant que la 2FA n'est pas configurée (obligatoire pour tous les comptes).
 * Seuls les endpoints profil / 2FA restent accessibles.
 */
@Component
@RequiredArgsConstructor
public class TwoFactorEnforcementFilter extends OncePerRequestFilter {

    private static final List<String> ALLOWED_WITHOUT_2FA = List.of(
            "/api/profile/me",
            "/api/profile/email",
            "/api/profile/password",
            "/api/profile/2fa/status",
            "/api/profile/2fa/setup",
            "/api/profile/2fa/setup/totp",
            "/api/profile/2fa/setup/email",
            "/api/profile/2fa/enable",
            "/api/profile/2fa/enable/totp",
            "/api/profile/2fa/enable/email",
            "/api/profile/2fa/disable"
    );

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication.getPrincipal() == null
                || "anonymousUser".equals(authentication.getPrincipal())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = stripContextPath(request.getRequestURI(), request.getContextPath());
        if (isAllowedWithoutTwoFactor(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        User user = userRepository.findByUsername(authentication.getName()).orElse(null);
        if (user == null || user.isTwoFactorEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), Map.of(
                "message", "La double authentification est obligatoire. Configurez-la depuis votre profil.",
                "mustEnableTwoFactor", true
        ));
    }

    private boolean isAllowedWithoutTwoFactor(String path) {
        if (path == null) {
            return false;
        }
        for (String allowed : ALLOWED_WITHOUT_2FA) {
            if (path.equals(allowed) || path.startsWith(allowed)) {
                return true;
            }
        }
        return false;
    }

    private String stripContextPath(String uri, String contextPath) {
        if (uri == null) {
            return "";
        }
        if (contextPath != null && !contextPath.isBlank() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }
}
