package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
@RequiredArgsConstructor
public class SecurityExceptionHandlers implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final SecurityEventService securityEventService;
    private final UserRepository userRepository;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         org.springframework.security.core.AuthenticationException authException) throws IOException {
        log.warn("401 UNAUTHORIZED on {} {} (auth missing/invalid)", request.getMethod(), request.getRequestURI());
        writeJson(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentification requise.");
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        String uri = request.getRequestURI();
        log.warn("403 FORBIDDEN on {} {} (access denied)", request.getMethod(), uri);

        if (isAdminApi(uri)) {
            User user = resolveCurrentUser();
            String ip = IpAddressUtils.resolve(request);
            String username = user != null ? user.getUsername() : "inconnu";
            String message = String.format(
                    "Accès admin refusé — %s %s — utilisateur : %s — IP : %s",
                    request.getMethod(),
                    stripContextPath(uri, request.getContextPath()),
                    username,
                    ip
            );
            securityEventService.createAlert(AlertType.UNAUTHORIZED_ACCESS, message, user, ip);
        }

        writeJson(response, HttpServletResponse.SC_FORBIDDEN, "Accès refusé. Droits insuffisants.");
    }

    private boolean isAdminApi(String uri) {
        return uri != null && (uri.contains("/api/admin/") || uri.endsWith("/api/admin"));
    }

    private String stripContextPath(String uri, String contextPath) {
        if (contextPath != null && !contextPath.isBlank() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    private User resolveCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetails details) {
            return userRepository.findByUsername(details.getUsername()).orElse(null);
        }
        if (principal instanceof String username && !"anonymousUser".equals(username)) {
            return userRepository.findByUsername(username).orElse(null);
        }
        return null;
    }

    private void writeJson(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json;charset=UTF-8");
        String body = "{\"message\":\"" + escapeJson(message) + "\"}";
        response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
