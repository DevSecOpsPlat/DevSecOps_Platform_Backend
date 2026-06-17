package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.service.security.monitoring.Bucket4jRateLimitService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.Bucket4jRateLimitService.RateLimitResult;
import com.backend.devsecopsplatform_backend.service.security.monitoring.Bucket4jRateLimitService.Scope;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBlocklistService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.SecurityMonitoringService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.ThreatDetectionService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.ThreatScanResult;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import com.backend.devsecopsplatform_backend.util.SecurityAlertDetailsBuilder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringFilter extends OncePerRequestFilter {

    private static final int HTTP_TOO_MANY_REQUESTS = 429;

    private final SecurityMonitoringProperties properties;
    private final SecurityMonitoringService monitoringService;
    private final IpBlocklistService blocklistService;
    private final Bucket4jRateLimitService rateLimiter;
    private final ThreatDetectionService threatDetection;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.isMonitoringEnabled() || "OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = IpAddressUtils.resolve(request);
        if (monitoringService.shouldBypassMonitoring(ip)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (blocklistService.isBlocked(ip)) {
            writeJson(response, HTTP_TOO_MANY_REQUESTS,
                    "Adresse IP temporairement bloquée pour activité suspecte.");
            return;
        }

        String path = stripContextPath(request.getRequestURI(), request.getContextPath());
        String query = request.getQueryString();
        String userAgent = request.getHeader("User-Agent");
        boolean loginPath = isLoginPath(path);
        boolean adminPath = isAdminPath(path);
        boolean sensitive = loginPath || adminPath;
//verfier nb de requetes 
        RateLimitResult global = rateLimiter.tryConsume(ip, Scope.GLOBAL);
        if (!global.allowed()) {
            monitoringService.handleRateLimitExceeded(ip, "global", global.limit(), global.windowSeconds());
            writeRateLimitResponse(response, global, "Trop de requêtes. Réessayez plus tard.");
            return;
        }

        if (loginPath) {
            RateLimitResult login = rateLimiter.tryConsume(ip, Scope.LOGIN);
            if (!login.allowed()) {
                monitoringService.handleRateLimitExceeded(ip, "/auth/login", login.limit(), login.windowSeconds());
                writeRateLimitResponse(response, login, "Trop de tentatives de connexion. Réessayez plus tard.");
                return;
            }
        }

        if (adminPath) {
            RateLimitResult admin = rateLimiter.tryConsume(ip, Scope.ADMIN);
            if (!admin.allowed()) {
                monitoringService.handleRateLimitExceeded(ip, "/api/admin", admin.limit(), admin.windowSeconds());
                writeRateLimitResponse(response, admin, "Trop de requêtes sur l'API admin. Réessayez plus tard.");
                return;
            }
        }

        ThreatScanResult threat = threatDetection.scanRequest(path, query, userAgent, sensitive);
        if (threat != null) {
            String detailsJson = SecurityAlertDetailsBuilder.fromRequest(
                    request, path, query, userAgent, threat.category().name(), threat.detail());
            monitoringService.handleThreat(ip, request.getMethod(), path, threat, detailsJson);
            if (threat.blockImmediately() || blocklistService.isBlocked(ip)) {
                writeJson(response, HttpServletResponse.SC_FORBIDDEN, "Requête refusée.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void writeRateLimitResponse(HttpServletResponse response, RateLimitResult result, String message)
            throws IOException {
        response.setHeader("X-RateLimit-Limit", String.valueOf(result.limit()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, result.remainingTokens())));
        response.setHeader("Retry-After", String.valueOf(result.windowSeconds()));
        writeJson(response, HTTP_TOO_MANY_REQUESTS, message);
    }

    private boolean isLoginPath(String path) {
        return path != null && (path.endsWith("/auth/login") || path.equals("/auth/login"));
    }

    private boolean isAdminPath(String path) {
        return path != null && path.contains("/api/admin/");
    }

    private String stripContextPath(String uri, String contextPath) {
        if (uri == null) {
            return "/";
        }
        if (contextPath != null && !contextPath.isBlank() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
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
