package com.backend.devsecopsplatform_backend.service.security.monitoring;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class ThreatDetectionService {

    private static final List<String> HONEYPOT_PATHS = List.of(
            "/admin/secret",
            "/.env",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/actuator/env",
            "/.git/config",
            "/cgi-bin/",
            "/etc/passwd"
    );

    private static final List<String> SUSPICIOUS_PATH_FRAGMENTS = List.of(
            ".env",
            ".git",
            "wp-admin",
            "wp-login",
            "phpmyadmin",
            "web.config",
            "shell.php",
            "cmd.exe",
            "../",
            "..\\",
            "%2e%2e",
            "/actuator/",
            "/server-status",
            "/.aws/",
            "/config.json"
    );

    private static final List<Pattern> SQL_PATTERNS = List.of(
            Pattern.compile("('|\")\\s*or\\s+['\"]?\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bor\\s+1\\s*=\\s*1", Pattern.CASE_INSENSITIVE),
            Pattern.compile("--\\s*$", Pattern.CASE_INSENSITIVE),
            Pattern.compile(";\\s*drop\\s+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("union\\s+select", Pattern.CASE_INSENSITIVE),
            Pattern.compile("sleep\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("benchmark\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("information_schema", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> XSS_PATTERNS = List.of(
            Pattern.compile("<\\s*script", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript\\s*:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on(error|load|click|mouse)\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\s*iframe", Pattern.CASE_INSENSITIVE),
            Pattern.compile("document\\s*\\.\\s*cookie", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> SCANNER_USER_AGENTS = List.of(
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "dirbuster",
            "gobuster",
            "hydra",
            "metasploit",
            "wpscan",
            "acunetix",
            "nessus",
            "burpsuite",
            "zaproxy",
            "python-requests/",
            "libwww-perl"
    );

    public ThreatScanResult scanRequest(String uri, String queryString, String userAgent, boolean sensitiveEndpoint) {
        String path = uri != null ? uri.toLowerCase(Locale.ROOT) : "";
        String full = path + "?" + (queryString != null ? queryString : "");

        for (String honeypot : HONEYPOT_PATHS) {
            if (path.contains(honeypot.toLowerCase(Locale.ROOT))) {
                return new ThreatScanResult(
                        ThreatCategory.HONEYPOT,
                        "Accès honeypot : " + honeypot,
                        true
                );
            }
        }

        for (String fragment : SUSPICIOUS_PATH_FRAGMENTS) {
            if (full.contains(fragment.toLowerCase(Locale.ROOT))) {
                return new ThreatScanResult(
                        ThreatCategory.SUSPICIOUS_URL,
                        "Chemin suspect détecté : " + fragment,
                        true
                );
            }
        }

        for (Pattern pattern : SQL_PATTERNS) {
            if (pattern.matcher(full).find()) {
                return new ThreatScanResult(
                        ThreatCategory.SQL_INJECTION,
                        "Motif SQL suspect : " + pattern.pattern(),
                        true
                );
            }
        }

        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(full).find()) {
                return new ThreatScanResult(
                        ThreatCategory.XSS,
                        "Motif XSS suspect détecté",
                        true
                );
            }
        }

        if (sensitiveEndpoint) {
            ThreatScanResult uaResult = scanUserAgent(userAgent);
            if (uaResult != null) {
                return uaResult;
            }
        }

        return null;
    }

    public ThreatScanResult scanUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return new ThreatScanResult(
                    ThreatCategory.SUSPICIOUS_USER_AGENT,
                    "User-Agent absent (script automatisé probable)",
                    false
            );
        }
        String ua = userAgent.toLowerCase(Locale.ROOT);
        for (String scanner : SCANNER_USER_AGENTS) {
            if (ua.contains(scanner)) {
                return new ThreatScanResult(
                        ThreatCategory.SUSPICIOUS_USER_AGENT,
                        "User-Agent d'outil d'attaque : " + scanner,
                        true
                );
            }
        }
        return null;
    }
}
