package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Vérifie l'accès au dépôt d'un service à l'enregistrement :
 * <ul>
 *   <li>token renseigné : il est vérifié auprès de GitHub / GitLab (API) — un mot de passe ou un token
 *       révoqué faisait échouer le clone du pipeline bien plus tard, au déploiement ;</li>
 *   <li>token vide : le dépôt doit être public (lecture Git anonyme), sinon le clone échouera.</li>
 * </ul>
 * GitHub et GitLab non joignables (réseau, quota d'API) : on n'empêche pas l'enregistrement.
 */
@Service
@Slf4j
public class GitAccessVerifier {

    public enum Status {
        /** Token accepté et accès au dépôt confirmé. */
        VALID,
        /** Token refusé (invalide, révoqué, expiré). */
        INVALID,
        /** Token valide mais sans accès à ce dépôt (ou dépôt inexistant). */
        NO_ACCESS,
        /** Dépôt lisible sans token. */
        PUBLIC,
        /** Lecture anonyme refusée : dépôt privé ou introuvable. */
        PRIVATE_OR_MISSING,
        /** Vérification impossible (hôte inconnu, réseau, quota) : on laisse passer. */
        UNVERIFIED
    }

    private static final Duration TIMEOUT = Duration.ofSeconds(6);
    private static final Pattern GITHUB_HTTPS = Pattern.compile("^https?://(?:www\\.)?github\\.com/([^/\\s]+)/([^/\\s]+?)(?:\\.git)?/?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern GITHUB_SSH = Pattern.compile("^git@github\\.com:([^/\\s]+)/([^/\\s]+?)(?:\\.git)?$", Pattern.CASE_INSENSITIVE);

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Value("${gitlab.url:https://gitlab.com}")
    private String configuredGitlabUrl;

    // ── Dépôt identifié ───────────────────────────────────────────────────────────────────────

    /** « owner/repo » d'un dépôt GitHub, ou vide. */
    static Optional<String> githubPath(String repoUrl) {
        if (repoUrl == null) return Optional.empty();
        String u = repoUrl.trim();
        Matcher m = GITHUB_HTTPS.matcher(u);
        if (!m.matches()) m = GITHUB_SSH.matcher(u);
        return m.matches() ? Optional.of(m.group(1) + "/" + m.group(2)) : Optional.empty();
    }

    /** « group/sub/repo » d'un dépôt sur gitlab.com ou sur l'instance GitLab configurée, ou vide. */
    Optional<String> gitlabPath(String repoUrl) {
        if (repoUrl == null) return Optional.empty();
        try {
            URI uri = URI.create(repoUrl.trim());
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            String configured = configuredGitlabUrl == null ? "" : URI.create(configuredGitlabUrl.trim()).getHost();
            boolean gitlab = host.equals("gitlab.com") || (configured != null && host.equalsIgnoreCase(configured));
            if (!gitlab || uri.getPath() == null) return Optional.empty();
            String path = uri.getPath().replaceAll("^/+|/+$", "").replaceAll("\\.git$", "");
            return path.contains("/") ? Optional.of(path) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /** Hôte dont on connaît le comportement (GitHub / GitLab) : le résultat peut bloquer l'enregistrement. */
    public boolean isKnownHost(String repoUrl) {
        return githubPath(repoUrl).isPresent() || gitlabPath(repoUrl).isPresent();
    }

    // ── Vérifications ─────────────────────────────────────────────────────────────────────────

    /** Token renseigné : accepté par le fournisseur et autorisé sur ce dépôt ? */
    public Status verifyToken(String repoUrl, String token) {
        if (token == null || token.isBlank()) return Status.UNVERIFIED;
        try {
            Optional<String> gh = githubPath(repoUrl);
            if (gh.isPresent()) {
                HttpResponse<Void> r = send(HttpRequest.newBuilder(URI.create("https://api.github.com/repos/" + gh.get()))
                        .header("Authorization", "Bearer " + token.trim())
                        .header("Accept", "application/vnd.github+json")
                        .header("User-Agent", "EnviroTest"));
                return switch (r.statusCode()) {
                    case 200 -> Status.VALID;
                    case 401 -> Status.INVALID;
                    case 404 -> Status.NO_ACCESS;
                    case 403 -> r.headers().firstValue("x-ratelimit-remaining").filter("0"::equals).isPresent()
                            ? Status.UNVERIFIED : Status.NO_ACCESS;
                    default -> Status.UNVERIFIED;
                };
            }
            Optional<String> gl = gitlabPath(repoUrl);
            if (gl.isPresent()) {
                String host = URI.create(repoUrl.trim()).getHost();
                HttpResponse<Void> r = send(HttpRequest.newBuilder(URI.create("https://" + host + "/api/v4/projects/"
                                + URLEncoder.encode(gl.get(), StandardCharsets.UTF_8)))
                        .header("PRIVATE-TOKEN", token.trim())
                        .header("User-Agent", "EnviroTest"));
                return switch (r.statusCode()) {
                    case 200 -> Status.VALID;
                    case 401 -> Status.INVALID;
                    case 403, 404 -> Status.NO_ACCESS;
                    default -> Status.UNVERIFIED;
                };
            }
        } catch (Exception e) {
            log.debug("Vérification du token Git impossible ({}) : {}", repoUrl, e.getMessage());
        }
        return Status.UNVERIFIED;
    }

    /** Token vide : le dépôt se lit-il sans authentification (protocole Git HTTP, hors quota d'API) ? */
    public Status checkAnonymousAccess(String repoUrl) {
        if (repoUrl == null || !repoUrl.trim().toLowerCase(Locale.ROOT).startsWith("http")) {
            return Status.UNVERIFIED;
        }
        try {
            String base = repoUrl.trim().replaceAll("/+$", "");
            if (!base.endsWith(".git")) base = base + ".git";
            HttpResponse<Void> r = send(HttpRequest.newBuilder(URI.create(base + "/info/refs?service=git-upload-pack"))
                    .header("User-Agent", "git/2.43.0"));
            String type = r.headers().firstValue("content-type").orElse("");
            if (r.statusCode() == 200 && type.startsWith("application/x-git-upload-pack-advertisement")) {
                return Status.PUBLIC;
            }
            if (r.statusCode() == 401 || r.statusCode() == 403 || r.statusCode() == 404) {
                return Status.PRIVATE_OR_MISSING;
            }
        } catch (Exception e) {
            log.debug("Vérification de l'accès anonyme impossible ({}) : {}", repoUrl, e.getMessage());
        }
        return Status.UNVERIFIED;
    }

    private HttpResponse<Void> send(HttpRequest.Builder request) throws Exception {
        return http.send(request.timeout(TIMEOUT).GET().build(), HttpResponse.BodyHandlers.discarding());
    }
}
