package com.backend.devsecopsplatform_backend.service.remediation;

import com.backend.devsecopsplatform_backend.entity.application.AppService;
import com.backend.devsecopsplatform_backend.entity.environment.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.repository.application.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.environment.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.RepositoryFile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Récupère un extrait de fichier depuis le dépôt de l'application (GitHub ou GitLab même instance que {@code gitlab.url})
 * pour enrichir la remédiation IA sans coller le code à la main.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SourceSnippetFetcherService {

    public record CodeSnippetFetch(String content, String source) {}

    private static final int MAX_CHARS = 24_000;
    private static final int MAX_LINES_WHEN_NO_HINT = 160;

    private static final Pattern GITHUB_SSH = Pattern.compile("git@github\\.com:([^/]+)/([^/]+?)(?:\\.git)?\\s*$", Pattern.CASE_INSENSITIVE);

    private static final List<String> DOCKERFILE_CANDIDATE_PATHS = List.of(
            "Dockerfile",
            "docker/Dockerfile",
            "dockerfile",
            ".docker/Dockerfile",
            "Dockerfile.prod",
            "deploy/Dockerfile",
            "build/Dockerfile"
    );

    private final EphemeralEnvironmentRepository ephemeralEnvironmentRepository;
    private final AppServiceRepository appServiceRepository;
    private final ApplicationService applicationService;
    private final GitLabApi gitLabApi;
    private final ObjectMapper objectMapper;

    @Value("${gitlab.url:https://gitlab.com}")
    private String configuredGitlabUrl;

    /**
     * @return extrait avec numéros de ligne + source (GITHUB / GITLAB), ou empty si impossible
     */
    public Optional<CodeSnippetFetch> tryFetchSnippet(UUID environmentId, String filePath, Integer lineStart, Integer lineEnd) {
        Optional<EphemeralEnvironment> envOpt = ephemeralEnvironmentRepository.findByIdWithService(environmentId);
        if (envOpt.isEmpty()) {
            return Optional.empty();
        }
        EphemeralEnvironment env = envOpt.get();
        AppService app = env.getService();
        if (app == null) {
            return Optional.empty();
        }
        String branch = env.getGitBranch() != null ? env.getGitBranch().trim() : "main";
        return tryFetchSnippetForRepository(app, branch, filePath, lineStart, lineEnd);
    }

    public Optional<CodeSnippetFetch> tryFetchSnippetForApplication(
            UUID applicationId,
            String branch,
            String filePath,
            Integer lineStart,
            Integer lineEnd
    ) {
        return appServiceRepository.findById(applicationId)
                .flatMap(app -> tryFetchSnippetForRepository(app, branch, filePath, lineStart, lineEnd));
    }

    public Optional<CodeSnippetFetch> tryFetchDockerfileFallback(AppService app, String branch) {
        if (app == null) {
            return Optional.empty();
        }
        String ref = (branch != null && !branch.isBlank()) ? branch.trim() : "main";
        for (String candidate : DOCKERFILE_CANDIDATE_PATHS) {
            Optional<CodeSnippetFetch> hit = tryFetchSnippetForRepository(app, ref, candidate, null, null);
            if (hit.isPresent()) {
                String header = "# Dockerfile du dépôt : " + candidate + " (branche " + ref + ")\n"
                        + "# Finding conteneur — corriger l'image de base / les paquets OS ici.\n\n";
                return Optional.of(new CodeSnippetFetch(header + hit.get().content(), "DOCKERFILE"));
            }
        }
        return Optional.empty();
    }

    public Optional<CodeSnippetFetch> tryFetchSnippetForRepository(
            AppService app,
            String branch,
            String filePath,
            Integer lineStart,
            Integer lineEnd
    ) {
        if (app == null || filePath == null || filePath.isBlank()) {
            return Optional.empty();
        }
        String normalized = normalizeRepoRelativePath(filePath);
        if (normalized.isBlank()) {
            return Optional.empty();
        }
        String repoUrl = app.getGitRepositoryUrl();
        String ref = (branch != null && !branch.isBlank()) ? branch.trim() : "main";

        try {
            if (isGitHubUrl(repoUrl)) {
                Optional<String[]> gh = parseGithubOwnerRepo(repoUrl);
                if (gh.isEmpty()) {
                    log.debug("URL GitHub non reconnue: {}", repoUrl);
                    return Optional.empty();
                }
                String[] parts = gh.get();
                String token = safeToken(() -> applicationService.getDecryptedGithubToken(app.getId()));
                return fetchGithubFile(parts[0], parts[1], normalized, ref, lineStart, lineEnd, token)
                        .map(s -> new CodeSnippetFetch(s, "GITHUB"));
            }
            if (isSameGitLabHostAsConfig(repoUrl)) {
                Optional<String> projectPath = parseGitLabProjectPath(repoUrl);
                if (projectPath.isEmpty()) {
                    return Optional.empty();
                }
                return fetchGitLabFile(projectPath.get(), normalized, ref, lineStart, lineEnd)
                        .map(s -> new CodeSnippetFetch(s, "GITLAB"));
            }
            log.debug("Hôte dépôt non supporté pour fetch snippet: {}", repoUrl);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Fetch snippet échoué (app={}, branch={}, path={}): {}",
                    app.getId(), ref, normalized, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Contenu COMPLET d'un fichier du dépôt (sans numéros de ligne), pour les analyses qui doivent
     * savoir si une configuration est absente d'un fichier entier. Dépôt GitHub public : lecture via
     * raw.githubusercontent.com (hors quota de l'API GitHub, 60 appels/h sans jeton).
     */
    public Optional<String> tryFetchFullFile(AppService app, String branch, String filePath) {
        if (app == null || filePath == null || filePath.isBlank()) {
            return Optional.empty();
        }
        String normalized = normalizeRepoRelativePath(filePath);
        String repoUrl = app.getGitRepositoryUrl();
        String ref = (branch != null && !branch.isBlank()) ? branch.trim() : "main";
        try {
            if (isGitHubUrl(repoUrl)) {
                Optional<String[]> gh = parseGithubOwnerRepo(repoUrl);
                if (gh.isEmpty()) return Optional.empty();
                String token = safeToken(() -> applicationService.getDecryptedGithubToken(app.getId()));
                Optional<String> raw = fetchGithubRaw(gh.get()[0], gh.get()[1], normalized, ref);
                if (raw.isPresent() || token.isBlank()) {
                    return raw;
                }
                return fetchGithubFullViaApi(gh.get()[0], gh.get()[1], normalized, ref, token);
            }
            if (isSameGitLabHostAsConfig(repoUrl)) {
                Optional<String> projectPath = parseGitLabProjectPath(repoUrl);
                if (projectPath.isEmpty()) return Optional.empty();
                RepositoryFile rf = gitLabApi.getRepositoryFileApi().getFile(projectPath.get(), normalized, ref);
                if (rf == null) return Optional.empty();
                String full = rf.getDecodedContentAsString();
                return Optional.ofNullable(full);
            }
        } catch (Exception e) {
            log.debug("Lecture complète échouée (app={}, path={}): {}", app.getId(), normalized, e.getMessage());
        }
        return Optional.empty();
    }

    /** Numérote un contenu complet comme les autres extraits (« 12| code »). */
    public static String numberLines(String content, int maxLines) {
        String[] lines = content.split("\r\n|\n|\r", -1);
        int end = Math.min(lines.length, maxLines);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < end; i++) {
            sb.append(String.format("%5d| %s%n", i + 1, lines[i]));
        }
        if (lines.length > end) {
            sb.append("   ...| [").append(lines.length - end).append(" lignes non affichées]\n");
        }
        return sb.toString();
    }

    private Optional<String> fetchGithubRaw(String owner, String repo, String filePath, String ref) {
        String encodedPath = java.util.Arrays.stream(filePath.split("/"))
                .map(s -> java.net.URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"))
                .reduce((a, b) -> a + "/" + b)
                .orElse("");
        String url = "https://raw.githubusercontent.com/" + owner + "/" + repo + "/"
                + java.net.URLEncoder.encode(ref, StandardCharsets.UTF_8) + "/" + encodedPath;
        try {
            RestTemplate rest = com.backend.devsecopsplatform_backend.configuration.HttpTimeouts.restTemplate(5_000, 15_000);
            ResponseEntity<String> response = rest.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, String.class);
            String body = response.getBody();
            if (body == null || body.length() > 400_000) return Optional.empty();
            return Optional.of(body);
        } catch (HttpStatusCodeException e) {
            log.debug("raw.githubusercontent {} pour {}: {}", e.getStatusCode(), filePath, e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.debug("raw.githubusercontent erreur {}: {}", filePath, e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<String> fetchGithubFullViaApi(String owner, String repo, String filePath, String ref, String token) {
        String encodedPath = java.util.Arrays.stream(filePath.split("/"))
                .map(s -> java.net.URLEncoder.encode(s, StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "/" + b)
                .orElse("");
        String url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + encodedPath
                + "?ref=" + java.net.URLEncoder.encode(ref, StandardCharsets.UTF_8);
        try {
            RestTemplate rest = com.backend.devsecopsplatform_backend.configuration.HttpTimeouts.restTemplate(5_000, 15_000);
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.parseMediaType("application/vnd.github+json")));
            headers.setBearerAuth(token);
            ResponseEntity<String> response = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            if (response.getBody() == null) return Optional.empty();
            JsonNode root = objectMapper.readTree(response.getBody());
            String b64 = root.path("content").asText("").replaceAll("\\s", "");
            if (b64.isEmpty()) return Optional.empty();
            return Optional.of(new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.debug("GitHub API (fichier complet) {}: {}", filePath, e.getMessage());
            return Optional.empty();
        }
    }

    /** Chemin DefectDojo typique d'un artefact dans l'image (pas dans le dépôt Git). */
    public static boolean isContainerFilesystemPath(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            return false;
        }
        String p = filePath.trim().replace('\\', '/');
        if (!p.startsWith("/")) {
            return false;
        }
        return p.startsWith("/lib/")
                || p.startsWith("/usr/")
                || p.startsWith("/var/")
                || p.startsWith("/etc/")
                || p.contains("/apk/")
                || p.contains("dpkg");
    }

    private static String safeToken(java.util.concurrent.Callable<String> supplier) {
        try {
            String t = supplier.call();
            return t != null ? t : "";
        } catch (Exception e) {
            return "";
        }
    }

    static String normalizeRepoRelativePath(String filePath) {
        String p = filePath.trim().replace('\\', '/');
        while (p.startsWith("./")) {
            p = p.substring(2);
        }
        if (p.toLowerCase().startsWith("user-repo/")) {
            p = p.substring("user-repo/".length());
        }
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }

    private boolean isGitHubUrl(String url) {
        if (url == null) return false;
        String u = url.toLowerCase();
        return u.contains("github.com") || GITHUB_SSH.matcher(url.trim()).find();
    }

    private static Optional<String[]> parseGithubOwnerRepo(String url) {
        if (url == null) return Optional.empty();
        String u = url.trim();
        Matcher ssh = GITHUB_SSH.matcher(u);
        if (ssh.find()) {
            return Optional.of(new String[]{ssh.group(1), stripDotGit(ssh.group(2))});
        }
        try {
            URI uri = URI.create(u.replace(" ", "%20"));
            if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase("github.com")) {
                return Optional.empty();
            }
            String path = uri.getPath();
            if (path == null || path.length() < 3) return Optional.empty();
            String[] segments = path.split("/");
            if (segments.length < 3) return Optional.empty();
            String owner = segments[1];
            String repo = stripDotGit(segments[2]);
            if (owner.isBlank() || repo.isBlank()) return Optional.empty();
            return Optional.of(new String[]{owner, repo});
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static String stripDotGit(String name) {
        if (name != null && name.endsWith(".git")) {
            return name.substring(0, name.length() - 4);
        }
        return name;
    }

    private boolean isSameGitLabHostAsConfig(String repoUrl) {
        try {
            URI u = URI.create(repoUrl.trim().replace(" ", "%20"));
            URI cfg = URI.create(configuredGitlabUrl.trim());
            return u.getHost() != null && cfg.getHost() != null
                    && u.getHost().equalsIgnoreCase(cfg.getHost());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * https://gitlab.com/group/sub/repo.git → group/sub/repo
     */
    private static Optional<String> parseGitLabProjectPath(String repoUrl) {
        try {
            URI uri = URI.create(repoUrl.trim().replace(" ", "%20"));
            String path = uri.getPath();
            if (path == null || path.length() < 2) return Optional.empty();
            String p = path.startsWith("/") ? path.substring(1) : path;
            p = stripDotGit(p);
            if (p.isBlank()) return Optional.empty();
            return Optional.of(p);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<String> fetchGithubFile(String owner, String repo, String filePath, String ref,
                                             Integer lineStart, Integer lineEnd, String token) {
        if (token == null || token.isBlank()) {
            // Dépôt public sans jeton : raw.githubusercontent.com n'entame pas le quota de l'API (60 appels/h).
            Optional<String> raw = fetchGithubRaw(owner, repo, filePath, ref);
            if (raw.isPresent()) {
                return Optional.of(windowAroundLines(raw.get(), lineStart, lineEnd));
            }
        }
        String encodedPath = java.util.Arrays.stream(filePath.split("/"))
                .map(s -> java.net.URLEncoder.encode(s, StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "/" + b)
                .orElse("");
        String url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + encodedPath
                + "?ref=" + java.net.URLEncoder.encode(ref, StandardCharsets.UTF_8);

        RestTemplate rest = com.backend.devsecopsplatform_backend.configuration.HttpTimeouts.restTemplate(5_000, 15_000);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.parseMediaType("application/vnd.github+json")));
        if (token != null && !token.isBlank()) {
            headers.setBearerAuth(token);
        }
        try {
            ResponseEntity<String> response = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            if (response.getBody() == null) return Optional.empty();
            JsonNode root = objectMapper.readTree(response.getBody());
            if (!"file".equals(root.path("type").asText())) {
                log.debug("GitHub contents n'est pas un fichier unique (symlink/submodule?)");
                return Optional.empty();
            }
            String b64 = root.path("content").asText("").replaceAll("\\s", "");
            if (b64.isEmpty()) return Optional.empty();
            String full = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
            return Optional.of(windowAroundLines(full, lineStart, lineEnd));
        } catch (HttpStatusCodeException e) {
            log.debug("GitHub API {} pour {}: {}", e.getStatusCode(), filePath, e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.debug("GitHub fetch erreur {}: {}", filePath, e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<String> fetchGitLabFile(String projectPath, String filePath, String ref,
                                              Integer lineStart, Integer lineEnd) {
        try {
            RepositoryFile rf = gitLabApi.getRepositoryFileApi().getFile(projectPath, filePath, ref);
            if (rf == null) return Optional.empty();
            String full = rf.getDecodedContentAsString();
            if (full == null && rf.getContent() != null) {
                full = new String(Base64.getDecoder().decode(rf.getContent().replaceAll("\\s", "")), StandardCharsets.UTF_8);
            }
            if (full == null) return Optional.empty();
            return Optional.of(windowAroundLines(full, lineStart, lineEnd));
        } catch (GitLabApiException e) {
            log.debug("GitLab getFile {}: {}", filePath, e.getMessage());
            return Optional.empty();
        }
    }

    static String windowAroundLines(String full, Integer lineStart, Integer lineEnd) {
        if (lineStart != null && lineStart > 0) {
            int hi = (lineEnd != null && lineEnd > 0) ? lineEnd : lineStart;
            return CodeContextExtractor.extractSnippet(full, hi, MAX_CHARS);
        }
        String[] lines = full.split("\r\n|\n|\r", -1);
        int end = lines.length;
        if (lines.length > MAX_LINES_WHEN_NO_HINT) {
            end = MAX_LINES_WHEN_NO_HINT;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < end; i++) {
            sb.append(String.format("%5d| %s%n", i + 1, lines[i]));
        }
        String out = sb.toString();
        if (out.length() > MAX_CHARS) {
            return out.substring(0, MAX_CHARS) + "\n...[truncated]";
        }
        return out;
    }
}
