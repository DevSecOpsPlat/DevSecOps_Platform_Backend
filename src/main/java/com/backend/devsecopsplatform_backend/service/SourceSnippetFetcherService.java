package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
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

    private static final int CONTEXT_LINES = 55;
    private static final int MAX_CHARS = 48_000;
    private static final int MAX_LINES_WHEN_NO_HINT = 220;

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
        String encodedPath = java.util.Arrays.stream(filePath.split("/"))
                .map(s -> java.net.URLEncoder.encode(s, StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "/" + b)
                .orElse("");
        String url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + encodedPath
                + "?ref=" + java.net.URLEncoder.encode(ref, StandardCharsets.UTF_8);

        RestTemplate rest = new RestTemplate();
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
        String[] lines = full.split("\r\n|\n|\r", -1);
        int start = 0;
        int end = lines.length;
        if (lineStart != null && lineStart > 0) {
            int idx0 = lineStart - 1;
            start = Math.max(0, idx0 - CONTEXT_LINES);
            int hi = (lineEnd != null && lineEnd > 0) ? lineEnd : lineStart;
            end = Math.min(lines.length, hi + CONTEXT_LINES);
        } else {
            if (lines.length > MAX_LINES_WHEN_NO_HINT) {
                end = MAX_LINES_WHEN_NO_HINT;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < end; i++) {
            sb.append(String.format("%5d| %s%n", i + 1, lines[i]));
        }
        String out = sb.toString();
        if (out.length() > MAX_CHARS) {
            return out.substring(0, MAX_CHARS) + "\n...[truncated]";
        }
        return out;
    }
}
