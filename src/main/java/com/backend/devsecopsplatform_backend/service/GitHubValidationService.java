package com.backend.devsecopsplatform_backend.service;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Service pour valider qu'un repository GitHub existe et est accessible
 */
@Service
@Slf4j
public class GitHubValidationService {

    private final WebClient webClient;

    public GitHubValidationService() {
        this.webClient = WebClient.builder()
                .baseUrl("https://api.github.com")
                .build();
    }

    /**
     * Valide qu'un repository GitHub existe et que le token fonctionne.
     * GitHub accepte "Bearer &lt;token&gt;" (fine-grained PAT) ou "token &lt;token&gt;" (classic PAT).
     *
     * @param repoUrl URL du repository (ex: https://github.com/user/repo ou https://github.com/user/repo.git)
     * @param token   Token GitHub (ghp_xxx ou github_pat_xxx)
     * @return true si le repo est accessible, false sinon
     */
    public boolean validateRepository(String repoUrl, String token) {
        try {
            String normalizedUrl = repoUrl == null ? "" : repoUrl.trim();
            if (normalizedUrl.endsWith("/")) {
                normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length() - 1);
            }
            // Extraire owner/repo : https://github.com/owner/repo ou .../owner/repo.git
            String path = normalizedUrl.replace("https://github.com/", "").replace("http://github.com/", "");
            String[] parts = path.split("/");
            if (parts.length < 2) {
                log.error("❌ URL GitHub invalide: {}", repoUrl);
                return false;
            }

            String owner = parts[0].trim();
            String repo = parts[1].trim().replace(".git", "");
            if (owner.isEmpty() || repo.isEmpty()) {
                log.error("❌ URL GitHub invalide (owner/repo vides): {}", repoUrl);
                return false;
            }

            log.info("🔍 Validation repository GitHub: {}/{}", owner, repo);

            String apiUrl = String.format("/repos/%s/%s", owner, repo);
            String authHeader = buildGitHubAuthHeader(token);

            HttpStatusCode status = webClient.get()
                    .uri(apiUrl)
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .exchangeToMono(response -> Mono.just(response.statusCode()))
                    .block();

            if (status != null && status.is2xxSuccessful()) {
                log.info("✅ Repository GitHub valide et accessible");
                return true;
            }
            // Si 404 avec Bearer, réessayer avec "token " (classic PAT)
            if (status != null && status.value() == 404 && authHeader.startsWith("Bearer ")) {
                String classicAuth = "token " + token.trim();
                status = webClient.get()
                        .uri(apiUrl)
                        .header(HttpHeaders.AUTHORIZATION, classicAuth)
                        .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                        .exchangeToMono(response -> Mono.just(response.statusCode()))
                        .block();
                if (status != null && status.is2xxSuccessful()) {
                    log.info("✅ Repository GitHub valide (token classique)");
                    return true;
                }
            }
            log.warn("⚠️ Repository GitHub non accessible (statut: {}). Vérifiez que le dépôt existe et que le token a les droits 'repo' (classic) ou 'Contents: Read' (fine-grained).", status);
            return false;

        } catch (Exception e) {
            log.error("❌ Erreur lors de la validation GitHub: {}", e.getMessage());
            return false;
        }
    }

    /** GitHub accepte "Bearer <token>" (fine-grained) ou "token <token>" (classic). */
    private String buildGitHubAuthHeader(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        String t = token.trim();
        if (t.startsWith("ghp_") || t.startsWith("gho_")) {
            return "Bearer " + t;
        }
        return "Bearer " + t;
    }

    /**
     * Récupère les branches d'un repository (pour le dropdown du frontend)
     */
    public Mono<String[]> getRepositoryBranches(String repoUrl, String token) {
        try {
            String path = (repoUrl == null ? "" : repoUrl.trim()).replace("https://github.com/", "").replace("http://github.com/", "");
            String[] parts = path.split("/");
            if (parts.length < 2) return Mono.empty();
            String owner = parts[0].trim();
            String repo = parts[1].trim().replace(".git", "");
            String apiUrl = String.format("/repos/%s/%s/branches", owner, repo);
            String authHeader = buildGitHubAuthHeader(token);
            return webClient.get()
                    .uri(apiUrl)
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .retrieve()
                    .bodyToMono(String[].class);
        } catch (Exception e) {
            log.error("❌ Erreur récupération branches: {}", e.getMessage());
            return Mono.empty();
        }
    }
}