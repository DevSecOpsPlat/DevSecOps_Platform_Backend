package com.backend.devsecopsplatform_backend.service.application;

import com.backend.devsecopsplatform_backend.controller.application.ApplicationResponse;
import com.backend.devsecopsplatform_backend.controller.application.CreateApplicationRequest;
import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.ApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.GitHubValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class ApplicationService {

    private final ApplicationRepository applicationRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final GitHubValidationService gitHubValidationService; // À créer

    /**
     * Crée une nouvelle application avec token GitHub chiffré
     */
    @Transactional
    public ApplicationResponse createApplication(CreateApplicationRequest request) {
        log.info("📦 Création nouvelle application: {}", request.getName());

        // 1. Récupérer l'utilisateur connecté
        User currentUser = getCurrentUser();

        // 2. Valider que le repository GitHub existe et est accessible avec le token
        boolean isValid = gitHubValidationService.validateRepository(
                request.getGitRepositoryUrl(),
                request.getGithubToken()
        );

        if (!isValid) {
            throw new RuntimeException("Repository GitHub invalide ou token incorrect");
        }

        // 3. Chiffrer le token GitHub avant de le stocker
        String encryptedToken = encryptionService.encrypt(request.getGithubToken());
        log.info("🔐 Token GitHub chiffré avec succès");

        // 4. Créer l'entité Application
        Application application = new Application();
        application.setName(request.getName());
        application.setDescription(request.getDescription());
        application.setGitRepositoryUrl(request.getGitRepositoryUrl());
        application.setDockerfilePath(request.getDockerfilePath());
        application.setEncryptedGithubToken(encryptedToken); // ✅ Stockage chiffré
        application.setCreatedBy(currentUser);

        // 5. Sauvegarder en BDD
        Application saved = applicationRepository.save(application);
        log.info("✅ Application créée avec ID: {}", saved.getId());

        // 6. Retourner la réponse (SANS le token)
        return mapToResponse(saved);
    }

    /**
     * Récupère le token GitHub déchiffré pour une application
     * ⚠️ À utiliser UNIQUEMENT dans le backend, jamais exposé au frontend
     */
    public String getDecryptedGithubToken(UUID applicationId) {
        Application app = applicationRepository.findById(applicationId)
                .orElseThrow(() -> new RuntimeException("Application non trouvée"));

        if (app.getEncryptedGithubToken() == null) {
            return null;
        }

        // Déchiffrer le token
        String decryptedToken = encryptionService.decrypt(app.getEncryptedGithubToken());
        log.debug("🔓 Token GitHub déchiffré pour application: {}", applicationId);

        return decryptedToken;
    }

    /**
     * Liste toutes les applications de l'utilisateur connecté
     */
    public List<ApplicationResponse> getMyApplications() {
        User currentUser = getCurrentUser();

        List<Application> apps = applicationRepository.findByCreatedBy(currentUser);

        return apps.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Pour le déploiement : trouve ou crée une application par URL de repo pour l'utilisateur.
     * Si un token est fourni, il est chiffré avant stockage.
     * Si dockerfilePath est fourni, il est enregistré sur l'application.
     *
     * @return Application entity (pour usage interne par EnvironmentService)
     */
    @Transactional
    public Application findOrCreateApplicationForDeploy(User user, String gitRepositoryUrl, String githubToken, String dockerfilePath) {
        Optional<Application> existing = applicationRepository.findByCreatedByAndGitRepositoryUrl(user, gitRepositoryUrl);
        if (existing.isPresent()) {
            Application app = existing.get();
            if (githubToken != null && !githubToken.isBlank()) {
                app.setEncryptedGithubToken(encryptionService.encrypt(githubToken));
                log.info("🔐 Token GitHub mis à jour (chiffré) pour application: {}", app.getId());
            }
            if (dockerfilePath != null && !dockerfilePath.isBlank()) {
                app.setDockerfilePath(dockerfilePath);
            }
            return applicationRepository.save(app);
        }
        String name = deriveAppNameFromUrl(gitRepositoryUrl);
        Application app = new Application();
        app.setName(name);
        app.setGitRepositoryUrl(gitRepositoryUrl);
        app.setDockerfilePath(dockerfilePath != null && !dockerfilePath.isBlank() ? dockerfilePath : "./Dockerfile");
        app.setCreatedBy(user);
        if (githubToken != null && !githubToken.isBlank()) {
            app.setEncryptedGithubToken(encryptionService.encrypt(githubToken));
            log.info("🔐 Token GitHub chiffré pour nouvelle application");
        }
        return applicationRepository.save(app);
    }

    private static String deriveAppNameFromUrl(String url) {
        if (url == null || url.isBlank()) return "app";
        String path = url.replace("https://github.com/", "").replace(".git", "").trim();
        int last = path.lastIndexOf('/');
        return last >= 0 ? path.substring(last + 1) : path;
    }

    /**
     * Récupère une application par ID
     */
    public ApplicationResponse getApplicationById(UUID id) {
        Application app = applicationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Application non trouvée"));

        return mapToResponse(app);
    }

    /**
     * Convertit une entité Application en DTO Response
     */
    private ApplicationResponse mapToResponse(Application app) {
        return ApplicationResponse.builder()
                .id(app.getId())
                .name(app.getName())
                .description(app.getDescription())
                .gitRepositoryUrl(app.getGitRepositoryUrl())
                .dockerfilePath(app.getDockerfilePath())
                .createdAt(app.getCreatedAt())
                .createdByUsername(app.getCreatedBy().getUsername())
                .hasGithubToken(app.getEncryptedGithubToken() != null) // ✅ Juste un boolean
                .build();
    }

    /**
     * Récupère l'utilisateur connecté depuis le contexte de sécurité
     */
    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }
}