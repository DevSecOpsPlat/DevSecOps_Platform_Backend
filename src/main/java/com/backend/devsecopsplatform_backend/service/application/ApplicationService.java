package com.backend.devsecopsplatform_backend.service.application;

import com.backend.devsecopsplatform_backend.controller.application.ApplicationResponse;
import com.backend.devsecopsplatform_backend.controller.application.CreateApplicationRequest;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
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

    private final AppServiceRepository applicationRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final GitHubValidationService gitHubValidationService;

    @Transactional
    public ApplicationResponse createApplication(CreateApplicationRequest request) {
        log.info("📦 Création nouvelle application: {}", request.getName());

        User currentUser = getCurrentUser();

        boolean isValid = gitHubValidationService.validateRepository(
                request.getGitRepositoryUrl(),
                request.getGithubToken()
        );

        if (!isValid) {
            throw new RuntimeException("Repository GitHub invalide ou token incorrect");
        }

        String encryptedToken = encryptionService.encrypt(request.getGithubToken());
        log.info("🔐 Token GitHub chiffré avec succès");

        AppService application = new AppService();
        application.setName(request.getName());
        application.setDescription(request.getDescription());
        application.setGitRepositoryUrl(request.getGitRepositoryUrl());
        application.setDockerfilePath(request.getDockerfilePath());
        application.setEncryptedGithubToken(encryptedToken);
        application.setCreatedBy(currentUser);

        AppService saved = applicationRepository.save(application);
        log.info("✅ Application créée avec ID: {}", saved.getId());

        return mapToResponse(saved);
    }

    public String getDecryptedGithubToken(UUID applicationId) {
        AppService app = applicationRepository.findById(applicationId)
                .orElseThrow(() -> new RuntimeException("Application non trouvée"));

        if (app.getEncryptedGithubToken() == null) {
            return null;
        }

        String decryptedToken = encryptionService.decrypt(app.getEncryptedGithubToken());
        log.debug("🔓 Token GitHub déchiffré pour application: {}", applicationId);

        return decryptedToken;
    }

    public List<ApplicationResponse> getMyApplications() {
        User currentUser = getCurrentUser();

        List<AppService> apps = applicationRepository.findByCreatedBy(currentUser);

        return apps.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public AppService findOrCreateApplicationForDeploy(User user, String gitRepositoryUrl, String githubToken, String dockerfilePath) {
        Optional<AppService> existing = applicationRepository.findByCreatedByAndGitRepositoryUrl(user, gitRepositoryUrl);
        if (existing.isPresent()) {
            AppService app = existing.get();
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
        AppService app = new AppService();
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

    public ApplicationResponse getApplicationById(UUID id) {
        AppService app = applicationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Application non trouvée"));

        return mapToResponse(app);
    }

    private ApplicationResponse mapToResponse(AppService app) {
        return ApplicationResponse.builder()
                .id(app.getId())
                .name(app.getName())
                .description(app.getDescription())
                .gitRepositoryUrl(app.getGitRepositoryUrl())
                .dockerfilePath(app.getDockerfilePath())
                .createdAt(app.getCreatedAt())
                .createdByUsername(app.getCreatedBy().getUsername())
                .hasGithubToken(app.getEncryptedGithubToken() != null)
                .build();
    }

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }
}
