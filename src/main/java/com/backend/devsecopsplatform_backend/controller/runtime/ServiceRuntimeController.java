package com.backend.devsecopsplatform_backend.controller.runtime;

import com.backend.devsecopsplatform_backend.controller.appmgmt.AppDeploymentResponse;
import com.backend.devsecopsplatform_backend.controller.environment.DeployRequest;
import com.backend.devsecopsplatform_backend.controller.environment.DeployResponse;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppDeploymentService;
import com.backend.devsecopsplatform_backend.controller.appmgmt.ManagedDeployRequest;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import com.backend.devsecopsplatform_backend.service.appmgmt.ManagedDeployOptions;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Endpoints de "runtime" côté services (déclenchés depuis les cartes de service dans l'UI).
 *
 * <ul>
 *   <li>{@code POST /api/applications/{id}/scan} — déclenche un scan (pipeline GitLab existant)
 *   à partir des identifiants stockés sur le service (repo + token chiffré) — aucune ressaisie
 *   côté utilisateur.</li>
 *   <li>{@code POST /api/managed-applications/{appId}/services/{svcId}/deploy} — déploie un seul
 *   service (avec sa base dépendante, si déclarée) sur Kubernetes.</li>
 * </ul>
 *
 * <p>Aucune logique de scan ou de déploiement existante n'est modifiée : ces endpoints
 * réutilisent {@link EnvironmentService#deploy(DeployRequest)} et
 * {@link AppDeploymentService#deploySingleService(ManagedApplication, UUID)}.</p>
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class ServiceRuntimeController {

    private final AppServiceRepository appServiceRepository;
    private final ManagedApplicationRepository managedApplicationRepository;
    private final UserRepository userRepository;
    private final EnvironmentService environmentService;
    private final AppDeploymentService appDeploymentService;
    private final EncryptionService encryptionService;

    /**
     * Corps optionnel d'un scan : branche (défaut = branche du service, sinon "main").
     */
    @Data
    public static class ScanRunRequest {
        private String branch;
    }

    /**
     * Réponse "contexte de déploiement" pour un service — utilisée par l'UI pour savoir si
     * un bouton "Déployer ce service" doit être proposé (et vers quel projet).
     */
    @Data
    public static class ServiceDeployContextResponse {
        private UUID applicationId;
        private UUID managedApplicationId;
        private boolean canDeploySingle;
        private String serviceName;
    }

    /**
     * Réponse résumée d'un service "orphelin" (sans projet parent) — filet de migration pour
     * les apps legacy scannées avant l'introduction des projets.
     */
    @Data
    public static class OrphanServiceItem {
        private UUID id;
        private String name;
        private String description;
        private String gitRepositoryUrl;
    }

    /**
     * Liste les services qui n'appartiennent à aucun projet (managed_application_id IS NULL).
     * Utilisé par l'UI comme section "Services orphelins" (filet de migration ; en régime
     * nominal cette liste est vide car toute création de service passe par un projet).
     */
    @GetMapping("/api/applications/orphans")
    public ResponseEntity<java.util.List<OrphanServiceItem>> listOrphanServices() {
        User currentUser = getCurrentUser();
        java.util.List<AppService> orphans = appServiceRepository.findByCreatedBy(currentUser).stream()
                .filter(s -> s.getManagedApplication() == null)
                .toList();
        java.util.List<OrphanServiceItem> out = new java.util.ArrayList<>();
        for (AppService s : orphans) {
            OrphanServiceItem item = new OrphanServiceItem();
            item.setId(s.getId());
            item.setName(s.getName());
            item.setDescription(s.getDescription());
            item.setGitRepositoryUrl(s.getGitRepositoryUrl());
            out.add(item);
        }
        return ResponseEntity.ok(out);
    }

    /**
     * Retourne le projet parent (s'il y en a un) pour un service, permettant à l'UI de router
     * le bouton "Déployer" vers l'endpoint {@code deploySingleService}.
     */
    @GetMapping("/api/applications/{id}/deploy-context")
    public ResponseEntity<ServiceDeployContextResponse> getDeployContext(@PathVariable UUID id) {
        User currentUser = getCurrentUser();
        AppService svc = appServiceRepository.findByIdAndCreatedBy(id, currentUser)
                .orElseThrow(() -> new AppValidationException("Service introuvable ou accès refusé."));
        ServiceDeployContextResponse resp = new ServiceDeployContextResponse();
        resp.setApplicationId(svc.getId());
        resp.setServiceName(svc.getName());
        if (svc.getManagedApplication() != null) {
            resp.setManagedApplicationId(svc.getManagedApplication().getId());
            resp.setCanDeploySingle(true);
        } else {
            resp.setCanDeploySingle(false);
        }
        return ResponseEntity.ok(resp);
    }

    /**
     * Déclenche un scan pour un service dont l'ID est {@code applications.id}.
     * Le repo et le token sont lus sur l'entité — aucun formulaire, aucune saisie utilisateur.
     */
    @PostMapping("/api/applications/{id}/scan")
    public ResponseEntity<DeployResponse> scanService(
            @PathVariable UUID id,
            @RequestBody(required = false) ScanRunRequest body) {
        User currentUser = getCurrentUser();
        AppService svc = appServiceRepository.findByIdAndCreatedBy(id, currentUser)
                .orElseThrow(() -> new AppValidationException("Service introuvable ou accès refusé."));

        String repoUrl = svc.getGitRepositoryUrl();
        if (repoUrl == null || repoUrl.isBlank()) {
            throw new AppValidationException("Le service n'a pas d'URL Git — impossible de scanner.");
        }

        String token = resolveDecryptedToken(svc);
        String branch = body != null && body.getBranch() != null && !body.getBranch().isBlank()
                ? body.getBranch().trim()
                : (svc.getGitBranch() != null && !svc.getGitBranch().isBlank() ? svc.getGitBranch() : "main");

        DeployRequest req = new DeployRequest();
        req.setGitRepositoryUrl(repoUrl);
        req.setBranch(branch);
        req.setGithubToken(token);
        req.setDockerfilePath(svc.getDockerfilePath() != null ? svc.getDockerfilePath() : "./Dockerfile");

        log.info("🔎 Scan service {} (repo={}, branch={})", svc.getId(), repoUrl, branch);
        DeployResponse response = environmentService.scan(req, svc);
        return ResponseEntity.ok(response);
    }

    /**
     * Déploie un seul service (avec sa base dépendante, si déclarée).
     * Réutilise {@link AppDeploymentService#deploySingleService(ManagedApplication, UUID)}.
     */
    @PostMapping("/api/managed-applications/{appId}/services/{svcId}/deploy")
    public ResponseEntity<AppDeploymentResponse> deployServiceInProject(
            @PathVariable UUID appId,
            @PathVariable UUID svcId,
            @RequestBody(required = false) ManagedDeployRequest body) {
        User currentUser = getCurrentUser();
        ManagedApplication app = managedApplicationRepository.findByIdAndCreatedBy(appId, currentUser)
                .orElseThrow(() -> new AppValidationException("Projet introuvable ou accès refusé."));

        ManagedDeployOptions options = ManagedDeployOptions.from(body);
        AppDeployment deployment = appDeploymentService.deploySingleService(app, svcId, options);
        log.info("🚀 Déploiement service {} — branche={}, ttlHours={}",
                svcId, options.resolveBranch(null), options.ttlHours());
        return ResponseEntity.ok(mapDeployment(deployment));
    }

    // ---------------------------------------------------------------------

    private String resolveDecryptedToken(AppService svc) {
        // git_token (nouveau, chiffré via AppCryptoConverter) est déjà déchiffré par JPA à la lecture.
        if (svc.getGitToken() != null && !svc.getGitToken().isBlank()) {
            return svc.getGitToken();
        }
        // Fallback legacy : encryptedGithubToken (chiffrement via EncryptionService).
        if (svc.getEncryptedGithubToken() != null && !svc.getEncryptedGithubToken().isBlank()) {
            try {
                return encryptionService.decrypt(svc.getEncryptedGithubToken());
            } catch (Exception e) {
                log.warn("Impossible de déchiffrer encryptedGithubToken du service {}: {}", svc.getId(), e.getMessage());
                return null;
            }
        }
        return null;
    }

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new AppValidationException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new AppValidationException("Utilisateur non trouvé."));
    }

    private AppDeploymentResponse mapDeployment(AppDeployment d) {
        return AppDeploymentResponse.builder()
                .id(d.getId())
                .namespace(d.getNamespace())
                .status(d.getStatus())
                .gitlabPipelineId(d.getGitlabPipelineId())
                .deployedAt(d.getDeployedAt())
                .servicesState(d.getServicesState())
                .createdAt(d.getCreatedAt())
                .updatedAt(d.getUpdatedAt())
                .build();
    }
}
