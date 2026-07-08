package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.environment.CiDeployRequest;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineExecutionKind;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppDatabaseRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Orchestration du déploiement d'une application managée (rôle "DeploymentPipelineService"
 * du cadrage §3).
 *
 * <p>Enchaîne : validation (§3.2) → génération des URLs BD (§3.1) → génération des
 * manifestes K8s (bundles bases + services) → calcul de l'ordre en vagues (§3.3) →
 * déclenchement du pipeline de déploiement GitLab. Le pipeline appelle ensuite le callback
 * de statut ({@link #applyStatusCallback}). Le teardown supprime le namespace via le
 * pipeline.</p>
 *
 * <p>Réutilise le mécanisme de déclenchement existant (variables CI, cf.
 * {@code GitLabService.triggerPipeline}) via {@link AppDeploymentGitLabService} — sans
 * modifier {@code GitLabService} (règle de non-régression).</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AppDeploymentService {

    private final AppDeploymentRepository deploymentRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final AppDatabaseRepository databaseRepository;
    private final AppDeploymentValidationService validationService;
    private final AppConnectionUrlService connectionUrlService;
    private final AppK8sManifestService manifestService;
    private final AppDeploymentGitLabService gitLabService;
    private final EncryptionService encryptionService;
    private final ObjectMapper objectMapper;
    private final K8sManifestApplyService k8sManifestApplyService;

    @Value("${deployment.registry.server:registry.gitlab.com}")
    private String registryServer;

    @Value("${deployment.registry.username:gitlab-ci-token}")
    private String registryUsername;

    @Value("${deployment.registry.password:${gitlab.token:}}")
    private String registryPassword;

    @Value("${deployment.registry.pull-secret-name:gitlab-registry}")
    private String pullSecretName;

    @Value("${deployment.ingress.enabled:true}")
    private boolean ingressEnabled;

    @Value("${deployment.ingress.domain:local}")
    private String ingressDomain;

    /** Secret partagé validé par le callback (même valeur que le job GitLab). */
    @Value("${pipeline.secret:}")
    private String pipelineSecret;

    /** URL du backend joignable depuis le cluster (pour l'appel du callback par le pipeline). */
    @Value("${deployment.callback.base-url:}")
    private String callbackBaseUrl;

    @Value("${deployment.preview.nip.enabled:false}")
    private boolean nipPreviewEnabled;

    @Value("${deployment.preview.nip.scheme:https}")
    private String nipScheme;

    @Value("${deployment.preview.nip.master-ip:}")
    private String nipMasterIp;

    @Value("${deployment.preview.nip.node-port:30374}")
    private int nipNodePort;

    // =====================================================================
    // Déclenchement
    // =====================================================================

    /**
     * Lance un déploiement de l'application : valide, génère les artefacts et déclenche
     * le pipeline GitLab. Renvoie le déploiement persisté (status DEPLOYING).
     */
    @Transactional
    public AppDeployment deploy(ManagedApplication app) {
        return deploy(app, ManagedDeployOptions.defaults(null));
    }

    @Transactional
    public AppDeployment deploy(ManagedApplication app, ManagedDeployOptions options) {
        ManagedDeployOptions resolved = options != null ? options : ManagedDeployOptions.defaults(null);
        List<String> warnings = validationService.validate(app);
        warnings.forEach(w -> log.info("⚠️ [deploy {}] {}", app.getId(), w));

        AppDeployment deployment = new AppDeployment();
        deployment.setApplication(app);
        deployment.setStatus(AppDeploymentStatus.PENDING);
        deployment.setNamespace("pending");
        deployment = deploymentRepository.save(deployment); // obtient l'id → namespace stable

        String namespace = AppNaming.namespace(app.getSlug(), deployment.getId());
        deployment.setNamespace(namespace);

        // §3.1 : générer et stocker les URLs de connexion des bases.
        for (AppDatabase db : app.getDatabases()) {
            db.setGeneratedConnectionUrl(connectionUrlService.buildConnectionUrl(db, namespace));
            databaseRepository.save(db);
        }

        String imageTag = AppNaming.shortId(deployment.getId());
        AppK8sManifestService.ManifestOptions opts = AppK8sManifestService.ManifestOptions.builder()
                .registryServer(registryServer)
                .registryUsername(registryUsername)
                .registryPassword(registryPassword)
                .pullSecretName(pullSecretName)
                .ingressEnabled(ingressEnabled)
                .ingressDomain(ingressDomain)
                .imageTag(imageTag)
                .build();

        // Deux ensembles : bases (appliquées + Ready en premier) puis services.
        String databasesB64 = b64(manifestService.generateDatabaseBundle(app, namespace, opts));
        String servicesB64 = b64(manifestService.generateServiceBundle(app, namespace, opts));

        Map<Integer, List<AppService>> waves = computeWaves(app);
        String servicesJson = buildServicesJson(app, waves, imageTag);

        deployment.setServicesState(buildInitialState(app, namespace, waves));

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        variables.put("APP_ID", app.getId().toString());
        variables.put("APP_SLUG", app.getSlug());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        AppService gitService = app.getServices().stream().findFirst()
                .orElseThrow(() -> new AppValidationException("Aucun service dans le projet."));
        String deployBranch = resolved.resolveBranch(gitService.getGitBranch());
        addGitPipelineVariables(variables, gitService, deployBranch);
        variables.put("APPLICATION_ID", gitService.getId().toString());
        variables.put("NAMESPACE", namespace);
        putBackendUrlIfConfigured(variables);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        variables.put("IMAGE_TAG", imageTag);
        variables.put("PULL_SECRET_NAME", pullSecretName);
        variables.put("K8S_DATABASES_B64", databasesB64);
        variables.put("K8S_SERVICES_B64", servicesB64);
        variables.put("SERVICES_JSON", servicesJson);
        variables.put("TTL_HOURS", String.valueOf(resolved.ttlHours()));

        EphemeralEnvironment env = createEphemeralEnvironmentForDeploy(
                gitService, app.getCreatedBy(), deployBranch, namespace, resolved.ttlHours());
        variables.put("ENVIRONMENT_ID", env.getId().toString());

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        deployment.setStatus(pipelineId != null ? AppDeploymentStatus.DEPLOYING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());
        linkDeployPipelineExecution(gitService, env, pipelineId, deployBranch);

        return deploymentRepository.save(deployment);
    }

    /**
     * Déploiement ciblé d'un seul service (avec sa base de données dépendante, si déclarée).
     * Le déploiement est rattaché au vrai projet pour la FK ; les manifests / vagues / état
     * initial sont générés à partir d'une vue filtrée (shadow) en mémoire, sans muter la
     * collection JPA {@link ManagedApplication#getServices()}.
     */
    @Transactional
    public AppDeployment deploySingleService(ManagedApplication realApp, UUID targetServiceId) {
        return deploySingleService(realApp, targetServiceId, ManagedDeployOptions.defaults(null));
    }

    @Transactional
    public AppDeployment deploySingleService(
            ManagedApplication realApp,
            UUID targetServiceId,
            ManagedDeployOptions options
    ) {
        ManagedDeployOptions resolved = options != null ? options : ManagedDeployOptions.defaults(null);
        AppService target = realApp.getServices().stream()
                .filter(s -> targetServiceId.equals(s.getId()))
                .findFirst()
                .orElseThrow(() -> new AppValidationException("Service introuvable dans ce projet."));

        List<AppDatabase> depDbs = new ArrayList<>();
        if (target.getDependsOnDatabaseId() != null) {
            realApp.getDatabases().stream()
                    .filter(d -> target.getDependsOnDatabaseId().equals(d.getId()))
                    .findFirst()
                    .ifPresent(depDbs::add);
        }

        // Vue en mémoire (n'est jamais save() → aucun cascade JPA).
        ManagedApplication shadow = new ManagedApplication();
        shadow.setId(realApp.getId());
        shadow.setName(realApp.getName());
        shadow.setSlug(realApp.getSlug());
        shadow.setDescription(realApp.getDescription());
        shadow.setCreatedBy(realApp.getCreatedBy());
        shadow.setServices(List.of(target));
        shadow.setDatabases(depDbs);

        List<String> warnings = validationService.validate(shadow);
        warnings.forEach(w -> log.info("⚠️ [deploy-svc {}] {}", target.getId(), w));

        AppDeployment deployment = new AppDeployment();
        deployment.setApplication(realApp);
        deployment.setStatus(AppDeploymentStatus.PENDING);
        deployment.setNamespace("pending");
        deployment = deploymentRepository.save(deployment);

        String namespace = AppNaming.namespace(realApp.getSlug() + "-" + AppNaming.k8sName(target.getName()),
                deployment.getId());
        deployment.setNamespace(namespace);

        for (AppDatabase db : depDbs) {
            db.setGeneratedConnectionUrl(connectionUrlService.buildConnectionUrl(db, namespace));
            databaseRepository.save(db);
        }

        String imageTag = AppNaming.shortId(deployment.getId());
        AppK8sManifestService.ManifestOptions opts = AppK8sManifestService.ManifestOptions.builder()
                .registryServer(registryServer)
                .registryUsername(registryUsername)
                .registryPassword(registryPassword)
                .pullSecretName(pullSecretName)
                .ingressEnabled(ingressEnabled)
                .ingressDomain(ingressDomain)
                .imageTag(imageTag)
                .build();

        String databasesB64 = b64(manifestService.generateDatabaseBundle(shadow, namespace, opts));
        String servicesB64 = b64(manifestService.generateServiceBundle(shadow, namespace, opts));

        Map<Integer, List<AppService>> waves = computeWaves(shadow);
        String servicesJson = buildServicesJson(shadow, waves, imageTag);

        deployment.setServicesState(buildInitialState(shadow, namespace, waves));

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        variables.put("APP_ID", realApp.getId().toString());
        variables.put("APP_SLUG", realApp.getSlug());
        variables.put("SERVICE_ID", target.getId().toString());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        String deployBranch = resolved.resolveBranch(target.getGitBranch());
        addGitPipelineVariables(variables, target, deployBranch);
        variables.put("APPLICATION_ID", target.getId().toString());
        variables.put("NAMESPACE", namespace);
        putBackendUrlIfConfigured(variables);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        variables.put("IMAGE_TAG", imageTag);
        variables.put("PULL_SECRET_NAME", pullSecretName);
        variables.put("K8S_DATABASES_B64", databasesB64);
        variables.put("K8S_SERVICES_B64", servicesB64);
        variables.put("SERVICES_JSON", servicesJson);
        variables.put("TTL_HOURS", String.valueOf(resolved.ttlHours()));

        EphemeralEnvironment env = createEphemeralEnvironmentForDeploy(
                target, realApp.getCreatedBy(), deployBranch, namespace, resolved.ttlHours());
        variables.put("ENVIRONMENT_ID", env.getId().toString());

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        deployment.setStatus(pipelineId != null ? AppDeploymentStatus.DEPLOYING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());
        linkDeployPipelineExecution(target, env, pipelineId, deployBranch);

        return deploymentRepository.save(deployment);
    }

    /**
     * Teardown : supprime le namespace K8s via le pipeline (le runner exécute
     * {@code kubectl delete namespace}) et passe le déploiement à STOPPED.
     */
    @Transactional
    public AppDeployment teardown(AppDeployment deployment) {
        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "teardown");
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        variables.put("NAMESPACE", deployment.getNamespace());
        putBackendUrlIfConfigured(variables);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        gitLabService.triggerPipeline(variables);

        deployment.setStatus(AppDeploymentStatus.STOPPED);
        return deploymentRepository.save(deployment);
    }

    // =====================================================================
    // Callback de statut (appelé par le pipeline, secret partagé)
    // =====================================================================

    /**
     * Met à jour un déploiement d'après le callback du pipeline.
     *
     * @param deploymentId id du déploiement
     * @param status       « RUNNING » / « SUCCESS » → RUNNING, sinon FAILED
     * @param namespace    namespace confirmé (optionnel)
     * @param readyServices noms des services signalés Ready par le pipeline (optionnel : si
     *                      absent et status=succès, tous les services sont marqués Ready)
     */
    @Transactional
    public AppDeployment applyStatusCallback(UUID deploymentId, String status, String namespace,
                                             Set<String> readyServices) {
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));

        boolean success = status != null
                && (status.equalsIgnoreCase("RUNNING") || status.equalsIgnoreCase("SUCCESS")
                    || status.equalsIgnoreCase("OK") || status.equalsIgnoreCase("SUCCEEDED"));

        deployment.setStatus(success ? AppDeploymentStatus.RUNNING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());
        if (namespace != null && !namespace.isBlank()) {
            deployment.setNamespace(namespace);
        }

        updateServicesState(deployment, success, readyServices);
        return deploymentRepository.save(deployment);
    }

    /**
     * Appelé par le job CI {@code deploy:trigger-backend} (header {@code X-Pipeline-Secret}, pas de JWT).
     */
    @Transactional
    public Map<String, Object> applyFromCiPipeline(CiDeployRequest request) {
        if (request.getImage() == null || request.getImage().isBlank()) {
            throw new AppValidationException("image requis");
        }
        if (request.getNamespace() == null || request.getNamespace().isBlank()) {
            throw new AppValidationException("namespace requis");
        }
        UUID deploymentId = parseUuid(request.getDeploymentId());
        if (deploymentId == null) {
            deploymentId = parseUuid(request.getEnvironmentId());
        }
        if (deploymentId == null) {
            throw new AppValidationException("deploymentId ou environmentId requis");
        }
        final UUID resolvedDeploymentId = deploymentId;

        AppDeployment deployment = deploymentRepository.findById(resolvedDeploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable: " + resolvedDeploymentId));

        ManagedApplication realApp = deployment.getApplication();
        if (realApp == null) {
            throw new AppValidationException("Application managée introuvable pour le déploiement");
        }

        String namespace = request.getNamespace().trim();
        deployment.setNamespace(namespace);

        ManagedApplication shadow = buildShadowForDeployment(deployment, realApp);
        String imageTag = AppNaming.shortId(deployment.getId());
        AppK8sManifestService.ManifestOptions opts = AppK8sManifestService.ManifestOptions.builder()
                .registryServer(registryServer)
                .registryUsername(registryUsername)
                .registryPassword(registryPassword)
                .pullSecretName(pullSecretName)
                .ingressEnabled(ingressEnabled)
                .ingressDomain(ingressDomain)
                .imageTag(imageTag)
                .resolvedServiceImage(request.getImage().trim())
                .build();

        try {
            String databasesYaml = manifestService.generateDatabaseBundle(shadow, namespace, opts);
            String servicesYaml = manifestService.generateServiceBundle(shadow, namespace, opts);
            String allYaml = databasesYaml + "\n---\n" + servicesYaml;
            k8sManifestApplyService.applyManifests(allYaml);
        } catch (Exception e) {
            deployment.setStatus(AppDeploymentStatus.FAILED);
            deploymentRepository.save(deployment);
            throw new AppValidationException("Échec apply Kubernetes: " + e.getMessage());
        }

        deployment.setStatus(AppDeploymentStatus.RUNNING);
        deployment.setDeployedAt(Instant.now());
        markServicesDeploying(deployment);
        deploymentRepository.save(deployment);

        UUID environmentId = parseUuid(request.getEnvironmentId());
        if (environmentId != null) {
            environmentRepository.findById(environmentId).ifPresent(env -> {
                env.setNamespace(namespace);
                env.setStatus(EnvironmentStatus.RUNNING);
                String appUrl = resolvePublicUrl(deployment, shadow);
                if (appUrl != null) {
                    env.setUrl(appUrl);
                }
                environmentRepository.save(env);
            });
        }

        log.info("CI deploy appliqué — deployment={} namespace={} image={}",
                deploymentId, namespace, request.getImage());
        return Map.of(
                "status", "accepted",
                "deploymentId", deploymentId.toString(),
                "namespace", namespace
        );
    }

    @Transactional
    public Map<String, Object> getCiDeployStatus(UUID deploymentId) {
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable"));

        ManagedApplication realApp = deployment.getApplication();
        ManagedApplication shadow = buildShadowForDeployment(deployment, realApp);
        boolean ready = false;
        if (!shadow.getServices().isEmpty()) {
            AppService svc = shadow.getServices().get(0);
            String k8sName = AppNaming.k8sName(svc.getName());
            ready = k8sManifestApplyService.isDeploymentReady(deployment.getNamespace(), k8sName);
        }
        if (ready) {
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            markServicesReady(deployment);
        }

        String appUrl = resolvePublicUrl(deployment, shadow);
        String state = deployment.getStatus() == AppDeploymentStatus.FAILED
                ? "FAILED"
                : (ready ? "SUCCESS" : "RUNNING");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", state);
        out.put("ready", ready);
        if (appUrl != null) {
            out.put("appUrl", appUrl);
        }
        out.put("namespace", deployment.getNamespace());
        out.put("message", ready ? "Application prête" : "Déploiement en cours");
        return out;
    }

    private ManagedApplication buildShadowForDeployment(AppDeployment deployment, ManagedApplication realApp) {
        Map<String, Object> state = deployment.getServicesState();
        List<AppService> targetServices = new ArrayList<>();
        if (state != null && state.get("services") instanceof Map<?, ?> servicesMap) {
            for (Object key : servicesMap.keySet()) {
                String name = String.valueOf(key);
                realApp.getServices().stream()
                        .filter(s -> name.equals(s.getName()))
                        .findFirst()
                        .ifPresent(targetServices::add);
            }
        }
        if (targetServices.isEmpty() && realApp.getServices().size() == 1) {
            targetServices.add(realApp.getServices().get(0));
        }
        if (targetServices.isEmpty()) {
            throw new AppValidationException("Aucun service à déployer pour ce déploiement");
        }

        List<AppDatabase> depDbs = new ArrayList<>();
        for (AppService svc : targetServices) {
            if (svc.getDependsOnDatabaseId() != null) {
                realApp.getDatabases().stream()
                        .filter(d -> svc.getDependsOnDatabaseId().equals(d.getId()))
                        .findFirst()
                        .ifPresent(db -> {
                            if (depDbs.stream().noneMatch(x -> x.getId().equals(db.getId()))) {
                                depDbs.add(db);
                            }
                        });
            }
        }

        ManagedApplication shadow = new ManagedApplication();
        shadow.setId(realApp.getId());
        shadow.setName(realApp.getName());
        shadow.setSlug(realApp.getSlug());
        shadow.setServices(targetServices);
        shadow.setDatabases(depDbs);
        return shadow;
    }

    @SuppressWarnings("unchecked")
    private void markServicesDeploying(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (e.getValue() instanceof Map) {
                    ((Map<String, Object>) e.getValue()).put("status", "Deploying");
                }
            }
        }
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private void markServicesReady(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (e.getValue() instanceof Map) {
                    Map<String, Object> svcState = (Map<String, Object>) e.getValue();
                    svcState.put("status", "Ready");
                    if (svcState.get("externalUrl") == null) {
                        ManagedApplication shadow = buildShadowForDeployment(
                                deployment, deployment.getApplication());
                        String resolved = resolvePublicUrl(deployment, shadow);
                        if (resolved != null) {
                            svcState.put("externalUrl", resolved);
                        }
                    }
                }
            }
        }
        deployment.setServicesState(state);
        deploymentRepository.save(deployment);
    }

    private String resolvePublicUrl(AppDeployment deployment, ManagedApplication shadow) {
        Map<String, Object> state = deployment.getServicesState();
        if (state != null && state.get("services") instanceof Map<?, ?> services) {
            for (Object v : services.values()) {
                if (v instanceof Map<?, ?> svcState) {
                    Object ext = svcState.get("externalUrl");
                    if (ext != null && !String.valueOf(ext).isBlank()) {
                        return String.valueOf(ext);
                    }
                }
            }
        }
        if (nipPreviewEnabled && nipMasterIp != null && !nipMasterIp.isBlank()) {
            String scheme = nipScheme != null && !nipScheme.isBlank() ? nipScheme.trim().toLowerCase() : "https";
            String id = deployment.getId().toString().toLowerCase();
            return scheme + "://app-" + id + "." + nipMasterIp.trim() + ".nip.io:" + nipNodePort;
        }
        if (!shadow.getServices().isEmpty() && ingressEnabled) {
            AppService svc = shadow.getServices().get(0);
            String k8sName = AppNaming.k8sName(svc.getName());
            return "http://" + k8sName + "-" + deployment.getNamespace() + "." + ingressDomain;
        }
        return null;
    }

    private UUID parseUuid(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(raw.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private void updateServicesState(AppDeployment deployment, boolean success, Set<String> readyServices) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (e.getValue() instanceof Map) {
                    Map<String, Object> svcState = (Map<String, Object>) e.getValue();
                    boolean ready = success && (readyServices == null || readyServices.isEmpty()
                            || readyServices.contains(String.valueOf(e.getKey())));
                    svcState.put("status", ready ? "Ready" : "NotReady");
                }
            }
        }
        Object dbObj = state.get("databases");
        if (dbObj instanceof Map<?, ?> databases) {
            for (Map.Entry<?, ?> e : databases.entrySet()) {
                if (e.getValue() instanceof Map) {
                    ((Map<String, Object>) e.getValue()).put("status", success ? "Ready" : "NotReady");
                }
            }
        }
        // Réaffecte pour forcer la détection de changement JSONB par Hibernate.
        deployment.setServicesState(state);
    }

    // =====================================================================
    // Vagues + payload
    // =====================================================================

    /**
     * §3.3 — ordre borné :
     * <ol>
     *   <li>vague 0 : bases (appliquées et Ready en premier via {@code kubectl wait -l tier=database}) ;</li>
     *   <li>vague 1 : services avec dépendance ({@code depends_on_*}) ;</li>
     *   <li>vague 2 : services sans dépendance.</li>
     * </ol>
     */
    private Map<Integer, List<AppService>> computeWaves(ManagedApplication app) {
        Map<Integer, List<AppService>> waves = new LinkedHashMap<>();
        waves.put(1, new ArrayList<>());
        waves.put(2, new ArrayList<>());
        for (AppService svc : app.getServices()) {
            boolean hasDep = svc.getDependsOnDatabaseId() != null || svc.getDependsOnServiceId() != null;
            waves.get(hasDep ? 1 : 2).add(svc);
        }
        return waves;
    }

    private int waveOf(Map<Integer, List<AppService>> waves, AppService svc) {
        for (Map.Entry<Integer, List<AppService>> e : waves.entrySet()) {
            if (e.getValue().contains(svc)) {
                return e.getKey();
            }
        }
        return 2;
    }

    private String buildServicesJson(ManagedApplication app, Map<Integer, List<AppService>> waves, String imageTag) {
        List<Map<String, Object>> entries = new ArrayList<>();
        for (AppService svc : app.getServices()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("serviceName", AppNaming.k8sName(svc.getName()));
            m.put("role", svc.getRole().name());
            m.put("gitRepo", svc.getGitRepositoryUrl());
            m.put("gitToken", svc.getGitToken() != null ? svc.getGitToken() : ""); // déchiffré au déclenchement
            m.put("gitBranch", svc.getGitBranch());
            m.put("dockerfilePath", svc.getDockerfilePath());
            m.put("buildContext", svc.getBuildContext());
            m.put("exposedPort", svc.getExposedPort());
            m.put("imageTag", imageTag);
            m.put("wave", waveOf(waves, svc));
            entries.add(m);
        }
        try {
            return objectMapper.writeValueAsString(entries);
        } catch (Exception e) {
            log.error("Erreur sérialisation SERVICES_JSON: {}", e.getMessage());
            return "[]";
        }
    }

    private Map<String, Object> buildInitialState(ManagedApplication app, String namespace,
                                                  Map<Integer, List<AppService>> waves) {
        Map<String, Object> state = new LinkedHashMap<>();
        Map<String, Object> databases = new LinkedHashMap<>();
        for (AppDatabase db : app.getDatabases()) {
            Map<String, Object> dbState = new LinkedHashMap<>();
            dbState.put("status", "NotReady");
            dbState.put("wave", 0);
            dbState.put("internalHost", connectionUrlService.internalHost(db, namespace));
            databases.put(db.getName(), dbState);
        }
        Map<String, Object> services = new LinkedHashMap<>();
        for (AppService svc : app.getServices()) {
            String k8sName = AppNaming.k8sName(svc.getName());
            Map<String, Object> svcState = new LinkedHashMap<>();
            svcState.put("status", "NotReady");
            svcState.put("wave", waveOf(waves, svc));
            svcState.put("internalHost", k8sName + "." + namespace + ".svc.cluster.local");
            boolean exposed = svc.getRole() != com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.WORKER;
            svcState.put("externalUrl", exposed ? ("http://" + k8sName + "-" + namespace + "." + ingressDomain) : null);
            services.put(svc.getName(), svcState);
        }
        state.put("namespace", namespace);
        state.put("databases", databases);
        state.put("services", services);
        return state;
    }

    private String b64(String content) {
        return Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
    }

    private void addGitPipelineVariables(Map<String, String> variables, AppService service) {
        if (service == null) {
            throw new AppValidationException("Aucun service trouvé pour préparer les variables Git du pipeline.");
        }
        String branch = (service.getGitBranch() == null || service.getGitBranch().isBlank())
                ? "main"
                : service.getGitBranch().trim();
        addGitPipelineVariables(variables, service, branch);
    }

    private void addGitPipelineVariables(Map<String, String> variables, AppService service, String branch) {
        if (service == null) {
            throw new AppValidationException("Aucun service trouvé pour préparer les variables Git du pipeline.");
        }

        String repoUrl = service.getGitRepositoryUrl();
        if (repoUrl == null || repoUrl.isBlank()) {
            throw new AppValidationException("Le service ne contient pas d'URL Git (GIT_REPO_URL).");
        }

        String resolvedBranch = (branch == null || branch.isBlank()) ? "main" : branch.trim();
        String dockerfilePath = (service.getDockerfilePath() == null || service.getDockerfilePath().isBlank())
                ? "./Dockerfile"
                : service.getDockerfilePath().trim();
        String token = resolveDecryptedToken(service);

        variables.put("GIT_REPO_URL", repoUrl.trim());
        variables.put("GIT_BRANCH", resolvedBranch);
        variables.put("DOCKERFILE_PATH", dockerfilePath);
        variables.put("GITHUB_TOKEN", token != null ? token : "");
    }

    private String resolveDecryptedToken(AppService svc) {
        if (svc.getGitToken() != null && !svc.getGitToken().isBlank()) {
            return svc.getGitToken();
        }
        if (svc.getEncryptedGithubToken() != null && !svc.getEncryptedGithubToken().isBlank()) {
            try {
                return encryptionService.decrypt(svc.getEncryptedGithubToken());
            } catch (Exception e) {
                log.warn("Impossible de déchiffrer encryptedGithubToken du service {}: {}", svc.getId(), e.getMessage());
            }
        }
        return null;
    }

    private EphemeralEnvironment createEphemeralEnvironmentForDeploy(
            AppService service,
            User owner,
            String branch,
            String namespace,
            int ttlHours
    ) {
        EphemeralEnvironment env = new EphemeralEnvironment();
        env.setEnvironmentName("env-" + UUID.randomUUID().toString().substring(0, 8));
        env.setService(service);
        env.setGitBranch(branch != null && !branch.isBlank() ? branch : "main");
        env.setRequestedBy(owner);
        env.setStatus(EnvironmentStatus.PENDING);
        env.setTtlHours(ttlHours > 0 ? ttlHours : 4);
        env.setNamespace(namespace);
        service.addEphemeralEnvironment(env);
        log.info("Environnement éphémère créé pour déploiement — ttlHours={}, expiresAt sera calculé à la persistance",
                env.getTtlHours());
        return environmentRepository.save(env);
    }

    private void linkDeployPipelineExecution(
            AppService service,
            EphemeralEnvironment env,
            Long gitlabPipelineId,
            String branch
    ) {
        if (service == null || env == null || gitlabPipelineId == null) {
            return;
        }
        if (pipelineExecutionRepository.findByGitlabPipelineId(gitlabPipelineId).isPresent()) {
            return;
        }
        PipelineExecution execution = new PipelineExecution();
        execution.setAppService(service);
        execution.setGitlabPipelineId(gitlabPipelineId);
        execution.setExecutionKind(PipelineExecutionKind.DEPLOY);
        execution.setGitBranch(branch != null && !branch.isBlank() ? branch : env.getGitBranch());
        execution.setStatus(PipelineStatus.fromGitLabStatus("running"));
        execution.setStartedAt(LocalDateTime.now());
        execution.setEnvironment(env);
        env.setPipelineExecution(execution);
        pipelineExecutionRepository.save(execution);
        environmentRepository.save(env);
        log.info("Deploy enregistré — env={} pipeline_exec gitlab=#{} service={}",
                env.getId(), gitlabPipelineId, service.getId());
    }

    private void putBackendUrlIfConfigured(Map<String, String> variables) {
        if (isPublicCallbackBaseUrl(callbackBaseUrl)) {
            variables.put("BACKEND_URL", callbackBaseUrl.trim());
        }
    }

    private static boolean isPublicCallbackBaseUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        String normalized = url.trim().toLowerCase();
        return !normalized.contains("host.docker.internal")
                && !normalized.contains("localhost")
                && !normalized.startsWith("http://127.")
                && !normalized.startsWith("https://127.");
    }
}
