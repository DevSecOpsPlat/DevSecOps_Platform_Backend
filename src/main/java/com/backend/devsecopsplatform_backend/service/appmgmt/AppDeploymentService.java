package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.ClusterPruneResponse;
import com.backend.devsecopsplatform_backend.controller.appmgmt.RuntimeSyncResponse;
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
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import com.backend.devsecopsplatform_backend.repository.AppDatabaseRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentLifecycleService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    private final AppServiceRepository appServiceRepository;
    private final AppDeploymentValidationService validationService;
    private final AppConnectionUrlService connectionUrlService;
    private final AppK8sManifestService manifestService;
    private final AppDeploymentGitLabService gitLabService;
    private final EncryptionService encryptionService;
    private final ObjectMapper objectMapper;
    private final K8sManifestApplyService k8sManifestApplyService;
    private final EnvironmentLifecycleService environmentLifecycleService;
    private final TransactionTemplate transactionTemplate;

    /** Pool pour applies CI concurrents (plusieurs apps / rebuilds en parallèle). */
    private ExecutorService ciDeployExecutor;

    @Value("${deployment.ci-deploy.pool-size:4}")
    private int ciDeployPoolSize;

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

    @Value("${deployment.ingress.path-based:true}")
    private boolean pathBasedRouting;

    @Value("${deployment.ingress.controller:traefik}")
    private String ingressController;

    @Value("${deployment.ingress.class-name:traefik}")
    private String ingressClassName;

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

    @Value("${deployment.k8s.deploy-wait-timeout-seconds:300}")
    private int deployWaitTimeoutSeconds;

    @Value("${deployment.namespace.resource-quota.enabled:true}")
    private boolean namespaceResourceQuotaEnabled;

    @Value("${deployment.namespace.cpu-quota:4}")
    private String namespaceCpuQuota;

    @Value("${deployment.namespace.memory-quota:8Gi}")
    private String namespaceMemoryQuota;

    @PostConstruct
    void initCiDeployExecutor() {
        int size = Math.max(1, ciDeployPoolSize);
        java.util.concurrent.atomic.AtomicInteger idx =
                new java.util.concurrent.atomic.AtomicInteger();
        ciDeployExecutor = Executors.newFixedThreadPool(size, r -> {
            Thread t = new Thread(r, "ci-deploy-worker-" + idx.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        log.info("CI deploy executor initialisé — pool-size={}", size);
    }

    @PreDestroy
    void shutdownCiDeployExecutor() {
        if (ciDeployExecutor != null) {
            ciDeployExecutor.shutdownNow();
        }
    }

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
        AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                deployment.getId(), resolved.ttlHours(), null, app);

        // Les services sont générés après le build, lorsque toutes les images sont résolues.
        String databasesB64 = b64(manifestService.generateDatabaseBundle(app, namespace, opts));
        String servicesB64 = "";

        Map<Integer, List<AppService>> waves = computeWaves(app);
        String servicesJson = buildServicesJson(app, waves, imageTag);

        deployment.setServicesState(buildInitialState(app, namespace, waves, resolved.ttlHours()));

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        variables.put("APP_ID", app.getId().toString());
        variables.put("APP_SLUG", app.getSlug());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        AppService gitService = app.getServices().stream().findFirst()
                .orElseThrow(() -> new AppValidationException("Aucun service dans le projet."));
        variables.put("SERVICE_NAME", AppNaming.k8sName(gitService.getName()));
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
        deployment.setEphemeralEnvironmentId(env.getId());
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
        shadow.setCustomHostname(realApp.getCustomHostname());
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

        String appSlug = AppNaming.k8sName(realApp.getSlug());
        String serviceSlug = AppNaming.k8sName(target.getName());
        if (serviceSlug.startsWith(appSlug + "-")) {
            serviceSlug = serviceSlug.substring((appSlug + "-").length());
        }
        String namespace = AppNaming.namespace(appSlug + "-" + serviceSlug, deployment.getId());
        deployment.setNamespace(namespace);

        for (AppDatabase db : depDbs) {
            db.setGeneratedConnectionUrl(connectionUrlService.buildConnectionUrl(db, namespace));
            databaseRepository.save(db);
        }

        String imageTag = AppNaming.shortId(deployment.getId());
        AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                deployment.getId(), resolved.ttlHours(), null, realApp);

        String databasesB64 = b64(manifestService.generateDatabaseBundle(shadow, namespace, opts));
        String servicesB64 = "";

        Map<Integer, List<AppService>> waves = computeWaves(shadow);
        String servicesJson = buildServicesJson(shadow, waves, imageTag);

        deployment.setServicesState(buildInitialState(shadow, namespace, waves, resolved.ttlHours()));

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        variables.put("APP_ID", realApp.getId().toString());
        variables.put("APP_SLUG", realApp.getSlug());
        variables.put("SERVICE_ID", target.getId().toString());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        variables.put("SERVICE_NAME", AppNaming.k8sName(target.getName()));
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
        deployment.setEphemeralEnvironmentId(env.getId());
        variables.put("ENVIRONMENT_ID", env.getId().toString());

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        deployment.setStatus(pipelineId != null ? AppDeploymentStatus.DEPLOYING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());
        linkDeployPipelineExecution(target, env, pipelineId, deployBranch);

        return deploymentRepository.save(deployment);
    }

    /**
     * Teardown : supprime le namespace K8s via Fabric8 (si configuré), sinon via pipeline GitLab.
     * Met toujours le déploiement en STOPPED et aligne l'état UI (services/bases).
     */
    @Transactional
    public AppDeployment teardown(AppDeployment deployment) {
        String namespace = deployment.getNamespace();
        if (k8sManifestApplyService.isConfigured()
                && namespace != null
                && !namespace.isBlank()
                && !"pending".equals(namespace)) {
            try {
                k8sManifestApplyService.deleteNamespace(namespace);
            } catch (Exception e) {
                // Namespace peut être déjà parti / Terminating — on continue pour aligner l'UI.
                log.warn("Teardown namespace {} : {} — statut STOPPED quand même",
                        namespace, e.getMessage());
            }
        } else if (!k8sManifestApplyService.isConfigured()) {
            Map<String, String> variables = new LinkedHashMap<>();
            variables.put("ACTION", "teardown");
            variables.put("DEPLOYMENT_ID", deployment.getId().toString());
            variables.put("NAMESPACE", namespace != null ? namespace : "");
            putBackendUrlIfConfigured(variables);
            variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
            gitLabService.triggerPipeline(variables);
        }

        markDeploymentStopped(deployment);
        UUID envId = deployment.getEphemeralEnvironmentId();
        if (envId != null) {
            try {
                environmentLifecycleService.onDestroyed(envId, "Teardown manuel");
            } catch (Exception e) {
                log.warn("Teardown env {} : {}", envId, e.getMessage());
            }
        }
        return deploymentRepository.save(deployment);
    }

    /**
     * Alignement UI quand le TTL scheduler expire l'environnement lié.
     */
    @Transactional
    public void markStoppedFromTtl(UUID ephemeralEnvironmentId) {
        if (ephemeralEnvironmentId == null) {
            return;
        }
        deploymentRepository.findByEphemeralEnvironmentId(ephemeralEnvironmentId).ifPresent(deployment -> {
            if (deployment.getStatus() == AppDeploymentStatus.STOPPED
                    || deployment.getStatus() == AppDeploymentStatus.FAILED) {
                return;
            }
            markDeploymentStopped(deployment);
            deploymentRepository.save(deployment);
            log.info("Déploiement {} → STOPPED (TTL env {})", deployment.getId(), ephemeralEnvironmentId);
        });
    }

    @SuppressWarnings("unchecked")
    private void markDeploymentStopped(AppDeployment deployment) {
        deployment.setStatus(AppDeploymentStatus.STOPPED);
        clearPendingRebuild(deployment);
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (e.getValue() instanceof Map) {
                    Map<String, Object> svcState = (Map<String, Object>) e.getValue();
                    svcState.put("status", "Stopped");
                    svcState.put("externalUrl", null);
                }
            }
        }
        Object dbObj = state.get("databases");
        if (dbObj instanceof Map<?, ?> databases) {
            for (Map.Entry<?, ?> e : databases.entrySet()) {
                if (e.getValue() instanceof Map) {
                    ((Map<String, Object>) e.getValue()).put("status", "Stopped");
                }
            }
        }
        deployment.setServicesState(state);
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
     * Accepte un déploiement CI et lance l'apply K8s en arrière-plan (réponse HTTP immédiate).
     */
    public Map<String, Object> scheduleCiDeploy(CiDeployRequest request) {
        validateCiDeployRequest(request);
        UUID deploymentId = parseUuid(request.getDeploymentId());
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable: " + deploymentId));
        if (deployment.getApplication() == null) {
            throw new AppValidationException("Application managée introuvable pour le déploiement");
        }

        UUID environmentId = resolveEnvironmentId(request, deployment);
        String namespace = request.getNamespace().trim();
        deployment.setNamespace(namespace);
        deployment.setStatus(AppDeploymentStatus.DEPLOYING);
        deployment.setDeployedAt(null);
        markServicesDeploying(deployment, isPartialRebuild(deployment));
        deploymentRepository.save(deployment);

        if (environmentId != null) {
            environmentLifecycleService.onBuilding(environmentId);
        }

        CompletableFuture.runAsync(() -> {
            try {
                executeCiDeployWork(request);
            } catch (Exception e) {
                log.error("CI deploy async échoué (hors apply) — deployment={}: {}",
                        deploymentId, e.getMessage(), e);
                handleAsyncPrepareFailure(deploymentId, namespace, environmentId, e.getMessage());
            }
        }, ciDeployExecutor);

        log.info("CI deploy accepté (async) — deployment={} namespace={} image={} images={}",
                deploymentId, namespace, request.getImage(),
                request.getImages() != null ? request.getImages().keySet() : Set.of());
        return Map.of(
                "status", "deploying",
                "deploymentId", deploymentId.toString(),
                "namespace", namespace,
                "message", "Déploiement accepté — apply Kubernetes en cours"
        );
    }

    /** @deprecated Préférer {@link #scheduleCiDeploy} pour éviter les timeouts HTTP (Cloudflare 524). */
    public Map<String, Object> applyFromCiPipeline(CiDeployRequest request) {
        return scheduleCiDeploy(request);
    }

    private void validateCiDeployRequest(CiDeployRequest request) {
        boolean hasLegacyImage = request.getImage() != null && !request.getImage().isBlank();
        boolean hasImageMap = request.getImages() != null && !request.getImages().isEmpty();
        if (!hasLegacyImage && !hasImageMap) {
            throw new AppValidationException("image ou images requis");
        }
        if (hasLegacyImage && request.getImage().contains("${")) {
            throw new AppValidationException("Image CI non résolue: " + request.getImage());
        }
        if (hasImageMap) {
            request.getImages().forEach((service, image) -> {
                if (service == null || service.isBlank() || image == null || image.isBlank()) {
                    throw new AppValidationException("Chaque entrée images doit contenir un service et une image");
                }
                if (image.contains("${")) {
                    throw new AppValidationException(
                            "Image non résolue pour le service " + service + ": " + image);
                }
            });
        }
        if (request.getNamespace() == null || request.getNamespace().isBlank()) {
            throw new AppValidationException("namespace requis");
        }
        if (parseUuid(request.getDeploymentId()) == null) {
            throw new AppValidationException("deploymentId requis");
        }
    }

    private void executeCiDeployWork(CiDeployRequest request) {
        UUID deploymentId = parseUuid(request.getDeploymentId());
        String namespace = request.getNamespace().trim();

        PreparedCiDeploy prepared = transactionTemplate.execute(status -> {
            AppDeployment deployment = deploymentRepository.findWithApplicationById(deploymentId).orElse(null);
            if (deployment == null) {
                log.error("CI deploy async: déploiement introuvable {}", deploymentId);
                return null;
            }
            ManagedApplication realApp = deployment.getApplication();
            if (realApp == null) {
                log.error("CI deploy async: application introuvable pour {}", deploymentId);
                return null;
            }
            UUID appId = realApp.getId();
            List<AppService> services = appServiceRepository.findWithEnvVarsByManagedApplication_Id(appId);
            services.forEach(s -> s.getEnvVars().size());
            List<AppDatabase> databases = databaseRepository.findByApplication_Id(appId);
            UUID environmentId = resolveEnvironmentId(request, deployment);
            ManagedApplication shadow = buildShadowForDeployment(deployment, realApp, services, databases);
            String ciImageTarget = resolveCiImageTarget(request, shadow);
            int ttlHours = resolveTtlHours(environmentId, deployment);
            Map<String, String> resolvedImages = loadResolvedImages(deployment);
            mergeRequestedImages(request, shadow, resolvedImages);
            if (ciImageTarget != null && request.getImage() != null && !request.getImage().isBlank()) {
                if (shadow.getServices().size() != 1) {
                    throw new AppValidationException(
                            "Le payload image historique est réservé aux déploiements mono-service");
                }
                resolvedImages.clear();
                resolvedImages.put(ciImageTarget, request.getImage().trim());
            }
            assertAllServiceImagesResolved(shadow, resolvedImages);
            recordResolvedImages(deployment, resolvedImages);
            deploymentRepository.save(deployment);
            Map<String, String> validatedImages = Map.copyOf(resolvedImages);
            AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                    deployment.getId(), ttlHours, validatedImages, shadow);

            List<String> rebuildTargets = loadPendingRebuild(deployment);
            boolean partialRebuild = !rebuildTargets.isEmpty();

            String databasesYaml = "";
            boolean waitForDatabases = false;
            List<ServiceWaveManifest> serviceWaves = new ArrayList<>();
            String ingressYaml = "";

            if (partialRebuild) {
                Set<String> rebuildSet = Set.copyOf(rebuildTargets);
                List<AppService> targets = shadow.getServices().stream()
                        .filter(s -> rebuildSet.contains(AppNaming.k8sName(s.getName())))
                        .toList();
                if (targets.isEmpty()) {
                    throw new AppValidationException(
                            "Rebuild ciblé introuvable dans le déploiement: " + rebuildTargets);
                }
                // Ingress séparé après Ready (soft-fail) — pas dans la vague
                String waveYaml = manifestService.generateServiceWaveBundle(
                        shadow, namespace, opts, targets, false);
                List<String> depNames = targets.stream()
                        .map(s -> AppNaming.k8sName(s.getName()))
                        .toList();
                Map<String, Integer> replicaByName = new LinkedHashMap<>();
                for (AppService s : targets) {
                    replicaByName.put(AppNaming.k8sName(s.getName()),
                            s.getReplicas() != null ? Math.max(1, s.getReplicas()) : 1);
                }
                serviceWaves.add(new ServiceWaveManifest(waveYaml, depNames, replicaByName));
                ingressYaml = manifestService.generateIngressBundle(shadow, namespace, opts);
            } else {
                databasesYaml = manifestService.generateDatabaseBundle(shadow, namespace, opts);
                waitForDatabases = !shadow.getDatabases().isEmpty();
                Map<Integer, List<AppService>> waves = computeWaves(shadow);
                List<Integer> waveOrder = new ArrayList<>(waves.keySet());
                Collections.sort(waveOrder);
                for (int i = 0; i < waveOrder.size(); i++) {
                    List<AppService> waveServices = waves.get(waveOrder.get(i));
                    String waveYaml = manifestService.generateServiceWaveBundle(
                            shadow, namespace, opts, waveServices, false);
                    List<String> depNames = waveServices.stream()
                            .map(s -> AppNaming.k8sName(s.getName()))
                            .toList();
                    Map<String, Integer> replicaByName = new LinkedHashMap<>();
                    for (AppService s : waveServices) {
                        replicaByName.put(AppNaming.k8sName(s.getName()),
                                s.getReplicas() != null ? Math.max(1, s.getReplicas()) : 1);
                    }
                    serviceWaves.add(new ServiceWaveManifest(waveYaml, depNames, replicaByName));
                }
                ingressYaml = manifestService.generateIngressBundle(shadow, namespace, opts);
            }

            return new PreparedCiDeploy(
                    deployment,
                    shadow,
                    environmentId,
                    validatedImages,
                    databasesYaml,
                    waitForDatabases,
                    serviceWaves,
                    ingressYaml,
                    partialRebuild);
        });

        if (prepared == null) {
            handleAsyncPrepareFailure(deploymentId, namespace, null,
                    "Préparation du déploiement impossible (déploiement ou application introuvable)");
            return;
        }

        AppDeployment deployment = prepared.deployment();
        ManagedApplication shadow = prepared.shadow();
        UUID environmentId = prepared.environmentId();

        try {
            k8sManifestApplyService.ensureNamespaceReadyForApply(namespace);

            if (!prepared.partialRebuild()) {
                k8sManifestApplyService.applyManifests(prepared.databasesYaml());
                markDatabasesDeploying(deployment);

                if (prepared.waitForDatabases()) {
                    k8sManifestApplyService.waitUntilDatabasesReady(namespace);
                }
            }

            for (ServiceWaveManifest wave : prepared.serviceWaves()) {
                k8sManifestApplyService.applyManifests(wave.yaml());
                // SSA ignore souvent spec.replicas — forcer le scale voulu
                if (wave.replicaByName() != null) {
                    for (Map.Entry<String, Integer> e : wave.replicaByName().entrySet()) {
                        try {
                            k8sManifestApplyService.scaleDeployment(namespace, e.getKey(), e.getValue());
                        } catch (Exception scaleEx) {
                            log.warn("Scale {}/{} échoué (non bloquant): {}",
                                    namespace, e.getKey(), scaleEx.getMessage());
                        }
                    }
                }
                k8sManifestApplyService.waitUntilNamedDeploymentsReady(namespace, wave.deploymentNames());
            }

            // Ingress / Middleware après Ready — soft-fail si CRD Traefik bloque
            if (prepared.ingressYaml() != null && !prepared.ingressYaml().isBlank()) {
                String ingressError = null;
                boolean ingressOk = false;
                try {
                    k8sManifestApplyService.applyManifests(prepared.ingressYaml());
                    ingressOk = k8sManifestApplyService.hasAnyIngress(namespace);
                    if (!ingressOk) {
                        ingressError = "Aucun Ingress présent dans le namespace après apply";
                    }
                } catch (Exception ingressEx) {
                    ingressOk = false;
                    ingressError = ingressEx.getMessage();
                    log.warn("Ingress/Middleware non appliqué (non bloquant) ns={}: {}",
                            namespace, ingressEx.getMessage());
                }
                persistIngressState(deployment, ingressOk, ingressError);
            } else {
                // Ingress désactivé ou bundle vide
                persistIngressState(deployment, !ingressEnabled,
                        ingressEnabled ? "Bundle Ingress vide" : null);
            }

        } catch (Exception e) {
            log.error("CI deploy async échoué — deployment={}: {}", deploymentId, e.getMessage(), e);
            handleCiDeployFailure(deployment, environmentId, namespace, e.getMessage());
            return;
        }

        deployment.setStatus(AppDeploymentStatus.DEPLOYING);
        deployment.setDeployedAt(Instant.now());
        markServicesDeploying(deployment, prepared.partialRebuild());
        transactionTemplate.executeWithoutResult(status -> deploymentRepository.save(deployment));

        if (environmentId != null) {
            String appUrl = isIngressApplied(deployment)
                    ? resolvePublicUrl(deployment, shadow)
                    : null;
            transactionTemplate.executeWithoutResult(status ->
                    environmentRepository.findById(environmentId).ifPresent(env -> {
                        env.setNamespace(namespace);
                        if (appUrl != null) {
                            env.setUrl(appUrl);
                        }
                        environmentRepository.save(env);
                    }));
        }

        log.info("CI deploy appliqué (en attente Ready) — deployment={} namespace={} images={}",
                deploymentId, namespace, prepared.resolvedImages().keySet());
    }

    private record ServiceWaveManifest(
            String yaml,
            List<String> deploymentNames,
            Map<String, Integer> replicaByName
    ) {}

    private record PreparedCiDeploy(
            AppDeployment deployment,
            ManagedApplication shadow,
            UUID environmentId,
            Map<String, String> resolvedImages,
            String databasesYaml,
            boolean waitForDatabases,
            List<ServiceWaveManifest> serviceWaves,
            String ingressYaml,
            boolean partialRebuild
    ) {}

    @Transactional
    public Map<String, Object> getCiDeployStatus(UUID deploymentId) {
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable"));

        if (deployment.getStatus() == AppDeploymentStatus.FAILED) {
            return ciStatusResponse(deployment, false, "FAILED", "Déploiement en échec");
        }

        String namespace = deployment.getNamespace();

        ManagedApplication realApp = deployment.getApplication();
        ManagedApplication shadow = buildShadowForDeployment(deployment, realApp);
        List<String> expectedWorkloads;
        if (isPartialRebuild(deployment)) {
            // Rebuild ciblé : n'attendre que le(s) service(s) en cours de rebuild
            expectedWorkloads = loadPendingRebuild(deployment);
            log.debug("CI status rebuild partiel — wait workloads={}", expectedWorkloads);
        } else {
            expectedWorkloads = expectedWorkloadNames(shadow);
        }

        boolean workloadsReady = k8sManifestApplyService.isConfigured()
                && namespace != null
                && !namespace.isBlank()
                && k8sManifestApplyService.areExpectedWorkloadsReady(namespace, expectedWorkloads);

        // Si les pods sont déjà Ready, ne pas bloquer le CI sur un apply Ingress/Middleware en cours.
        if (deployment.getDeployedAt() == null
                && deployment.getStatus() == AppDeploymentStatus.DEPLOYING
                && !workloadsReady) {
            if (isDeployTimedOut(deployment)) {
                return failDeployTimeout(deployment);
            }
            return ciStatusResponse(deployment, false, "DEPLOYING", "Apply Kubernetes en cours");
        }

        boolean ready = workloadsReady;

        if (ready) {
            maybeRetryIngress(deployment, shadow, namespace);
            if (deployment.getDeployedAt() == null) {
                deployment.setDeployedAt(Instant.now());
            }
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            markServicesReady(deployment);
            clearPendingRebuild(deployment);
            deploymentRepository.save(deployment);
            UUID environmentId = resolveEnvironmentId(null, deployment);
            boolean ingressOk = isIngressApplied(deployment);
            String appUrl = ingressOk ? resolvePublicUrl(deployment, shadow) : null;
            if (environmentId != null) {
                final String resolvedUrl = appUrl;
                environmentRepository.findById(environmentId).ifPresent(env -> {
                    env.setNamespace(namespace);
                    if (resolvedUrl != null) {
                        env.setUrl(resolvedUrl);
                    }
                    environmentRepository.save(env);
                });
                environmentLifecycleService.onReady(environmentId, appUrl);
            }
            String msg = ingressOk
                    ? "Application prête"
                    : "Pods prêts — Ingress non appliqué (URL publique indisponible)";
            return ciStatusResponse(deployment, true, "SUCCESS", msg);
        }

        if (isDeployTimedOut(deployment)) {
            return failDeployTimeout(deployment);
        }

        if (deployment.getStatus() != AppDeploymentStatus.DEPLOYING
                && deployment.getStatus() != AppDeploymentStatus.RUNNING) {
            deployment.setStatus(AppDeploymentStatus.DEPLOYING);
            deploymentRepository.save(deployment);
        }

        return ciStatusResponse(deployment, false, "DEPLOYING", "Déploiement en cours — pods pas encore prêts");
    }

    private Map<String, Object> failDeployTimeout(AppDeployment deployment) {
        boolean rebuild = isPartialRebuild(deployment);
        if (rebuild) {
            // Pods souvent déjà Ready — ne pas laisser les services en "Deploying"
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            markServicesReady(deployment);
            clearPendingRebuild(deployment);
            deploymentRepository.save(deployment);
            return ciStatusResponse(deployment, false, "FAILED",
                    "Timeout rebuild — pods non prêts après " + deployWaitTimeoutSeconds + "s");
        }
        deployment.setStatus(AppDeploymentStatus.FAILED);
        deploymentRepository.save(deployment);
        UUID environmentId = resolveEnvironmentId(null, deployment);
        if (environmentId != null) {
            environmentLifecycleService.onPipelineFailed(
                    environmentId, "Timeout attente disponibilité des pods");
        }
        return ciStatusResponse(deployment, false, "FAILED",
                "Timeout — pods non prêts après " + deployWaitTimeoutSeconds + "s");
    }

    private List<String> expectedWorkloadNames(ManagedApplication shadow) {
        List<String> names = new ArrayList<>();
        if (shadow == null) {
            return names;
        }
        for (AppService svc : shadow.getServices()) {
            names.add(AppNaming.k8sName(svc.getName()));
        }
        for (AppDatabase db : shadow.getDatabases()) {
            names.add(connectionUrlService.serviceName(db));
        }
        return names;
    }

    @SuppressWarnings("unchecked")
    private void persistIngressState(AppDeployment deployment, boolean applied, String error) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        state.put("ingressApplied", applied);
        if (error != null && !error.isBlank()) {
            state.put("ingressError", error);
        } else {
            state.remove("ingressError");
        }
        if (applied) {
            state.remove("ingressRetryAt");
        }
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
    }

    private boolean isIngressApplied(AppDeployment deployment) {
        if (!ingressEnabled) {
            return true;
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !state.containsKey("ingressApplied")) {
            // Anciens déploiements sans flag : considérer OK si Ingress cluster présent
            String ns = deployment.getNamespace();
            return ns != null && k8sManifestApplyService.hasAnyIngress(ns);
        }
        return Boolean.TRUE.equals(state.get("ingressApplied"));
    }

    private void maybeRetryIngress(AppDeployment deployment, ManagedApplication shadow, String namespace) {
        if (!ingressEnabled || !k8sManifestApplyService.isConfigured()
                || namespace == null || namespace.isBlank()) {
            return;
        }
        if (isIngressApplied(deployment)) {
            return;
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state != null && state.get("ingressRetryAt") != null) {
            return; // un seul retry auto
        }
        try {
            AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                    deployment.getId(), resolveTtlHours(null, deployment),
                    loadResolvedImages(deployment), shadow);
            String yaml = manifestService.generateIngressBundle(shadow, namespace, opts);
            if (yaml == null || yaml.isBlank()) {
                persistIngressState(deployment, false, "Bundle Ingress vide au retry");
                return;
            }
            k8sManifestApplyService.applyManifests(yaml);
            boolean ok = k8sManifestApplyService.hasAnyIngress(namespace);
            Map<String, Object> st = deployment.getServicesState();
            if (st == null) {
                st = new LinkedHashMap<>();
            }
            st.put("ingressRetryAt", Instant.now().toString());
            deployment.setServicesState(st);
            persistIngressState(deployment, ok, ok ? null : "Retry Ingress : toujours absent");
            log.info("Retry Ingress ns={} applied={}", namespace, ok);
        } catch (Exception e) {
            Map<String, Object> st = deployment.getServicesState();
            if (st == null) {
                st = new LinkedHashMap<>();
            }
            st.put("ingressRetryAt", Instant.now().toString());
            deployment.setServicesState(st);
            persistIngressState(deployment, false, "Retry Ingress échoué: " + e.getMessage());
            log.warn("Retry Ingress ns={} échoué: {}", namespace, e.getMessage());
        }
    }

    private Map<String, Object> ciStatusResponse(
            AppDeployment deployment,
            boolean ready,
            String state,
            String message
    ) {
        ManagedApplication shadow = buildShadowForDeployment(deployment, deployment.getApplication());
        boolean ingressOk = isIngressApplied(deployment);
        String appUrl = ingressOk ? resolvePublicUrl(deployment, shadow) : null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", state);
        out.put("ready", ready);
        if (appUrl != null) {
            out.put("appUrl", appUrl);
        }
        out.put("namespace", deployment.getNamespace());
        out.put("message", message);
        out.put("ingressApplied", ingressOk);
        Map<String, Object> svcState = deployment.getServicesState();
        if (svcState != null && svcState.get("ingressError") != null) {
            out.put("ingressError", svcState.get("ingressError"));
        }
        return out;
    }

    private UUID resolveEnvironmentId(CiDeployRequest request, AppDeployment deployment) {
        if (request != null) {
            UUID fromRequest = parseUuid(request.getEnvironmentId());
            if (fromRequest != null) {
                return fromRequest;
            }
        }
        if (deployment.getEphemeralEnvironmentId() != null) {
            return deployment.getEphemeralEnvironmentId();
        }
        String ns = deployment.getNamespace();
        if (ns != null && !ns.isBlank() && !"pending".equals(ns)) {
            return environmentRepository.findFirstByNamespaceOrderByCreatedAtDesc(ns)
                    .map(EphemeralEnvironment::getId)
                    .orElse(null);
        }
        return null;
    }

    private String resolveCiImageTarget(CiDeployRequest request, ManagedApplication shadow) {
        if (request.getServiceName() != null && !request.getServiceName().isBlank()) {
            return AppNaming.k8sName(request.getServiceName().trim());
        }
        if (!shadow.getServices().isEmpty()) {
            return AppNaming.k8sName(shadow.getServices().get(0).getName());
        }
        return null;
    }

    private void mergeRequestedImages(
            CiDeployRequest request,
            ManagedApplication shadow,
            Map<String, String> resolvedImages
    ) {
        if (request.getImages() == null || request.getImages().isEmpty()) {
            return;
        }
        // Merge (pas clear) : un rebuild partiel ne renvoie qu'une image et doit
        // conserver les images déjà résolues des autres services.
        Set<String> knownServices = shadow.getServices().stream()
                .map(service -> AppNaming.k8sName(service.getName()))
                .collect(java.util.stream.Collectors.toSet());
        Set<String> seenInRequest = new java.util.HashSet<>();
        request.getImages().forEach((rawServiceName, rawImage) -> {
            String serviceName = AppNaming.k8sName(rawServiceName.trim());
            if (!knownServices.contains(serviceName)) {
                throw new AppValidationException(
                        "Image fournie pour un service inconnu du déploiement: " + rawServiceName);
            }
            String image = rawImage.trim();
            if (image.contains("${")) {
                throw new AppValidationException(
                        "Image non résolue pour le service " + rawServiceName + ": " + image);
            }
            if (!seenInRequest.add(serviceName)) {
                throw new AppValidationException(
                        "Collision de noms de services après normalisation: " + rawServiceName);
            }
            resolvedImages.put(serviceName, image);
        });
    }

    private void assertAllServiceImagesResolved(
            ManagedApplication shadow,
            Map<String, String> resolvedImages
    ) {
        List<String> missing = shadow.getServices().stream()
                .map(service -> AppNaming.k8sName(service.getName()))
                .filter(serviceName -> {
                    String image = resolvedImages.get(serviceName);
                    return image == null || image.isBlank() || image.contains("${");
                })
                .toList();
        if (!missing.isEmpty()) {
            throw new AppValidationException(
                    "Images CI manquantes pour les services: " + String.join(", ", missing));
        }
    }

    private int resolveTtlHours(UUID environmentId, AppDeployment deployment) {
        if (environmentId != null) {
            return environmentRepository.findById(environmentId)
                    .map(EphemeralEnvironment::getTtlHours)
                    .filter(h -> h != null && h > 0)
                    .orElse(4);
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state != null && state.get("ttlHours") instanceof Number n) {
            return n.intValue();
        }
        return 4;
    }

    private boolean isDeployTimedOut(AppDeployment deployment) {
        Instant start;
        if (isPartialRebuild(deployment)) {
            // Rebuild : deployedAt = 1er Ready (ne pas l'utiliser) → updatedAt du passage DEPLOYING
            start = deployment.getUpdatedAt() != null
                    ? deployment.getUpdatedAt()
                    : deployment.getCreatedAt();
        } else {
            // Pendant l'apply async deployedAt est null — timeout depuis createdAt
            start = deployment.getDeployedAt() != null
                    ? deployment.getDeployedAt()
                    : deployment.getCreatedAt();
        }
        if (start == null) {
            return false;
        }
        long elapsedMs = Instant.now().toEpochMilli() - start.toEpochMilli();
        return elapsedMs > deployWaitTimeoutSeconds * 1000L;
    }

    private void handleAsyncPrepareFailure(
            UUID deploymentId,
            String namespace,
            UUID environmentId,
            String reason
    ) {
        transactionTemplate.executeWithoutResult(status ->
                deploymentRepository.findById(deploymentId).ifPresent(deployment -> {
                    deployment.setStatus(AppDeploymentStatus.FAILED);
                    deploymentRepository.save(deployment);
                    UUID envId = environmentId != null ? environmentId : resolveEnvironmentId(null, deployment);
                    if (envId != null) {
                        environmentLifecycleService.onPipelineFailed(envId, reason);
                    }
                }));
    }

    private void handleCiDeployFailure(
            AppDeployment deployment,
            UUID environmentId,
            String namespace,
            String reason
    ) {
        // Si le poll CI a déjà marqué RUNNING (pods Ready), ne pas rollback.
        AppDeployment latest = deploymentRepository.findById(deployment.getId()).orElse(deployment);
        if (latest.getStatus() == AppDeploymentStatus.RUNNING) {
            log.warn("CI apply échoué après RUNNING — rollback ignoré — deployment={}: {}",
                    deployment.getId(), reason);
            return;
        }
        if (isPartialRebuild(deployment)) {
            // Rebuild in-place : conserver le namespace et le statut RUNNING.
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            clearPendingRebuild(deployment);
            deploymentRepository.save(deployment);
            log.error("Rebuild service échoué (namespace conservé) — deployment={}: {}",
                    deployment.getId(), reason);
            return;
        }
        deployment.setStatus(AppDeploymentStatus.FAILED);
        deploymentRepository.save(deployment);
        if (environmentId != null) {
            environmentLifecycleService.onPipelineFailed(
                    environmentId, "Échec apply Kubernetes: " + reason);
        }
        k8sManifestApplyService.rollbackNamespace(namespace);
    }

    @SuppressWarnings("unchecked")
    private void recordResolvedImages(AppDeployment deployment, Map<String, String> resolvedImages) {
        if (resolvedImages == null || resolvedImages.isEmpty()) {
            return;
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        Object imagesObj = state.get("resolvedImages");
        Map<String, String> images;
        if (imagesObj instanceof Map<?, ?> existing) {
            images = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : existing.entrySet()) {
                images.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
            }
        } else {
            images = new LinkedHashMap<>();
        }
        resolvedImages.forEach((service, image) -> {
            if (service != null && !service.isBlank() && image != null && !image.isBlank()) {
                images.put(AppNaming.k8sName(service), image.trim());
            }
        });
        state.put("resolvedImages", images);
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> loadResolvedImages(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("resolvedImages") instanceof Map<?, ?> raw)) {
            return new LinkedHashMap<>();
        }
        Map<String, String> images = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : raw.entrySet()) {
            images.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        }
        return images;
    }

    private AppK8sManifestService.ManifestOptions buildManifestOptions(
            UUID deploymentId,
            Integer ttlHours,
            Map<String, String> resolvedImages
    ) {
        return buildManifestOptions(deploymentId, ttlHours, resolvedImages, null);
    }

    private AppK8sManifestService.ManifestOptions buildManifestOptions(
            UUID deploymentId,
            Integer ttlHours,
            Map<String, String> resolvedImages,
            ManagedApplication app
    ) {
        String customHost = app != null ? normalizeCustomHostname(app.getCustomHostname()) : null;
        return AppK8sManifestService.ManifestOptions.builder()
                .registryServer(registryServer)
                .registryUsername(registryUsername)
                .registryPassword(registryPassword)
                .pullSecretName(pullSecretName)
                .ingressEnabled(ingressEnabled)
                .ingressDomain(ingressDomain)
                .customHostname(customHost)
                .pathBasedRouting(pathBasedRouting || customHost != null)
                .ingressController(ingressController)
                .ingressClassName(ingressClassName)
                .resolvedServiceImages(resolvedImages)
                .namespaceTtlHours(ttlHours)
                .deploymentId(deploymentId != null ? deploymentId.toString() : null)
                .resourceQuotaEnabled(namespaceResourceQuotaEnabled)
                .namespaceCpuQuota(namespaceCpuQuota)
                .namespaceMemoryQuota(namespaceMemoryQuota)
                .build();
    }

    static String normalizeCustomHostname(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String h = raw.trim().toLowerCase();
        if (h.startsWith("http://")) {
            h = h.substring(7);
        } else if (h.startsWith("https://")) {
            h = h.substring(8);
        }
        int slash = h.indexOf('/');
        if (slash >= 0) {
            h = h.substring(0, slash);
        }
        h = h.replaceAll("\\.$", "");
        if (!h.matches("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$") || h.length() > 253) {
            throw new AppValidationException(
                    "Hostname invalide (ex. demo.example.com, sans http://).");
        }
        return h;
    }

    private String applicationPublicBase(String namespace, ManagedApplication app) {
        String custom = app != null ? normalizeCustomHostnameSafe(app.getCustomHostname()) : null;
        if (custom != null) {
            return "http://" + custom;
        }
        return "http://app-" + namespace + "." + ingressDomain;
    }

    private static String normalizeCustomHostnameSafe(String raw) {
        try {
            return normalizeCustomHostname(raw);
        } catch (AppValidationException e) {
            return null;
        }
    }

    private ManagedApplication buildShadowForDeployment(AppDeployment deployment, ManagedApplication realApp) {
        return buildShadowForDeployment(
                deployment,
                realApp,
                realApp.getServices(),
                realApp.getDatabases());
    }

    private ManagedApplication buildShadowForDeployment(
            AppDeployment deployment,
            ManagedApplication realApp,
            List<AppService> allServices,
            List<AppDatabase> allDatabases
    ) {
        Map<String, Object> state = deployment.getServicesState();
        List<AppService> targetServices = new ArrayList<>();
        if (state != null && state.get("services") instanceof Map<?, ?> servicesMap) {
            for (Object key : servicesMap.keySet()) {
                String name = String.valueOf(key);
                allServices.stream()
                        .filter(s -> name.equals(s.getName()))
                        .findFirst()
                        .ifPresent(targetServices::add);
            }
        }
        if (targetServices.isEmpty() && allServices.size() == 1) {
            targetServices.add(allServices.get(0));
        }
        if (targetServices.isEmpty()) {
            throw new AppValidationException("Aucun service à déployer pour ce déploiement");
        }

        List<AppDatabase> depDbs = new ArrayList<>();
        for (AppService svc : targetServices) {
            if (svc.getDependsOnDatabaseId() != null) {
                allDatabases.stream()
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
        shadow.setCustomHostname(realApp.getCustomHostname());
        shadow.setServices(targetServices);
        shadow.setDatabases(depDbs);
        return shadow;
    }

    @SuppressWarnings("unchecked")
    private void markDatabasesDeploying(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        Object dbObj = state.get("databases");
        if (dbObj instanceof Map<?, ?> databases) {
            for (Map.Entry<?, ?> e : databases.entrySet()) {
                if (e.getValue() instanceof Map) {
                    ((Map<String, Object>) e.getValue()).put("status", "Deploying");
                }
            }
        }
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private void markServicesDeploying(AppDeployment deployment) {
        markServicesDeploying(deployment, false);
    }

    @SuppressWarnings("unchecked")
    private void markServicesDeploying(AppDeployment deployment, boolean partialRebuildOnly) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        Set<String> rebuildTargets = partialRebuildOnly
                ? Set.copyOf(loadPendingRebuild(deployment))
                : Set.of();
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (!(e.getValue() instanceof Map)) {
                    continue;
                }
                String logicalName = String.valueOf(e.getKey());
                if (partialRebuildOnly
                        && !rebuildTargets.contains(AppNaming.k8sName(logicalName))) {
                    continue;
                }
                ((Map<String, Object>) e.getValue()).put("status", "Deploying");
            }
        }
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private List<String> loadPendingRebuild(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("pendingRebuild") instanceof List<?> raw)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object o : raw) {
            if (o != null) {
                String name = AppNaming.k8sName(String.valueOf(o).trim());
                if (!name.isBlank()) {
                    out.add(name);
                }
            }
        }
        return out;
    }

    private boolean isPartialRebuild(AppDeployment deployment) {
        return !loadPendingRebuild(deployment).isEmpty();
    }

    private void setPendingRebuild(AppDeployment deployment, String k8sServiceName) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        state.put("pendingRebuild", List.of(AppNaming.k8sName(k8sServiceName)));
        deployment.setServicesState(state);
    }

    private void clearPendingRebuild(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        state.remove("pendingRebuild");
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private void markServicesReady(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            return;
        }
        boolean ingressOk = isIngressApplied(deployment);
        Object servicesObj = state.get("services");
        if (servicesObj instanceof Map<?, ?> services) {
            for (Map.Entry<?, ?> e : services.entrySet()) {
                if (e.getValue() instanceof Map) {
                    Map<String, Object> svcState = (Map<String, Object>) e.getValue();
                    svcState.put("status", "Ready");
                    if (ingressOk && svcState.get("externalUrl") == null) {
                        ManagedApplication shadow = buildShadowForDeployment(
                                deployment, deployment.getApplication());
                        String resolved = resolvePublicUrl(deployment, shadow);
                        if (resolved != null) {
                            svcState.put("externalUrl", resolved);
                        }
                    }
                    if (!ingressOk) {
                        // Ne pas afficher une URL Ingress morte
                        svcState.put("externalUrl", null);
                    }
                }
            }
        }
        Object dbObj = state.get("databases");
        if (dbObj instanceof Map<?, ?> databases) {
            for (Map.Entry<?, ?> e : databases.entrySet()) {
                if (e.getValue() instanceof Map) {
                    ((Map<String, Object>) e.getValue()).put("status", "Ready");
                }
            }
        }
        deployment.setServicesState(state);
        deploymentRepository.save(deployment);
    }

    private String resolvePublicUrl(AppDeployment deployment, ManagedApplication shadow) {
        if (!isIngressApplied(deployment)) {
            return null;
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state != null && state.get("services") instanceof Map<?, ?> services) {
            for (Object v : services.values()) {
                if (v instanceof Map<?, ?> svcState) {
                    Object ext = svcState.get("externalUrl");
                    if (ext != null && !String.valueOf(ext).isBlank()) {
                        String url = String.valueOf(ext);
                        // Ignorer d'anciennes URLs NodePort / IP:port — préférer Ingress host
                        if (!url.matches("^https?://\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+.*")) {
                            return url;
                        }
                    }
                }
            }
        }
        if (!shadow.getServices().isEmpty() && ingressEnabled && pathBasedRouting
                && deployment.getNamespace() != null) {
            return applicationPublicBase(deployment.getNamespace(), shadow);
        }
        if (nipPreviewEnabled && nipMasterIp != null && !nipMasterIp.isBlank()
                && normalizeCustomHostnameSafe(shadow.getCustomHostname()) == null) {
            String scheme = nipScheme != null && !nipScheme.isBlank() ? nipScheme.trim().toLowerCase() : "http";
            String id = deployment.getId().toString().toLowerCase();
            return scheme + "://app-" + id + "." + nipMasterIp.trim() + ".nip.io";
        }
        if (!shadow.getServices().isEmpty() && ingressEnabled) {
            String custom = normalizeCustomHostnameSafe(shadow.getCustomHostname());
            if (custom != null) {
                return "http://" + custom;
            }
            AppService svc = shadow.getServices().get(0);
            String k8sName = AppNaming.k8sName(svc.getName());
            return "http://" + k8sName + "-" + deployment.getNamespace() + "." + ingressDomain;
        }
        return null;
    }

    private String ingressServiceUrl(String namespace, AppService svc, ManagedApplication app) {
        if (!ingressEnabled || !isExternallyExposedService(svc)) {
            return null;
        }
        boolean usePath = pathBasedRouting || normalizeCustomHostnameSafe(app != null ? app.getCustomHostname() : null) != null;
        if (usePath) {
            String base = applicationPublicBase(namespace, app);
            AppService primary = findPrimaryExposed(app);
            if (primary != null && java.util.Objects.equals(svc.getId(), primary.getId())) {
                return base;
            }
            AppService primaryBackend = findPrimaryApiBackend(app, primary);
            if (primaryBackend != null && java.util.Objects.equals(svc.getId(), primaryBackend.getId())) {
                return base + "/api";
            }
            return base + "/" + AppNaming.k8sName(svc.getName());
        }
        return "http://" + AppNaming.k8sName(svc.getName()) + "-" + namespace + "." + ingressDomain;
    }

    private AppService findPrimaryApiBackend(ManagedApplication app, AppService primary) {
        if (primary != null && primary.getDependsOnServiceId() != null) {
            AppService declared = app.getServices().stream()
                    .filter(service -> primary.getDependsOnServiceId().equals(service.getId()))
                    .filter(this::isExternallyExposedService)
                    .filter(service -> service.getRole()
                            == com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.BACKEND)
                    .findFirst()
                    .orElse(null);
            if (declared != null) {
                return declared;
            }
        }
        return app.getServices().stream()
                .filter(this::isExternallyExposedService)
                .filter(service -> service.getRole()
                        == com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.BACKEND)
                .findFirst()
                .orElse(null);
    }

    private AppService findPrimaryExposed(ManagedApplication app) {
        List<AppService> exposed = app.getServices().stream()
                .filter(this::isExternallyExposedService)
                .toList();
        if (exposed.isEmpty()) {
            return null;
        }
        return exposed.stream()
                .filter(s -> s.getRole() == com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.FRONTEND)
                .findFirst()
                .orElse(exposed.get(0));
    }

    private boolean isExternallyExposedService(AppService svc) {
        return svc.getExposedPort() != null
                && svc.getRole() != com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.WORKER;
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
     * §3.3 — ordre :
     * <ol>
     *   <li>vague 0 : bases (kubectl wait -l tier=database) ;</li>
     *   <li>vagues services : tri topologique — sans dépendances service d'abord,
     *       puis ceux qui en dépendent (profondeur croissante).</li>
     * </ol>
     */
    private Map<Integer, List<AppService>> computeWaves(ManagedApplication app) {
        return ServiceTopology.computeWaves(app);
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

    private Map<String, Object> buildInitialState(
            ManagedApplication app,
            String namespace,
            Map<Integer, List<AppService>> waves,
            int ttlHours
    ) {
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
            svcState.put("externalUrl", ingressServiceUrl(namespace, svc, app));
            services.put(svc.getName(), svcState);
        }
        state.put("namespace", namespace);
        state.put("ttlHours", ttlHours > 0 ? ttlHours : 4);
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
        String buildContext = (service.getBuildContext() == null || service.getBuildContext().isBlank())
                ? "."
                : service.getBuildContext().trim();
        String token = resolveDecryptedToken(service);

        variables.put("GIT_REPO_URL", repoUrl.trim());
        variables.put("GIT_BRANCH", resolvedBranch);
        variables.put("DOCKERFILE_PATH", dockerfilePath);
        variables.put("BUILD_CONTEXT", buildContext);
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
        if (isReachableCallbackBaseUrl(callbackBaseUrl)) {
            variables.put("BACKEND_URL", callbackBaseUrl.trim());
        }
    }

    private static boolean isReachableCallbackBaseUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        String normalized = url.trim().toLowerCase();
        return !normalized.contains("localhost")
                && !normalized.startsWith("http://127.")
                && !normalized.startsWith("https://127.");
    }

    /**
     * Rebuild CI d'un seul service dans le namespace RUNNING existant (même DEPLOYMENT_ID).
     * Ne crée pas de nouveau namespace — contrairement à {@link #deploySingleService}.
     */
    @Transactional
    public AppDeployment rebuildServiceInPlace(ManagedApplication realApp, UUID serviceId) {
        if (realApp == null || realApp.getId() == null) {
            throw new AppValidationException("Application requise.");
        }
        UUID appId = realApp.getId();
        AppService target = realApp.getServices().stream()
                .filter(s -> serviceId.equals(s.getId()))
                .findFirst()
                .orElseThrow(() -> new AppValidationException("Service introuvable dans ce projet."));

        AppDeployment deployment = deploymentRepository
                .findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING
                        || d.getStatus() == AppDeploymentStatus.DEPLOYING)
                .findFirst()
                .orElseThrow(() -> new AppValidationException(
                        "Aucun environnement RUNNING — déployez l'application d'abord."));

        if (deployment.getStatus() == AppDeploymentStatus.DEPLOYING && isPartialRebuild(deployment)) {
            throw new AppValidationException(
                    "Un rebuild est déjà en cours sur ce déploiement. Attendez la fin.");
        }
        if (deployment.getStatus() == AppDeploymentStatus.DEPLOYING && !isPartialRebuild(deployment)) {
            throw new AppValidationException(
                    "Un déploiement complet est en cours. Attendez la fin avant de rebuild.");
        }

        String namespace = deployment.getNamespace();
        if (namespace == null || namespace.isBlank() || "pending".equals(namespace)) {
            throw new AppValidationException("Namespace invalide pour ce déploiement.");
        }

        String k8sName = AppNaming.k8sName(target.getName());
        Map<String, String> existingImages = loadResolvedImages(deployment);
        if (existingImages.isEmpty() || !existingImages.containsKey(k8sName)) {
            throw new AppValidationException(
                    "Image du service « " + target.getName()
                            + " » absente de ce déploiement — un redéploiement complet est requis.");
        }

        int ttlHours = resolveTtlHours(deployment.getEphemeralEnvironmentId(), deployment);
        String imageTag = "r" + Long.toHexString(System.currentTimeMillis());

        ManagedApplication shadow = new ManagedApplication();
        shadow.setId(realApp.getId());
        shadow.setName(realApp.getName());
        shadow.setSlug(realApp.getSlug());
        shadow.setCustomHostname(realApp.getCustomHostname());
        shadow.setServices(List.of(target));
        shadow.setDatabases(List.of());

        Map<Integer, List<AppService>> waves = computeWaves(shadow);
        String servicesJson = buildServicesJson(shadow, waves, imageTag);

        setPendingRebuild(deployment, k8sName);
        markServicesDeploying(deployment, true);
        deployment.setStatus(AppDeploymentStatus.DEPLOYING);
        // Ne pas écraser deployedAt (TTL / ready d'origine) — le timeout rebuild
        // utilise updatedAt via isDeployTimedOut.
        deployment = deploymentRepository.save(deployment);

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        variables.put("APP_ID", realApp.getId().toString());
        variables.put("APP_SLUG", realApp.getSlug());
        variables.put("SERVICE_ID", target.getId().toString());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        variables.put("SERVICE_NAME", k8sName);
        String deployBranch = (target.getGitBranch() == null || target.getGitBranch().isBlank())
                ? "main"
                : target.getGitBranch().trim();
        addGitPipelineVariables(variables, target, deployBranch);
        variables.put("APPLICATION_ID", target.getId().toString());
        variables.put("NAMESPACE", namespace);
        putBackendUrlIfConfigured(variables);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        variables.put("IMAGE_TAG", imageTag);
        variables.put("PULL_SECRET_NAME", pullSecretName);
        variables.put("K8S_DATABASES_B64", "");
        variables.put("K8S_SERVICES_B64", "");
        variables.put("SERVICES_JSON", servicesJson);
        variables.put("TTL_HOURS", String.valueOf(ttlHours));
        variables.put("REBUILD_ONLY", "true");

        UUID envId = deployment.getEphemeralEnvironmentId();
        if (envId != null) {
            variables.put("ENVIRONMENT_ID", envId.toString());
        } else {
            EphemeralEnvironment env = createEphemeralEnvironmentForDeploy(
                    target, realApp.getCreatedBy(), deployBranch, namespace, ttlHours);
            deployment.setEphemeralEnvironmentId(env.getId());
            variables.put("ENVIRONMENT_ID", env.getId().toString());
            envId = env.getId();
        }

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        if (pipelineId == null) {
            clearPendingRebuild(deployment);
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            deploymentRepository.save(deployment);
            throw new AppValidationException("Échec déclenchement pipeline GitLab (rebuild).");
        }

        EphemeralEnvironment env = environmentRepository.findById(envId).orElse(null);
        if (env != null) {
            linkDeployPipelineExecution(target, env, pipelineId, deployBranch);
        }

        log.info("Rebuild service in-place — app={} service={} ns={} deployment={} pipeline={}",
                appId, k8sName, namespace, deployment.getId(), pipelineId);
        return deploymentRepository.save(deployment);
    }

    /**
     * Après suppression d'un service en base : retire ses ressources K8s des namespaces
     * RUNNING et rafraîchit l'Ingress path-based avec les services restants.
     */
    public ClusterPruneResponse pruneRemovedService(
            ManagedApplication realApp,
            String logicalServiceName,
            String k8sServiceName
    ) {
        if (realApp == null || realApp.getId() == null) {
            throw new AppValidationException("Application requise.");
        }
        if (!k8sManifestApplyService.isConfigured()) {
            return ClusterPruneResponse.builder()
                    .pruned(false)
                    .message("Service retiré du modèle (cluster K8s non configuré).")
                    .build();
        }

        UUID appId = realApp.getId();
        String k8sName = AppNaming.k8sName(k8sServiceName != null ? k8sServiceName : logicalServiceName);
        List<AppDeployment> running = deploymentRepository
                .findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING
                        || d.getStatus() == AppDeploymentStatus.DEPLOYING)
                .toList();

        if (running.isEmpty()) {
            return ClusterPruneResponse.builder()
                    .pruned(false)
                    .message("Service retiré du modèle (aucun environnement RUNNING à nettoyer).")
                    .build();
        }

        List<AppService> remaining = appServiceRepository.findWithEnvVarsByManagedApplication_Id(appId);
        List<AppDatabase> databases = databaseRepository.findByApplication_Id(appId);
        List<String> namespaces = new ArrayList<>();
        List<String> removed = new ArrayList<>();

        for (AppDeployment deployment : running) {
            String ns = deployment.getNamespace();
            if (ns == null || ns.isBlank() || "pending".equals(ns)) {
                continue;
            }
            try {
                List<String> deleted = k8sManifestApplyService.deleteAppServiceResources(ns, k8sName);
                removed.addAll(deleted.stream().map(r -> ns + "/" + r).toList());

                removeFromServicesState(deployment, logicalServiceName, k8sName);
                removeResolvedImage(deployment, k8sName);

                ManagedApplication shadow = new ManagedApplication();
                shadow.setId(appId);
                shadow.setName(realApp.getName());
                shadow.setSlug(realApp.getSlug());
        shadow.setCustomHostname(realApp.getCustomHostname());
                shadow.setServices(remaining);
                shadow.setDatabases(databases);

                Map<String, String> images = loadResolvedImages(deployment);
                boolean anyExposed = remaining.stream()
                        .anyMatch(s -> s.getExposedPort() != null
                                && (s.getRole() == com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.FRONTEND
                                || s.getRole() == com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole.BACKEND));

                if (!anyExposed || remaining.isEmpty()) {
                    List<String> ingressGone = k8sManifestApplyService.deleteSharedAppIngress(ns);
                    removed.addAll(ingressGone.stream().map(r -> ns + "/" + r).toList());
                } else if (!images.isEmpty()) {
                    AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                            deployment.getId(), null, images, realApp);
                    String yaml = manifestService.generateServiceWaveBundle(
                            shadow, ns, opts, List.of(), true);
                    if (yaml != null && !yaml.isBlank()) {
                        k8sManifestApplyService.applyManifests(yaml);
                    }
                }

                deploymentRepository.save(deployment);
                namespaces.add(ns);
                log.info("Prune service OK — ns={} service={}", ns, k8sName);
            } catch (Exception e) {
                throw new AppValidationException(
                        "Échec nettoyage cluster sur " + ns + " : " + e.getMessage());
            }
        }

        return ClusterPruneResponse.builder()
                .pruned(!namespaces.isEmpty())
                .namespaces(namespaces)
                .removedResources(removed)
                .message(namespaces.isEmpty()
                        ? "Service retiré du modèle (rien à nettoyer sur le cluster)."
                        : "Service retiré et ressources K8s nettoyées sur "
                        + String.join(", ", namespaces) + ".")
                .build();
    }

    /**
     * Après suppression d'une base en modèle : retire Deployment/StatefulSet/Service/PVC
     * des namespaces RUNNING.
     */
    public ClusterPruneResponse pruneRemovedDatabase(ManagedApplication realApp, AppDatabase db) {
        if (realApp == null || realApp.getId() == null || db == null) {
            throw new AppValidationException("Application et base requises.");
        }
        if (!k8sManifestApplyService.isConfigured()) {
            return ClusterPruneResponse.builder()
                    .pruned(false)
                    .message("Base retirée du modèle (cluster K8s non configuré).")
                    .build();
        }

        String dbSvcName = connectionUrlService.serviceName(db);
        List<AppDeployment> running = deploymentRepository
                .findByApplication_IdOrderByCreatedAtDesc(realApp.getId()).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING
                        || d.getStatus() == AppDeploymentStatus.DEPLOYING)
                .toList();

        if (running.isEmpty()) {
            return ClusterPruneResponse.builder()
                    .pruned(false)
                    .message("Base retirée du modèle (aucun environnement RUNNING à nettoyer).")
                    .build();
        }

        List<String> namespaces = new ArrayList<>();
        List<String> removed = new ArrayList<>();

        for (AppDeployment deployment : running) {
            String ns = deployment.getNamespace();
            if (ns == null || ns.isBlank() || "pending".equals(ns)) {
                continue;
            }
            try {
                List<String> deleted = k8sManifestApplyService.deleteDatabaseResources(ns, dbSvcName);
                removed.addAll(deleted.stream().map(r -> ns + "/" + r).toList());
                removeFromDatabasesState(deployment, db.getName());
                deploymentRepository.save(deployment);
                namespaces.add(ns);
                log.info("Prune database OK — ns={} db={}", ns, dbSvcName);
            } catch (Exception e) {
                throw new AppValidationException(
                        "Échec nettoyage base sur " + ns + " : " + e.getMessage());
            }
        }

        return ClusterPruneResponse.builder()
                .pruned(!namespaces.isEmpty())
                .namespaces(namespaces)
                .removedResources(removed)
                .message(namespaces.isEmpty()
                        ? "Base retirée du modèle (rien à nettoyer sur le cluster)."
                        : "Base retirée et ressources K8s nettoyées sur "
                        + String.join(", ", namespaces) + ".")
                .build();
    }

    @SuppressWarnings("unchecked")
    private void removeFromServicesState(AppDeployment deployment, String logicalName, String k8sName) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("services") instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> services = (Map<String, Object>) state.get("services");
        services.remove(logicalName);
        services.remove(k8sName);
        // Au cas où la clé stockée diffère légèrement
        new ArrayList<>(services.keySet()).stream()
                .filter(k -> AppNaming.k8sName(k).equals(k8sName))
                .forEach(services::remove);
        deployment.setServicesState(state);
    }

    @SuppressWarnings("unchecked")
    private void removeFromDatabasesState(AppDeployment deployment, String dbName) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("databases") instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> databases = (Map<String, Object>) state.get("databases");
        databases.remove(dbName);
        deployment.setServicesState(state);
    }

    private void removeResolvedImage(AppDeployment deployment, String k8sName) {
        Map<String, String> images = loadResolvedImages(deployment);
        if (images.isEmpty()) {
            return;
        }
        images.remove(k8sName);
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        state.put("resolvedImages", images);
        deployment.setServicesState(state);
    }

    /**
     * Applique les variables d'environnement (et config service) du service sur tous les
     * déploiements RUNNING, sans rebuild CI : Secret + Deployment + rollout restart.
     */
    public RuntimeSyncResponse syncServiceRuntime(ManagedApplication realApp, UUID serviceId) {
        if (realApp == null || realApp.getId() == null) {
            throw new AppValidationException("Application requise.");
        }
        UUID appId = realApp.getId();
        if (!k8sManifestApplyService.isConfigured()) {
            return RuntimeSyncResponse.builder()
                    .synced(false)
                    .message("Cluster K8s non configuré sur le backend.")
                    .build();
        }

        List<AppDeployment> running = deploymentRepository
                .findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING)
                .toList();
        if (running.isEmpty()) {
            return RuntimeSyncResponse.builder()
                    .synced(false)
                    .message("Aucun environnement RUNNING — les variables s'appliqueront au prochain déploiement.")
                    .build();
        }

        List<AppService> allServices = appServiceRepository.findWithEnvVarsByManagedApplication_Id(appId);
        AppService target = allServices.stream()
                .filter(s -> serviceId.equals(s.getId()))
                .findFirst()
                .orElseThrow(() -> new AppValidationException("Service introuvable."));
        List<AppDatabase> databases = databaseRepository.findByApplication_Id(appId);
        String k8sName = AppNaming.k8sName(target.getName());

        List<String> namespaces = new ArrayList<>();
        List<String> restarted = new ArrayList<>();

        for (AppDeployment deployment : running) {
            Map<String, String> images = loadResolvedImages(deployment);
            if (images.isEmpty()) {
                log.warn("Sync runtime ignoré — deployment {} sans images résolues", deployment.getId());
                continue;
            }
            if (!images.containsKey(k8sName)) {
                log.info("Service {} absent du déploiement {} — skip", k8sName, deployment.getNamespace());
                continue;
            }

            ManagedApplication shadow = new ManagedApplication();
            shadow.setId(appId);
            shadow.setName(realApp.getName());
            shadow.setSlug(realApp.getSlug());
        shadow.setCustomHostname(realApp.getCustomHostname());
            shadow.setServices(allServices);
            shadow.setDatabases(databases);

            AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                    deployment.getId(), null, images, realApp);
            // includeIngress=true : met à jour aussi Ingress + Middleware (port, /api, contextPath)
            String yaml = manifestService.generateServiceWaveBundle(
                    shadow, deployment.getNamespace(), opts, List.of(target), true);

            try {
                k8sManifestApplyService.applyManifests(yaml);
                boolean hasSecrets = target.getEnvVars() != null
                        && target.getEnvVars().stream().anyMatch(ServiceEnvVar::isSecret);
                if (!hasSecrets) {
                    k8sManifestApplyService.deleteSecretIfExists(
                            deployment.getNamespace(), k8sName + "-secrets");
                }
                // SSA n'applique souvent pas spec.replicas → scale explicite
                int replicas = target.getReplicas() != null ? target.getReplicas() : 1;
                k8sManifestApplyService.scaleDeployment(
                        deployment.getNamespace(), k8sName, replicas);
                k8sManifestApplyService.restartDeployment(deployment.getNamespace(), k8sName);
                k8sManifestApplyService.waitUntilNamedDeploymentsReady(
                        deployment.getNamespace(), List.of(k8sName));
                namespaces.add(deployment.getNamespace());
                restarted.add(k8sName);
                log.info("Runtime sync OK — ns={} service={} replicas={} (ingress inclus)",
                        deployment.getNamespace(), k8sName, replicas);
            } catch (Exception e) {
                throw new AppValidationException(
                        "Échec sync runtime sur " + deployment.getNamespace() + " : " + e.getMessage());
            }
        }

        if (namespaces.isEmpty()) {
            return RuntimeSyncResponse.builder()
                    .synced(false)
                    .message("Service non présent dans les environnements RUNNING (redéploiement complet requis).")
                    .build();
        }

        int replicas = target.getReplicas() != null ? target.getReplicas() : 1;
        return RuntimeSyncResponse.builder()
                .synced(true)
                .namespaces(namespaces)
                .restartedServices(restarted)
                .message("Config appliquée sur " + String.join(", ", namespaces)
                        + " (env, port, replicas=" + replicas + ", Ingress) — pods synchronisés.")
                .build();
    }

    /**
     * Réapplique l'Ingress des déploiements RUNNING avec le hostname custom (ou nip.io).
     */
    public RuntimeSyncResponse syncIngressHostname(ManagedApplication realApp) {
        if (realApp == null || realApp.getId() == null) {
            throw new AppValidationException("Application requise.");
        }
        if (!k8sManifestApplyService.isConfigured()) {
            return RuntimeSyncResponse.builder()
                    .synced(false)
                    .message("Cluster K8s non configuré.")
                    .build();
        }
        UUID appId = realApp.getId();
        List<AppDeployment> running = deploymentRepository
                .findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING)
                .toList();
        if (running.isEmpty()) {
            return RuntimeSyncResponse.builder()
                    .synced(false)
                    .message("Aucun environnement RUNNING — le domaine s'appliquera au prochain déploiement.")
                    .build();
        }

        List<AppService> allServices = appServiceRepository.findWithEnvVarsByManagedApplication_Id(appId);
        List<AppDatabase> databases = databaseRepository.findByApplication_Id(appId);
        List<String> namespaces = new ArrayList<>();

        for (AppDeployment deployment : running) {
            Map<String, String> images = loadResolvedImages(deployment);
            if (images.isEmpty()) {
                continue;
            }
            ManagedApplication shadow = new ManagedApplication();
            shadow.setId(appId);
            shadow.setName(realApp.getName());
            shadow.setSlug(realApp.getSlug());
        shadow.setCustomHostname(realApp.getCustomHostname());
            shadow.setCustomHostname(realApp.getCustomHostname());
            shadow.setServices(allServices);
            shadow.setDatabases(databases);

            AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                    deployment.getId(), null, images, shadow);
            String yaml = manifestService.generateIngressBundle(shadow, deployment.getNamespace(), opts);
            if (yaml == null || yaml.isBlank()) {
                continue;
            }
            try {
                k8sManifestApplyService.applyManifests(yaml);
                // Met à jour externalUrl dans servicesState
                Map<String, Object> state = deployment.getServicesState();
                if (state != null && state.get("services") instanceof Map<?, ?> servicesRaw) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> services = (Map<String, Object>) servicesRaw;
                    for (AppService svc : allServices) {
                        Object row = services.get(svc.getName());
                        if (row instanceof Map<?, ?> m) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> svcState = (Map<String, Object>) m;
                            svcState.put("externalUrl", ingressServiceUrl(deployment.getNamespace(), svc, shadow));
                        }
                    }
                    deployment.setServicesState(state);
                    deploymentRepository.save(deployment);
                }
                namespaces.add(deployment.getNamespace());
            } catch (Exception e) {
                throw new AppValidationException(
                        "Échec sync Ingress sur " + deployment.getNamespace() + " : " + e.getMessage());
            }
        }

        String host = normalizeCustomHostnameSafe(realApp.getCustomHostname());
        return RuntimeSyncResponse.builder()
                .synced(!namespaces.isEmpty())
                .namespaces(namespaces)
                .message(namespaces.isEmpty()
                        ? "Aucun Ingress à mettre à jour."
                        : "Ingress mis à jour (" + (host != null ? host : "nip.io") + ") sur "
                        + String.join(", ", namespaces) + ". Pointez le DNS A/CNAME vers l'IP Traefik.")
                .build();
    }
}
