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

    private final ExecutorService ciDeployExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ci-deploy-worker");
        t.setDaemon(true);
        return t;
    });

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
                deployment.getId(), resolved.ttlHours(), null);

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
                deployment.getId(), resolved.ttlHours(), null);

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
     */
    @Transactional
    public AppDeployment teardown(AppDeployment deployment) {
        if (k8sManifestApplyService.isConfigured()) {
            try {
                k8sManifestApplyService.deleteNamespace(deployment.getNamespace());
            } catch (Exception e) {
                throw new AppValidationException("Échec suppression namespace K8s : " + e.getMessage());
            }
            deployment.setStatus(AppDeploymentStatus.STOPPED);
            return deploymentRepository.save(deployment);
        }

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
        markServicesDeploying(deployment);
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
                    deployment.getId(), ttlHours, validatedImages);

            String databasesYaml = manifestService.generateDatabaseBundle(shadow, namespace, opts);
            Map<Integer, List<AppService>> waves = computeWaves(shadow);
            List<Integer> waveOrder = new ArrayList<>(waves.keySet());
            Collections.sort(waveOrder);
            List<ServiceWaveManifest> serviceWaves = new ArrayList<>();
            for (int i = 0; i < waveOrder.size(); i++) {
                List<AppService> waveServices = waves.get(waveOrder.get(i));
                boolean lastWave = i == waveOrder.size() - 1;
                String waveYaml = manifestService.generateServiceWaveBundle(
                        shadow, namespace, opts, waveServices, lastWave);
                List<String> depNames = waveServices.stream()
                        .map(s -> AppNaming.k8sName(s.getName()))
                        .toList();
                serviceWaves.add(new ServiceWaveManifest(waveYaml, depNames));
            }

            return new PreparedCiDeploy(
                    deployment,
                    shadow,
                    environmentId,
                    validatedImages,
                    databasesYaml,
                    !shadow.getDatabases().isEmpty(),
                    serviceWaves);
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

            k8sManifestApplyService.applyManifests(prepared.databasesYaml());
            markDatabasesDeploying(deployment);

            if (prepared.waitForDatabases()) {
                k8sManifestApplyService.waitUntilDatabasesReady(namespace);
            }

            for (ServiceWaveManifest wave : prepared.serviceWaves()) {
                k8sManifestApplyService.applyManifests(wave.yaml());
                k8sManifestApplyService.waitUntilNamedDeploymentsReady(namespace, wave.deploymentNames());
            }

        } catch (Exception e) {
            log.error("CI deploy async échoué — deployment={}: {}", deploymentId, e.getMessage(), e);
            handleCiDeployFailure(deployment, environmentId, namespace, e.getMessage());
            return;
        }

        deployment.setStatus(AppDeploymentStatus.DEPLOYING);
        deployment.setDeployedAt(Instant.now());
        markServicesDeploying(deployment);
        transactionTemplate.executeWithoutResult(status -> deploymentRepository.save(deployment));

        if (environmentId != null) {
            String appUrl = resolvePublicUrl(deployment, shadow);
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

    private record ServiceWaveManifest(String yaml, List<String> deploymentNames) {}

    private record PreparedCiDeploy(
            AppDeployment deployment,
            ManagedApplication shadow,
            UUID environmentId,
            Map<String, String> resolvedImages,
            String databasesYaml,
            boolean waitForDatabases,
            List<ServiceWaveManifest> serviceWaves
    ) {}

    @Transactional
    public Map<String, Object> getCiDeployStatus(UUID deploymentId) {
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable"));

        if (deployment.getStatus() == AppDeploymentStatus.FAILED) {
            return ciStatusResponse(deployment, false, "FAILED", "Déploiement en échec");
        }

        String namespace = deployment.getNamespace();

        // Ne pas déclarer SUCCESS tant que l'apply async n'a pas terminé (deployedAt null).
        // Sinon le pipeline peut réussir alors que l'Ingress échoue encore → rollback ensuite.
        if (deployment.getDeployedAt() == null
                && deployment.getStatus() == AppDeploymentStatus.DEPLOYING) {
            return ciStatusResponse(deployment, false, "DEPLOYING", "Apply Kubernetes en cours");
        }

        ManagedApplication realApp = deployment.getApplication();
        ManagedApplication shadow = buildShadowForDeployment(deployment, realApp);

        boolean ready = k8sManifestApplyService.isConfigured()
                && namespace != null
                && !namespace.isBlank()
                && k8sManifestApplyService.areAllDeploymentsReady(namespace);

        if (ready) {
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            markServicesReady(deployment);
            UUID environmentId = resolveEnvironmentId(null, deployment);
            String appUrl = resolvePublicUrl(deployment, shadow);
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
            return ciStatusResponse(deployment, true, "SUCCESS", "Application prête");
        }

        if (isDeployTimedOut(deployment)) {
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

        if (deployment.getStatus() != AppDeploymentStatus.DEPLOYING
                && deployment.getStatus() != AppDeploymentStatus.RUNNING) {
            deployment.setStatus(AppDeploymentStatus.DEPLOYING);
            deploymentRepository.save(deployment);
        }

        return ciStatusResponse(deployment, false, "DEPLOYING", "Déploiement en cours — pods pas encore prêts");
    }

    private Map<String, Object> ciStatusResponse(
            AppDeployment deployment,
            boolean ready,
            String state,
            String message
    ) {
        ManagedApplication shadow = buildShadowForDeployment(deployment, deployment.getApplication());
        String appUrl = resolvePublicUrl(deployment, shadow);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", state);
        out.put("ready", ready);
        if (appUrl != null) {
            out.put("appUrl", appUrl);
        }
        out.put("namespace", deployment.getNamespace());
        out.put("message", message);
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
        resolvedImages.clear();
        Set<String> knownServices = shadow.getServices().stream()
                .map(service -> AppNaming.k8sName(service.getName()))
                .collect(java.util.stream.Collectors.toSet());
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
            String previous = resolvedImages.put(serviceName, image);
            if (previous != null) {
                throw new AppValidationException(
                        "Collision de noms de services après normalisation: " + rawServiceName);
            }
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
        if (deployment.getDeployedAt() == null) {
            return false;
        }
        long elapsedMs = Instant.now().toEpochMilli() - deployment.getDeployedAt().toEpochMilli();
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
        return AppK8sManifestService.ManifestOptions.builder()
                .registryServer(registryServer)
                .registryUsername(registryUsername)
                .registryPassword(registryPassword)
                .pullSecretName(pullSecretName)
                .ingressEnabled(ingressEnabled)
                .ingressDomain(ingressDomain)
                .pathBasedRouting(pathBasedRouting)
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
            return "http://app-" + deployment.getNamespace() + "." + ingressDomain;
        }
        if (nipPreviewEnabled && nipMasterIp != null && !nipMasterIp.isBlank()) {
            String scheme = nipScheme != null && !nipScheme.isBlank() ? nipScheme.trim().toLowerCase() : "http";
            String id = deployment.getId().toString().toLowerCase();
            return scheme + "://app-" + id + "." + nipMasterIp.trim() + ".nip.io";
        }
        if (!shadow.getServices().isEmpty() && ingressEnabled) {
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
        if (pathBasedRouting) {
            String base = "http://app-" + namespace + "." + ingressDomain;
            AppService primary = findPrimaryExposed(app);
            if (primary != null && java.util.Objects.equals(svc.getId(), primary.getId())) {
                return base;
            }
            return base + "/" + AppNaming.k8sName(svc.getName());
        }
        return "http://" + AppNaming.k8sName(svc.getName()) + "-" + namespace + "." + ingressDomain;
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
