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
import org.springframework.context.annotation.Lazy;
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
    /** @Lazy : casse le cycle avec DeploymentRuntimeAlertService → ApplicationManagementService → AppDeploymentService. */
    @Lazy
    private final DeploymentRuntimeAlertService deploymentRuntimeAlertService;

    /**
     * Cycle direct ApplicationManagementService ↔ AppDeploymentService : injection par champ
     * (pas via le constructeur @RequiredArgsConstructor) car Lombok ne recopie pas @Lazy sur le
     * paramètre généré ici — seule l'injection @Autowired @Lazy sur le champ brise le cycle.
     */
    @org.springframework.beans.factory.annotation.Autowired
    @Lazy
    private ApplicationManagementService applicationManagementService;

    /** Pool pour applies CI concurrents (plusieurs apps / rebuilds en parallèle). */
    private ExecutorService ciDeployExecutor;

    @Value("${deployment.ci-deploy.pool-size:4}")
    private int ciDeployPoolSize;

    @Value("${deployment.registry.server:registry.gitlab.com}")
    private String registryServer;

    @Value("${deployment.registry.username:oauth2}")
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

    /**
     * Domaine perso automatique : une app SANS "Domaine personnalisé" explicite obtient
     * <slug-app>.<ce-domaine> automatiquement — plus besoin de le taper à chaque déploiement.
     * Vide = comportement d'origine (fallback nip.io).
     */
    @Value("${deployment.ingress.custom-base-domain:}")
    private String customBaseDomain;

    /** Schéma des URLs pour un hostname personnalisé (auto ou tapé) — https par défaut. */
    @Value("${deployment.ingress.custom-scheme:https}")
    private String customHostnameScheme;

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

    @Value("${deployment.network-policy.enabled:true}")
    private boolean networkPolicyEnabled;

    @Value("${deployment.network-policy.ingress-namespace:kube-system}")
    private String networkPolicyIngressNamespace;

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
        // Sous-ensemble de services → vue mémoire (shadow) ; FK déploiement reste sur le vrai projet.
        ManagedApplication target = resolved.hasServiceFilter()
                ? validationService.buildShadow(app, resolved.serviceIdsOrEmpty())
                : app;

        List<String> warnings = validationService.validate(target);
        warnings.forEach(w -> log.info("⚠️ [deploy {}] {}", app.getId(), w));

        AppService gitService = target.getServices().stream().findFirst()
                .orElseThrow(() -> new AppValidationException("Aucun service dans le projet."));
        String deployBranch = resolved.resolveBranch(gitService.getGitBranch());

        // Un déploiement RUNNING de cette MÊME app sur cette MÊME branche devient orphelin dès
        // qu'on en recrée un nouveau : l'ancien garde le même hostname auto-généré (<slug> ou
        // <slug>-<branche>), plus aucun bouton dans l'UI ne peut plus l'arrêter (elle ne pilote
        // que app.lastDeployment), et Traefik tranche de façon non déterministe entre les deux
        // Ingress qui réclament le même host — l'app "marche" par intermittence selon celui qui
        // gagne. On le remplace donc proprement ici, plutôt que de le laisser tourner en double
        // pour rien (bug réel constaté le 18 août 2026, cf. audit-deploiement.md §8). Toujours
        // le MÊME propriétaire (même app) : jamais l'environnement d'un autre utilisateur.
        deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(app.getId()).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING)
                .filter(d -> sameBranch(deployBranch, resolveDeploymentBranch(d.getId())))
                .forEach(old -> {
                    log.info("deploy({}) : remplace le déploiement RUNNING existant {} (même branche {})",
                            app.getId(), old.getId(), deployBranch);
                    try {
                        teardown(old);
                    } catch (Exception e) {
                        log.warn("Teardown de l'ancien déploiement {} avant redeploy : {}",
                                old.getId(), e.getMessage());
                    }
                });

        AppDeployment deployment = new AppDeployment();
        deployment.setApplication(app);
        deployment.setStatus(AppDeploymentStatus.PENDING);
        deployment.setNamespace("pending");
        deployment = deploymentRepository.save(deployment); // obtient l'id → namespace stable

        String namespace = AppNaming.namespace(app.getSlug(), deployment.getId());
        deployment.setNamespace(namespace);

        // §3.1 : générer et stocker les URLs de connexion des bases.
        for (AppDatabase db : target.getDatabases()) {
            db.setGeneratedConnectionUrl(connectionUrlService.buildConnectionUrl(db, namespace));
            databaseRepository.save(db);
        }

        String imageTag = AppNaming.shortId(deployment.getId());
        AppK8sManifestService.ManifestOptions opts = buildManifestOptions(
                deployment.getId(), resolved.ttlHours(), null, app, deployBranch);

        // Les services sont générés après le build, lorsque toutes les images sont résolues.
        String databasesB64 = b64(manifestService.generateDatabaseBundle(target, namespace, opts));
        String servicesB64 = "";

        Map<Integer, List<AppService>> waves = computeWaves(target);
        String servicesJson = buildServicesJson(target, waves, imageTag);

        deployment.setServicesState(buildInitialState(target, namespace, waves, resolved.ttlHours()));

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "deploy");
        // Sans ça, deploy:defectdojo-import (.gitlab-ci.yml) ne tourne jamais (rules exige
        // DD_IMPORT_ENABLED=true, défaut "false" dans le fichier) -- ZAP + Grype du flux deploy
        // ne remontaient jamais dans DefectDojo. Passé au déclenchement plutôt qu'écrit dans le
        // fichier (convention du projet : .gitlab-ci.yml n'est pas modifié par l'outil).
        variables.put("DD_IMPORT_ENABLED", "true");
        variables.put("APP_ID", app.getId().toString());
        variables.put("APP_SLUG", app.getSlug());
        variables.put("DEPLOYMENT_ID", deployment.getId().toString());
        variables.put("SERVICE_NAME", AppNaming.k8sName(gitService.getName()));
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
        // Déploiement multi-services : gitService n'est que le "1er service de la liste", pas
        // forcément le seul déployé (target.getServices() peut en contenir plusieurs -- toutes
        // partagent le même pipelineId/namespace/environnement, un seul pipeline GitLab pour
        // toute l'app). Sans cette boucle, seul gitService recevait une PipelineExecution DEPLOY
        // -- les autres services (ex. "back" quand gitService="front") n'avaient alors JAMAIS
        // d'environnement de déploiement associé : leur page Quality Gate / Post-déploiement
        // restait bloquée sur leur dernier SCAN, indéfiniment, même après de multiples
        // redéploiements de l'app entière (bug réel constaté le 28 août 2026, aoo 1).
        for (AppService svc : target.getServices()) {
            if (svc.getId().equals(gitService.getId())) {
                continue;
            }
            String svcBranch = resolved.resolveBranch(svc.getGitBranch());
            linkDeployPipelineExecution(svc, env, pipelineId, svcBranch, false);
        }

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
        variables.put("DD_IMPORT_ENABLED", "true"); // voir commentaire au 1er site d'appel
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
     * Résumé Grype (scan de l'image construite) poussé par le job deploy:grype-scan — stocké
     * dans servicesState pour affichage plateforme (audit-deploiement.md, chantier #9).
     */
    @SuppressWarnings("unchecked")
    public void applyContainerScanCallback(
            UUID deploymentId,
            com.backend.devsecopsplatform_backend.controller.appmgmt.ContainerScanCallbackRequest request
    ) {
        AppDeployment deployment = deploymentRepository.findById(deploymentId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        Map<String, Object> scan = new LinkedHashMap<>();
        scan.put("critical", request.getCritical() != null ? request.getCritical() : 0);
        scan.put("high", request.getHigh() != null ? request.getHigh() : 0);
        scan.put("medium", request.getMedium() != null ? request.getMedium() : 0);
        scan.put("low", request.getLow() != null ? request.getLow() : 0);
        scan.put("imageName", request.getImageName());
        scan.put("checkedAt", Instant.now().toString());
        state.put("containerScan", scan);
        deployment.setServicesState(state);
        deploymentRepository.save(deployment);
        log.info("Container scan (Grype) enregistré — deployment={} critical={} high={}",
                deploymentId, scan.get("critical"), scan.get("high"));
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
            // onRetryScheduled (pas onBuilding) : un retry GitLab sur un job échoué réutilise le
            // même environnement/namespace, potentiellement déjà FAILED en base — voir le
            // commentaire de la méthode pour la race trouvée en direct le 4 septembre 2026.
            environmentLifecycleService.onRetryScheduled(environmentId);
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

        boolean hasIngressStep = prepared.ingressYaml() != null && !prepared.ingressYaml().isBlank();
        initDeploySteps(deployment, prepared.waitForDatabases(), prepared.serviceWaves(), hasIngressStep);

        try {
            setDeployPhase(deployment, "Préparation du namespace");
            k8sManifestApplyService.ensureNamespaceReadyForApply(namespace);
            advanceDeployStep(deployment, "namespace");

            if (!prepared.partialRebuild()) {
                setDeployPhase(deployment, "Bases de données — apply");
                k8sManifestApplyService.applyManifests(prepared.databasesYaml());
                markDatabasesDeploying(deployment);

                if (prepared.waitForDatabases()) {
                    setDeployPhase(deployment, "Bases de données — en attente Ready");
                    k8sManifestApplyService.waitUntilDatabasesReady(namespace);
                    advanceDeployStep(deployment, "databases");
                }
                setDeployPhase(deployment, "Bases de données prêtes");
            }

            int waveCount = prepared.serviceWaves().size();
            int waveIdx = 0;
            for (ServiceWaveManifest wave : prepared.serviceWaves()) {
                waveIdx++;
                setDeployPhase(deployment, "Vague " + waveIdx + "/" + waveCount + " — apply");
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
                setDeployPhase(deployment, "Vague " + waveIdx + "/" + waveCount + " — en attente Ready");
                k8sManifestApplyService.waitUntilNamedDeploymentsReady(namespace, wave.deploymentNames());
                setDeployPhase(deployment, "Vague " + waveIdx + "/" + waveCount + " prête");
                advanceDeployStep(deployment, "wave-" + waveIdx);
            }

            // Ingress / Middleware après Ready — soft-fail si CRD Traefik bloque
            if (hasIngressStep) {
                setDeployPhase(deployment, "Ingress — apply");
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
                setDeployPhase(deployment, ingressOk ? "Terminé — Ingress appliqué" : "Terminé — Ingress indisponible (non bloquant)");
                advanceDeployStep(deployment, "ingress");
            } else {
                // Bundle Ingress vide : soit rien à exposer (déploiement worker-only -- cas
                // normal, pas un échec), soit l'Ingress est globalement désactivé. Avant, un
                // déploiement sans aucun FRONTEND/BACKEND exposé était marqué ingressApplied=false
                // en permanence (pas d'Ingress généré par construction, cf. applicationIngress) --
                // ça déclenchait côté front un faux "Ingress non appliqué" ET masquait tout le
                // bandeau live (TTL + boutons Prolonger), ingressBroken() dépendant du même flag.
                boolean nothingToExpose = !hasExternallyExposedService(shadow);
                boolean applied = !ingressEnabled || nothingToExpose;
                persistIngressState(deployment, applied, applied ? null : "Bundle Ingress vide");
                setDeployPhase(deployment, "Terminé");
            }

        } catch (Exception e) {
            markCurrentDeployStepFailed(deployment);
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
            boolean firstReady = deployment.getDeployedAt() == null;
            if (firstReady) {
                deployment.setDeployedAt(Instant.now());
            }
            deployment.setStatus(AppDeploymentStatus.RUNNING);
            markServicesReady(deployment);
            clearPendingRebuild(deployment);
            deploymentRepository.save(deployment);
            // Retenter tant qu'aucun résultat n'est encore écrit (pas seulement au 1er "ready") --
            // runSmokeTest() ne fait rien si aucun service n'a encore d'externalUrl (Ingress
            // appliqué APRÈS readiness, en soft-fail -- markServicesReady() peut retomber sur
            // ingressOk=false à ce tick précis et mettre externalUrl à null). Avec le déclenchement
            // limité à "firstReady", ce cas de figure faisait échouer le smoke test en silence,
            // pour toujours, sur ce déploiement (constaté le 24 et 27 août 2026 : servicesState
            // sans clé "smokeTest" du tout). deploy:trigger-backend (.gitlab-ci.yml) continue de
            // toute façon à sonder ce endpoint tant que appUrl est vide, donc ça retente à chaque
            // poll suivant jusqu'à ce qu'Ingress soit prêt, sans appel GitLab supplémentaire.
            if (!hasSmokeTestResult(deployment)) {
                try {
                    runSmokeTest(deployment, shadow);
                } catch (Exception smokeEx) {
                    log.debug("Smoke test post-déploiement non exécuté: {}", smokeEx.getMessage());
                }
            }
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

    /** Même règle que AppK8sManifestService#applicationIngress (FRONTEND/BACKEND + port exposé) --
     * si rien ne matche, un bundle Ingress vide est normal, pas un échec. */
    private boolean hasExternallyExposedService(ManagedApplication app) {
        return app.getServices().stream()
                .anyMatch(s -> AppServiceRules.isExternallyExposed(s.getRole()) && s.getExposedPort() != null);
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
                boolean nothingToExpose = !hasExternallyExposedService(shadow);
                persistIngressState(deployment, nothingToExpose,
                        nothingToExpose ? null : "Bundle Ingress vide au retry");
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
        if (svcState != null && svcState.get("deployPhase") != null) {
            out.put("deployPhase", svcState.get("deployPhase"));
        }
        return out;
    }

    /** Un résultat de smoke test (même en échec) a déjà été écrit pour ce déploiement. */
    private boolean hasSmokeTestResult(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        return state != null && state.get("smokeTest") != null;
    }

    /**
     * Smoke test post-déploiement : sonde une fois l'URL publique de chaque service exposé,
     * dès que l'environnement passe Ready (audit-deploiement.md, chantier #8). Réutilise le
     * même probe HTTP que le health check du Monitoring (résolution ingress/.local incluse) —
     * best-effort, ne doit jamais faire échouer le passage à RUNNING.
     */
    @SuppressWarnings("unchecked")
    private void runSmokeTest(AppDeployment deployment, ManagedApplication shadow) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("services") instanceof Map<?, ?> servicesRaw)) {
            return;
        }
        Map<String, Object> results = new LinkedHashMap<>();
        boolean allOk = true;
        boolean anyChecked = false;
        for (Map.Entry<?, ?> e : servicesRaw.entrySet()) {
            String name = String.valueOf(e.getKey());
            if (!(e.getValue() instanceof Map)) {
                continue;
            }
            Map<String, Object> svc = (Map<String, Object>) e.getValue();
            Object urlObj = svc.get("externalUrl");
            String url = urlObj != null ? String.valueOf(urlObj).trim() : "";
            if (url.isBlank()) {
                continue;
            }
            Map<String, Object> health = applicationManagementService.probeHttpHealth(url, null);
            anyChecked = true;
            Map<String, Object> probe = new LinkedHashMap<>();
            boolean ok = Boolean.TRUE.equals(health.get("ok"));
            probe.put("ok", ok);
            probe.put("statusCode", health.get("statusCode"));
            probe.put("message", health.get("message"));
            probe.put("probedUrl", health.get("probedUrl") != null ? health.get("probedUrl") : url);
            results.put(name, probe);
            if (!ok) {
                allOk = false;
            }
        }
        if (!anyChecked) {
            return;
        }
        Map<String, Object> smoke = new LinkedHashMap<>();
        smoke.put("checkedAt", Instant.now().toString());
        smoke.put("allOk", allOk);
        smoke.put("results", results);
        state.put("smokeTest", smoke);
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
        log.info("Smoke test post-déploiement — ns={} allOk={} services={}",
                deployment.getNamespace(), allOk, results.keySet());
    }

    private AppDeployment requireRunningDeployment(ManagedApplication realApp, UUID serviceId, String actionLabel) {
        if (realApp == null || realApp.getId() == null) {
            throw new AppValidationException("Application requise.");
        }
        boolean hasService = realApp.getServices().stream().anyMatch(s -> serviceId.equals(s.getId()));
        if (!hasService) {
            throw new AppValidationException("Service introuvable dans ce projet.");
        }
        return deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(realApp.getId()).stream()
                .filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING)
                .findFirst()
                .orElseThrow(() -> new AppValidationException(
                        "Aucun environnement RUNNING — impossible de relancer le " + actionLabel + "."));
    }

    /**
     * Relance manuelle du smoke test (Objectif 3, post-deploy §5 : bouton "Relancer" sans
     * restriction, coût quasi nul) — contourne délibérément hasSmokeTestResult(), qui n'existe
     * QUE pour éviter de re-sonder à chaque poll automatique de deploy:trigger-backend pendant les
     * ~5 min où le CI attend RUNNING (voir commentaire au 1er site d'appel, ligne ~953). Un
     * déclenchement manuel explicite n'a pas cette contrainte : c'est exactement le comportement
     * que corrige cet objectif (avant : un seul résultat enregistré, jamais rafraîchi ensuite).
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> rerunSmokeTestForService(ManagedApplication realApp, UUID serviceId) {
        AppDeployment deployment = requireRunningDeployment(realApp, serviceId, "smoke test");
        ManagedApplication shadow = buildShadowForDeployment(deployment, deployment.getApplication());
        runSmokeTest(deployment, shadow);
        Map<String, Object> state = deployment.getServicesState();
        Object smoke = state != null ? state.get("smokeTest") : null;
        if (smoke == null) {
            throw new AppValidationException(
                    "Aucun service n'a d'URL publique sur ce déploiement — rien à sonder.");
        }
        return (Map<String, Object>) smoke;
    }

    /**
     * Progression fine pendant l'apply K8s (namespace → BD → vague N/total → ingress), exposée
     * via getCiDeployStatus()/getDeployment() pour que la page pipeline n'affiche plus une boîte
     * noire pendant les ~5 min de polling de deploy:trigger-backend (audit-deploiement.md, #6).
     */
    @SuppressWarnings("unchecked")
    private void setDeployPhase(AppDeployment deployment, String phase) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        state.put("deployPhase", phase);
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
    }

    /**
     * Liste ordonnée des étapes de déploiement (namespace → BD → vague N → ingress), chacune avec
     * son statut (pending/running/done/failed) et — pour les vagues — les services concernés.
     * Complète {@code deployPhase} (texte fin, une phrase à la fois) par une checklist stable que
     * la page pipeline peut afficher sans avoir à parser du texte (audit-deploiement.md, retour
     * utilisateur du 17 août 2026 : « liste les services qui vont être faits un après l'autre »).
     */
    @SuppressWarnings("unchecked")
    private void initDeploySteps(AppDeployment deployment, boolean includeDatabases,
                                  List<ServiceWaveManifest> waves, boolean includeIngress) {
        List<Map<String, Object>> steps = new ArrayList<>();
        steps.add(deployStepOf("namespace", "Namespace", null));
        if (includeDatabases) {
            steps.add(deployStepOf("databases", "Bases de données", null));
        }
        for (int i = 0; i < waves.size(); i++) {
            int waveNo = i + 1;
            steps.add(deployStepOf("wave-" + waveNo, "Vague " + waveNo + "/" + waves.size(),
                    waves.get(i).deploymentNames()));
        }
        if (includeIngress) {
            steps.add(deployStepOf("ingress", "Ingress (URL publique)", null));
        }
        if (!steps.isEmpty()) {
            steps.get(0).put("status", "running");
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state == null) {
            state = new LinkedHashMap<>();
        }
        state.put("deploySteps", steps);
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
    }

    private Map<String, Object> deployStepOf(String key, String label, List<String> services) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        if (services != null && !services.isEmpty()) {
            m.put("services", services);
        }
        m.put("status", "pending");
        return m;
    }

    /** Marque une étape "done" et promeut la suivante en "running". */
    @SuppressWarnings("unchecked")
    private void advanceDeployStep(AppDeployment deployment, String completedKey) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("deploySteps") instanceof List<?> rawList)) {
            return;
        }
        boolean justCompleted = false;
        for (Object o : rawList) {
            if (!(o instanceof Map<?, ?> mRaw)) continue;
            Map<String, Object> m = (Map<String, Object>) mRaw;
            if (completedKey.equals(m.get("key"))) {
                m.put("status", "done");
                justCompleted = true;
            } else if (justCompleted && "pending".equals(m.get("status"))) {
                m.put("status", "running");
                justCompleted = false;
            }
        }
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
    }

    /** En cas d'erreur : marque l'étape en cours (running, ou 1ère pending à défaut) "failed". */
    @SuppressWarnings("unchecked")
    private void markCurrentDeployStepFailed(AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("deploySteps") instanceof List<?> rawList)) {
            return;
        }
        Map<String, Object> target = null;
        for (Object o : rawList) {
            if (!(o instanceof Map<?, ?> mRaw)) continue;
            Map<String, Object> m = (Map<String, Object>) mRaw;
            if ("running".equals(m.get("status"))) {
                target = m;
                break;
            }
            if (target == null && "pending".equals(m.get("status"))) {
                target = m;
            }
        }
        if (target == null) {
            return;
        }
        target.put("status", "failed");
        deployment.setServicesState(state);
        transactionTemplate.executeWithoutResult(s -> deploymentRepository.save(deployment));
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
        } else if (deployment.getDeployedAt() != null) {
            start = deployment.getDeployedAt();
        } else {
            // Re-trigger CI remet deployedAt=null : chrono depuis updatedAt (passage DEPLOYING),
            // pas createdAt (sinon timeout immédiat sur retry du même deploymentId).
            start = deployment.getUpdatedAt() != null
                    ? deployment.getUpdatedAt()
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
        // Résout la branche depuis le déploiement déjà persisté (sync/rebuild/reapply sur un
        // déploiement EXISTANT) — indisponible pour un tout nouveau deploy() dont l'environnement
        // n'existe pas encore à cet instant, cf. l'overload avec branche explicite ci-dessous.
        return buildManifestOptions(deploymentId, ttlHours, resolvedImages, app,
                resolveDeploymentBranch(deploymentId));
    }

    /** Variante avec branche explicite — utilisée par {@code deploy()} avant que l'environnement existe. */
    private AppK8sManifestService.ManifestOptions buildManifestOptions(
            UUID deploymentId,
            Integer ttlHours,
            Map<String, String> resolvedImages,
            ManagedApplication app,
            String branch
    ) {
        String customHost = effectiveCustomHostname(app, branch);
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
                .networkPolicyEnabled(networkPolicyEnabled)
                .networkPolicyIngressNamespace(networkPolicyIngressNamespace)
                .build();
    }

    /**
     * Hostname personnalisé effectif d'une app : celui tapé explicitement s'il existe (validé,
     * lève une erreur si invalide, jamais suffixé par la branche — l'utilisateur l'a choisi
     * volontairement), sinon <slug>.<custom-base-domain> généré automatiquement si ce domaine de
     * base est configuré, sinon {@code null} (fallback nip.io inchangé).
     *
     * <p>Le hostname auto-généré est suffixé par la branche quand elle diffère de la branche de
     * référence de l'app (celle du premier service) — deux déploiements RUNNING de branches
     * différentes de la même app obtiennent ainsi deux URLs distinctes au lieu d'entrer en
     * collision sur <slug>.<domaine> (bug réel constaté le 18 août 2026 : deux environnements
     * RUNNING simultanés, un seul Ingress "gagne" côté Traefik de façon non déterministe, l'autre
     * tourne en double pour rien sans jamais être joignable de façon fiable).</p>
     */
    private String effectiveCustomHostname(ManagedApplication app, String branch) {
        if (app == null) {
            return null;
        }
        String raw = app.getCustomHostname();
        if (raw != null && !raw.isBlank()) {
            return normalizeCustomHostname(raw);
        }
        if (customBaseDomain != null && !customBaseDomain.isBlank()
                && app.getSlug() != null && !app.getSlug().isBlank()) {
            String slug = AppNaming.k8sName(app.getSlug());
            String suffix = branchSuffix(app, branch);
            return slug + suffix + "." + customBaseDomain.trim().toLowerCase();
        }
        return null;
    }

    /** Compat : sans branche connue → pas de suffixe (comportement historique). */
    private String effectiveCustomHostname(ManagedApplication app) {
        return effectiveCustomHostname(app, null);
    }

    /** Variante non bloquante de {@link #effectiveCustomHostname} — jamais d'exception. */
    private String effectiveCustomHostnameSafe(ManagedApplication app) {
        return effectiveCustomHostnameSafe(app, null);
    }

    private String effectiveCustomHostnameSafe(ManagedApplication app, String branch) {
        try {
            return effectiveCustomHostname(app, branch);
        } catch (AppValidationException e) {
            return null;
        }
    }

    /**
     * "-" + slug DNS-safe de la branche, vide si {@code branch} est vide/inconnue ou correspond
     * à la branche de référence de l'app (premier service — même logique de fallback que
     * {@code ManagedDeployOptions.resolveBranch}). Ne lève jamais.
     */
    private String branchSuffix(ManagedApplication app, String branch) {
        if (branch == null || branch.isBlank()) {
            return "";
        }
        String reference = app.getServices() != null ? app.getServices().stream()
                .findFirst()
                .map(AppService::getGitBranch)
                .orElse(null) : null;
        if (reference != null && reference.equalsIgnoreCase(branch.trim())) {
            return "";
        }
        String slug = branchSlug(branch);
        return slug.isEmpty() ? "" : "-" + slug;
    }

    /** DNS-label-safe : minuscules, non-alphanumérique → "-", tronqué à 20 caractères. */
    private static String branchSlug(String branch) {
        String s = branch.trim().toLowerCase().replaceAll("[^a-z0-9]+", "-")
                .replaceAll("^-+|-+$", "");
        return s.length() > 20 ? s.substring(0, 20) : s;
    }

    /** Comparaison prudente : jamais "égales" si l'une des deux branches est inconnue (null). */
    private static boolean sameBranch(String a, String b) {
        return a != null && b != null && a.trim().equalsIgnoreCase(b.trim());
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

    /**
     * Branche connue d'un déploiement déjà persisté (via son EphemeralEnvironment) — pour que les
     * flux qui réappliquent l'Ingress d'un déploiement EXISTANT (sync service, rebuild, TTL…)
     * régénèrent le MÊME hostname que celui utilisé au déploiement initial, plutôt que de revenir
     * silencieusement à l'URL sans suffixe. Best-effort : {@code null} si indisponible.
     */
    private String resolveDeploymentBranch(UUID deploymentId) {
        if (deploymentId == null) {
            return null;
        }
        try {
            return deploymentRepository.findById(deploymentId)
                    .map(AppDeployment::getEphemeralEnvironmentId)
                    .flatMap(environmentRepository::findById)
                    .map(EphemeralEnvironment::getGitBranch)
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    /** Même chose que {@link #resolveDeploymentBranch(UUID)}, à partir du namespace. */
    private String resolveBranchByNamespace(String namespace) {
        if (namespace == null || namespace.isBlank()) {
            return null;
        }
        try {
            return deploymentRepository.findByNamespace(namespace)
                    .map(AppDeployment::getEphemeralEnvironmentId)
                    .flatMap(environmentRepository::findById)
                    .map(EphemeralEnvironment::getGitBranch)
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private String applicationPublicBase(String namespace, ManagedApplication app) {
        String custom = effectiveCustomHostnameSafe(app, resolveBranchByNamespace(namespace));
        if (custom != null) {
            return customHostnameScheme.trim().toLowerCase() + "://" + custom;
        }
        return "http://app-" + namespace + "." + ingressDomain;
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
                        String svcName = String.valueOf(e.getKey());
                        AppService match = shadow.getServices().stream()
                                .filter(s -> svcName.equals(s.getName()))
                                .findFirst()
                                .orElse(null);
                        String resolved = match != null
                                ? ingressServiceUrl(deployment.getNamespace(), match, shadow)
                                : resolvePublicUrl(deployment, shadow);
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
        // Entrée publique = FRONTEND (ou premier service exposé), pas le BACKEND /api
        // (sinon le bandeau UI affiche l'API et le health sonde /api/api/…).
        if (ingressEnabled && deployment.getNamespace() != null && shadow != null) {
            AppService primary = findPrimaryExposed(shadow);
            if (primary != null) {
                String primaryUrl = ingressServiceUrl(deployment.getNamespace(), primary, shadow);
                if (primaryUrl != null && !primaryUrl.isBlank()) {
                    return primaryUrl;
                }
            }
            if (pathBasedRouting || effectiveCustomHostnameSafe(shadow) != null) {
                return applicationPublicBase(deployment.getNamespace(), shadow);
            }
        }
        Map<String, Object> state = deployment.getServicesState();
        if (state != null && state.get("services") instanceof Map<?, ?> services) {
            String firstNonApi = null;
            String firstAny = null;
            for (Object v : services.values()) {
                if (!(v instanceof Map<?, ?> svcState)) continue;
                Object ext = svcState.get("externalUrl");
                if (ext == null || String.valueOf(ext).isBlank()) continue;
                String url = String.valueOf(ext).trim();
                // Ignorer d'anciennes URLs NodePort / IP:port — préférer Ingress host
                if (url.matches("^https?://\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+.*")) {
                    continue;
                }
                if (firstAny == null) firstAny = url;
                String path = url.replaceFirst("^https?://[^/]+", "");
                if (!path.equals("/api") && !path.startsWith("/api/") && !path.equals("api")) {
                    firstNonApi = url;
                    break;
                }
            }
            if (firstNonApi != null) return firstNonApi;
            if (firstAny != null) return firstAny;
        }
        if (nipPreviewEnabled && nipMasterIp != null && !nipMasterIp.isBlank()
                && effectiveCustomHostnameSafe(shadow) == null) {
            String scheme = nipScheme != null && !nipScheme.isBlank() ? nipScheme.trim().toLowerCase() : "http";
            String id = deployment.getId().toString().toLowerCase();
            return scheme + "://app-" + id + "." + nipMasterIp.trim() + ".nip.io";
        }
        if (!shadow.getServices().isEmpty() && ingressEnabled) {
            String custom = effectiveCustomHostnameSafe(shadow, resolveDeploymentBranch(deployment.getId()));
            if (custom != null) {
                return customHostnameScheme.trim().toLowerCase() + "://" + custom;
            }
            AppService svc = findPrimaryExposed(shadow);
            if (svc == null) {
                svc = shadow.getServices().get(0);
            }
            String k8sName = AppNaming.k8sName(svc.getName());
            return "http://" + k8sName + "-" + deployment.getNamespace() + "." + ingressDomain;
        }
        return null;
    }

    private String ingressServiceUrl(String namespace, AppService svc, ManagedApplication app) {
        if (!ingressEnabled || !isExternallyExposedService(svc)) {
            return null;
        }
        boolean usePath = pathBasedRouting || effectiveCustomHostnameSafe(app, resolveBranchByNamespace(namespace)) != null;
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
            svcState.put("role", svc.getRole() != null ? svc.getRole().name() : null);
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
        log.info("Environnement éphémère créé pour déploiement — ttlHours={}", env.getTtlHours());
        return environmentRepository.save(env);
    }

    private void linkDeployPipelineExecution(
            AppService service,
            EphemeralEnvironment env,
            Long gitlabPipelineId,
            String branch
    ) {
        linkDeployPipelineExecution(service, env, gitlabPipelineId, branch, true);
    }

    /**
     * @param setAsEnvironmentPrimary Ne positionner {@code env.setPipelineExecution(execution)}
     *                                (référence singulière) QUE pour un seul service par
     *                                environnement -- le 1er/représentant, appelé avec {@code true}
     *                                par les 3 call sites historiques (déploiement mono-service :
     *                                deploySingleService/rebuildServiceInPlace, ou le "service
     *                                représentant" du déploiement app entière). Les AUTRES services
     *                                d'un déploiement multi-services (boucle ajoutée dans
     *                                {@code deploy()}) passent {@code false} : ils doivent quand
     *                                même avoir LEUR PROPRE PipelineExecution (sinon leur page
     *                                Quality Gate / Post-déploiement ne voit jamais ce déploiement
     *                                -- bug réel constaté le 28 août 2026, "back" ne recevait
     *                                jamais de PipelineExecution DEPLOY lors d'un déploiement de
     *                                toute l'app, seul le 1er service de la liste en recevait un),
     *                                mais sans écraser la référence singulière du 1er service.
     */
    private void linkDeployPipelineExecution(
            AppService service,
            EphemeralEnvironment env,
            Long gitlabPipelineId,
            String branch,
            boolean setAsEnvironmentPrimary
    ) {
        if (service == null || env == null || gitlabPipelineId == null) {
            return;
        }
        // Scopé par service ET pipeline -- pas seulement par pipeline (bug historique : un
        // déploiement multi-services partage un seul gitlabPipelineId pour tous les services,
        // donc un simple findByGitlabPipelineId() faisait croire qu'"une" exécution existait déjà
        // dès que le 1er service de la boucle avait créé la sienne, empêchant les autres services
        // d'obtenir la leur).
        if (pipelineExecutionRepository.findByGitlabPipelineIdAndApplicationId(gitlabPipelineId, service.getId()).isPresent()) {
            return;
        }
        PipelineExecution execution = new PipelineExecution();
        execution.setAppService(service);
        execution.setGitlabPipelineId(gitlabPipelineId);
        execution.setExecutionKind(PipelineExecutionKind.DEPLOY);
        execution.setGitBranch(branch != null && !branch.isBlank() ? branch : env.getGitBranch());
        execution.setStatus(PipelineStatus.fromGitLabStatus("running"));
        execution.setStartedAt(LocalDateTime.now());
        // PipelineExecution.environment est un @OneToOne (unique=true côté DB, contrainte
        // uk4o1klj2ky574ep8utyh6y2fvl) -- un seul PipelineExecution peut référencer un environment_id
        // donné. Bug constaté le 30/08/2026 : execution.setEnvironment(env) était posé
        // INCONDITIONNELLEMENT ici, alors que seul env.setPipelineExecution(execution) ci-dessous
        // était protégé par setAsEnvironmentPrimary -- dès le 2e service de la boucle
        // (setAsEnvironmentPrimary=false), l'insert violait la contrainte unique et faisait échouer
        // tout le déploiement multi-services. Les deux doivent être protégés ensemble : les services
        // non-représentants restent trouvables via findByGitlabPipelineIdAndApplicationId()
        // (scopé service+pipeline, pas environment_id) -- inchangé, voir garde ligne ~2390.
        if (setAsEnvironmentPrimary) {
            execution.setEnvironment(env);
            env.setPipelineExecution(execution);
        }
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
        // localhost/127.x injoignables depuis un runner distant.
        // host.docker.internal OK pour runner self-hosted Docker Desktop → backend local.
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
        variables.put("DD_IMPORT_ENABLED", "true"); // voir commentaire au 1er site d'appel
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
                try {
                    deploymentRuntimeAlertService.recordSyncRuntime(realApp, deployment, target.getName());
                } catch (Exception traceEx) {
                    log.debug("Traçabilité sync runtime non enregistrée: {}", traceEx.getMessage());
                }
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

        String host = effectiveCustomHostnameSafe(realApp);
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
