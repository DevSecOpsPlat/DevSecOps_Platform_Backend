package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppDatabaseRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
    private final AppDatabaseRepository databaseRepository;
    private final AppDeploymentValidationService validationService;
    private final AppConnectionUrlService connectionUrlService;
    private final AppK8sManifestService manifestService;
    private final AppDeploymentGitLabService gitLabService;
    private final ObjectMapper objectMapper;

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
    @Value("${deployment.callback.base-url:http://host.docker.internal:8089/projet}")
    private String callbackBaseUrl;

    // =====================================================================
    // Déclenchement
    // =====================================================================

    /**
     * Lance un déploiement de l'application : valide, génère les artefacts et déclenche
     * le pipeline GitLab. Renvoie le déploiement persisté (status DEPLOYING).
     */
    @Transactional
    public AppDeployment deploy(ManagedApplication app) {
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
        variables.put("NAMESPACE", namespace);
        variables.put("BACKEND_URL", callbackBaseUrl);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        variables.put("IMAGE_TAG", imageTag);
        variables.put("PULL_SECRET_NAME", pullSecretName);
        variables.put("K8S_DATABASES_B64", databasesB64);
        variables.put("K8S_SERVICES_B64", servicesB64);
        variables.put("SERVICES_JSON", servicesJson);

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        deployment.setStatus(pipelineId != null ? AppDeploymentStatus.DEPLOYING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());

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
        variables.put("NAMESPACE", namespace);
        variables.put("BACKEND_URL", callbackBaseUrl);
        variables.put("PIPELINE_SECRET", pipelineSecret != null ? pipelineSecret : "");
        variables.put("IMAGE_TAG", imageTag);
        variables.put("PULL_SECRET_NAME", pullSecretName);
        variables.put("K8S_DATABASES_B64", databasesB64);
        variables.put("K8S_SERVICES_B64", servicesB64);
        variables.put("SERVICES_JSON", servicesJson);

        Long pipelineId = gitLabService.triggerPipeline(variables);
        deployment.setGitlabPipelineId(pipelineId);
        deployment.setStatus(pipelineId != null ? AppDeploymentStatus.DEPLOYING : AppDeploymentStatus.FAILED);
        deployment.setDeployedAt(Instant.now());

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
        variables.put("BACKEND_URL", callbackBaseUrl);
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
}
