package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.*;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import com.backend.devsecopsplatform_backend.repository.AppDatabaseRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.ServiceEnvVarRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service applicatif de gestion des applications managées (CRUD apps / services / bases /
 * variables d'env), avec masquage systématique des secrets et délégation du déploiement à
 * {@link AppDeploymentService}. N'altère aucun service existant.
 */
@Service
@Slf4j
public class ApplicationManagementService {

    private static final String MASK = AppConnectionUrlService.MASK;
    /** Limite les sondes health pour ne pas saturer le pool HTTP/DB si tous les chemins échouent. */
    private static final int MAX_HEALTH_PROBE_PATHS = 5;

    private final ManagedApplicationRepository appRepository;
    private final AppServiceRepository serviceRepository;
    private final AppDatabaseRepository databaseRepository;
    private final ServiceEnvVarRepository envVarRepository;
    private final AppDeploymentRepository deploymentRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final UserRepository userRepository;
    private final AppConnectionUrlService connectionUrlService;
    private final AppDeploymentService deploymentService;
    private final AppDeploymentValidationService deploymentValidationService;
    private final ImageTagAvailabilityService imageTagAvailability;
    private final K8sManifestApplyService k8sManifestApplyService;
    private final GitLabService gitLabService;
    private final DeploymentRuntimeAlertService deploymentRuntimeAlertService;
    private final DeploymentMetricsSamplerService deploymentMetricsSamplerService;
    private final TransactionTemplate readOnlyTx;

    /** IP Traefik / master — sonde health des domaines custom via Host header. */
    @Value("${deployment.preview.nip.master-ip:192.168.92.10}")
    private String ingressProbeIp;

    public ApplicationManagementService(
            ManagedApplicationRepository appRepository,
            AppServiceRepository serviceRepository,
            AppDatabaseRepository databaseRepository,
            ServiceEnvVarRepository envVarRepository,
            AppDeploymentRepository deploymentRepository,
            EphemeralEnvironmentRepository environmentRepository,
            UserRepository userRepository,
            AppConnectionUrlService connectionUrlService,
            AppDeploymentService deploymentService,
            AppDeploymentValidationService deploymentValidationService,
            ImageTagAvailabilityService imageTagAvailability,
            K8sManifestApplyService k8sManifestApplyService,
            GitLabService gitLabService,
            @Lazy DeploymentRuntimeAlertService deploymentRuntimeAlertService,
            DeploymentMetricsSamplerService deploymentMetricsSamplerService,
            PlatformTransactionManager transactionManager
    ) {
        this.appRepository = appRepository;
        this.serviceRepository = serviceRepository;
        this.databaseRepository = databaseRepository;
        this.envVarRepository = envVarRepository;
        this.deploymentRepository = deploymentRepository;
        this.environmentRepository = environmentRepository;
        this.userRepository = userRepository;
        this.connectionUrlService = connectionUrlService;
        this.deploymentService = deploymentService;
        this.deploymentValidationService = deploymentValidationService;
        this.imageTagAvailability = imageTagAvailability;
        this.k8sManifestApplyService = k8sManifestApplyService;
        this.gitLabService = gitLabService;
        this.deploymentRuntimeAlertService = deploymentRuntimeAlertService;
        this.deploymentMetricsSamplerService = deploymentMetricsSamplerService;
        this.readOnlyTx = new TransactionTemplate(transactionManager);
        this.readOnlyTx.setReadOnly(true);
    }

    // =====================================================================
    // Applications
    // =====================================================================

    @Transactional
    public ManagedAppResponse createApp(CreateManagedAppRequest request) {
        User user = getCurrentUser();
        ManagedApplication app = new ManagedApplication();
        app.setName(request.getName());
        app.setDescription(request.getDescription());
        app.setSlug(uniqueSlug(request.getName()));
        app.setCreatedBy(user);
        ManagedApplication saved = appRepository.save(app);
        return mapApp(saved, false);
    }

    public List<ManagedAppResponse> listApps() {
        User user = getCurrentUser();
        return appRepository.findByCreatedByOrderByCreatedAtDesc(user).stream()
                .map(a -> mapApp(a, false))
                .collect(Collectors.toList());
    }

    public ManagedAppResponse getApp(UUID id) {
        return mapApp(loadOwnedApp(id), true);
    }

    @Transactional
    public ManagedAppResponse updateApp(UUID id, UpdateManagedAppRequest request) {
        ManagedApplication app = loadOwnedApp(id);
        app.setName(request.getName());
        app.setDescription(request.getDescription());
        String previousHost = app.getCustomHostname();
        String newHost = AppDeploymentService.normalizeCustomHostname(request.getCustomHostname());
        app.setCustomHostname(newHost);
        ManagedApplication saved = appRepository.save(app);
        // Si hostname changé et env RUNNING → réapplique Ingress
        boolean hostChanged = !java.util.Objects.equals(
                previousHost != null ? previousHost.trim().toLowerCase() : null,
                newHost);
        if (hostChanged) {
            try {
                deploymentService.syncIngressHostname(saved);
            } catch (Exception e) {
                log.warn("Sync Ingress hostname échoué pour app {}: {}", id, e.getMessage());
            }
        }
        return mapApp(saved, true);
    }

    @Transactional
    public void deleteApp(UUID id) {
        ManagedApplication app = loadOwnedApp(id);
        appRepository.delete(app); // cascade services / databases / deployments
    }

    // =====================================================================
    // Services
    // =====================================================================

    @Transactional
    public AppServiceResponse addService(UUID appId, AppServiceRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        validateServiceRequest(app, request, null);

        AppService svc = new AppService();
        svc.setManagedApplication(app);
        svc.setCreatedBy(app.getCreatedBy());
        applyServiceScalars(svc, request);
        if (request.getGitToken() != null && !request.getGitToken().isBlank() && !MASK.equals(request.getGitToken())) {
            svc.setGitToken(request.getGitToken());
        }
        AppService saved = serviceRepository.save(svc);
        syncEnvVars(saved, request.getEnvVars());
        return mapService(serviceRepository.save(saved));
    }

    @Transactional
    public AppServiceResponse updateService(UUID appId, UUID serviceId, AppServiceRequest request) {
        loadOwnedApp(appId);
        AppService svc = serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        validateServiceRequest(svc.getManagedApplication(), request, serviceId);
        applyServiceScalars(svc, request);
        if (request.getGitToken() != null && !request.getGitToken().isBlank() && !MASK.equals(request.getGitToken())) {
            svc.setGitToken(request.getGitToken());
        }
        syncEnvVars(svc, request.getEnvVars());
        return mapService(serviceRepository.save(svc));
    }

    @Transactional
    public ClusterPruneResponse deleteService(UUID appId, UUID serviceId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppService svc = serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        if (serviceRepository.countByDependsOnServiceId(serviceId) > 0) {
            throw new AppValidationException(
                    "Ce service est référencé par un ou plusieurs autres services. Retirez la dépendance d'abord.");
        }
        String logicalName = svc.getName();
        String k8sName = AppNaming.k8sName(logicalName);
        serviceRepository.delete(svc);
        // Flush so remaining-services queries in prune don't see the deleted row.
        serviceRepository.flush();
        return deploymentService.pruneRemovedService(app, logicalName, k8sName);
    }

    private void applyServiceScalars(AppService svc, AppServiceRequest request) {
        AppServiceRole role = request.getRole();
        svc.setName(request.getName().trim());
        svc.setRole(role);
        svc.setGitRepositoryUrl(request.getGitRepositoryUrl().trim());
        svc.setGitBranch(orDefault(request.getGitBranch(), "main"));
        svc.setDockerfilePath(orDefault(request.getDockerfilePath(), "Dockerfile"));
        svc.setBuildContext(orDefault(request.getBuildContext(), "."));

        if (AppServiceRules.requiresExposedPort(role)) {
            svc.setExposedPort(request.getExposedPort());
        } else {
            svc.setExposedPort(null);
            svc.setHealthCheckPath(null);
        }

        if (AppServiceRules.canDependOnDatabase(role)) {
            svc.setDependsOnDatabaseId(request.getDependsOnDatabaseId());
            svc.setDbUrlEnvVar(orDefault(request.getDbUrlEnvVar(), "DATABASE_URL"));
        } else {
            svc.setDependsOnDatabaseId(null);
            svc.setDbUrlEnvVar(null);
        }

        svc.setDependsOnServiceId(request.getDependsOnServiceId());
        svc.setReplicas(request.getReplicas() != null ? request.getReplicas() : 1);

        if (AppServiceRules.allowsHealthCheck(role)
                && request.getHealthCheckPath() != null
                && !request.getHealthCheckPath().isBlank()) {
            svc.setHealthCheckPath(request.getHealthCheckPath().trim());
        } else if (AppServiceRules.requiresExposedPort(role)) {
            svc.setHealthCheckPath(request.getHealthCheckPath());
        }

        if (AppServiceRules.requiresExposedPort(role)) {
            svc.setContextPath(AppServiceRules.normalizeContextPath(request.getContextPath()));
        } else {
            svc.setContextPath(null);
        }

        svc.setCpuRequest(orDefault(request.getCpuRequest(), "100m"));
        svc.setCpuLimit(orDefault(request.getCpuLimit(), "500m"));
        svc.setMemoryRequest(orDefault(request.getMemoryRequest(), "128Mi"));
        svc.setMemoryLimit(orDefault(request.getMemoryLimit(), "512Mi"));
    }

    private void validateServiceRequest(ManagedApplication app, AppServiceRequest request, UUID selfId) {
        if (request.getRole() == null) {
            throw new AppValidationException("Le rôle du service est obligatoire.");
        }
        AppServiceRole role = request.getRole();

        String name = request.getName() == null ? "" : request.getName().trim();
        if (name.isBlank()) {
            throw new AppValidationException("Le nom du service est obligatoire.");
        }
        String k8s = AppNaming.k8sName(name);
        boolean k8sClash = app.getServices().stream()
                .filter(s -> selfId == null || !selfId.equals(s.getId()))
                .anyMatch(s -> AppNaming.k8sName(s.getName()).equals(k8s));
        if (k8sClash) {
            throw new AppValidationException(
                    "Un autre service produit déjà le même nom Kubernetes « " + k8s
                            + " ». Choisissez un nom distinct après normalisation.");
        }

        AppServiceRules.assertGitHttpsUrl(request.getGitRepositoryUrl());
        AppServiceRules.assertRelativePath(request.getDockerfilePath(), "Dockerfile");
        AppServiceRules.assertRelativePath(request.getBuildContext(), "Contexte de build");

        if (AppServiceRules.requiresExposedPort(role)) {
            Integer port = request.getExposedPort();
            if (port == null) {
                throw new AppValidationException("Le port exposé est obligatoire pour un " + role + ".");
            }
            if (port < AppServiceRules.MIN_EXPOSED_PORT || port > AppServiceRules.MAX_EXPOSED_PORT) {
                throw new AppValidationException(
                        "Port exposé hors plage (" + AppServiceRules.MIN_EXPOSED_PORT
                                + "–" + AppServiceRules.MAX_EXPOSED_PORT
                                + "). Un conteneur non-root ne peut pas binder un port < 1024.");
            }
            AppServiceRules.assertContextPath(request.getContextPath());
        } else if (request.getExposedPort() != null) {
            // WORKER : ignorer silencieux côté apply ; on refuse une valeur explicite trompeuse
            // uniquement si l'utilisateur tente d'exposer — ici on l'efface à applyServiceScalars.
        }

        int replicas = request.getReplicas() != null ? request.getReplicas() : 1;
        if (replicas < 1 || replicas > AppServiceRules.MAX_REPLICAS) {
            throw new AppValidationException(
                    "Réplicas hors plage (1–" + AppServiceRules.MAX_REPLICAS + ").");
        }

        AppServiceRules.validateQuantities(
                orDefault(request.getCpuRequest(), "100m"),
                orDefault(request.getCpuLimit(), "500m"),
                orDefault(request.getMemoryRequest(), "128Mi"),
                orDefault(request.getMemoryLimit(), "512Mi")
        );

        // --- Dépendance base ---
        if (request.getDependsOnDatabaseId() != null) {
            if (!AppServiceRules.canDependOnDatabase(role)) {
                throw new AppValidationException(
                        "Un FRONTEND ne peut pas dépendre d'une base de données. "
                                + "Passez par un service BACKEND (évite de livrer des secrets au navigateur).");
            }
            boolean exists = app.getDatabases().stream()
                    .anyMatch(d -> d.getId().equals(request.getDependsOnDatabaseId()));
            if (!exists) {
                throw new AppValidationException("La base de données liée n'existe pas dans cette application.");
            }
            String urlEnv = orDefault(request.getDbUrlEnvVar(), "DATABASE_URL");
            AppServiceRules.assertEnvVarKey(urlEnv);
            if (request.getEnvVars() != null) {
                boolean collision = request.getEnvVars().stream()
                        .anyMatch(e -> e.getVarKey() != null && urlEnv.equals(e.getVarKey().trim()));
                if (collision) {
                    throw new AppValidationException(
                            "La variable « " + urlEnv
                                    + " » est réservée à l'injection automatique de l'URL de base. "
                                    + "Retirez-la des variables manuelles ou changez dbUrlEnvVar.");
                }
            }
        }

        // --- Dépendance service ---
        if (request.getDependsOnServiceId() != null) {
            if (selfId != null && request.getDependsOnServiceId().equals(selfId)) {
                throw new AppValidationException("Un service ne peut pas dépendre de lui-même.");
            }
            boolean exists = app.getServices().stream()
                    .anyMatch(s -> s.getId().equals(request.getDependsOnServiceId()));
            if (!exists) {
                throw new AppValidationException("Le service dépendant n'existe pas dans cette application.");
            }
        }

        // Env vars
        if (request.getEnvVars() != null) {
            java.util.HashSet<String> seen = new java.util.HashSet<>();
            for (EnvVarRequest e : request.getEnvVars()) {
                if (e.getVarKey() == null || e.getVarKey().isBlank()) {
                    continue;
                }
                AppServiceRules.assertEnvVarKey(e.getVarKey());
                String k = e.getVarKey().trim();
                if (!seen.add(k)) {
                    throw new AppValidationException("Clé d'environnement en double : « " + k + " ».");
                }
            }
        }

        // Cycles (avec l'arête en cours)
        ServiceTopology.assertNoCycle(app, selfId, request.getDependsOnServiceId());
    }

    // =====================================================================
    // Databases
    // =====================================================================

    @Transactional
    public AppDatabaseResponse addDatabase(UUID appId, AppDatabaseRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        validateDatabaseRequest(request, true);

        String resourceName = request.getName().trim();
        if (databaseRepository.existsByApplication_IdAndNameIgnoreCase(appId, resourceName)) {
            throw new AppValidationException(
                    "Une base avec le nom ressource « " + resourceName + " » existe déjà dans cette application.");
        }

        AppDatabase db = new AppDatabase();
        db.setApplication(app);
        applyDatabaseScalars(db, request);
        applyRootPasswordOnCreate(db, request);
        try {
            return mapDatabase(databaseRepository.saveAndFlush(db));
        } catch (DataIntegrityViolationException e) {
            throw new AppValidationException(
                    "Une base avec ce nom existe déjà dans cette application.");
        }
    }

    @Transactional
    public AppDatabaseResponse updateDatabase(UUID appId, UUID databaseId, AppDatabaseRequest request) {
        loadOwnedApp(appId);
        AppDatabase db = databaseRepository.findByIdAndApplication_Id(databaseId, appId)
                .orElseThrow(() -> new AppValidationException("Base introuvable dans cette application."));
        validateDatabaseRequest(request, false);
        guardImmutableAfterDeploy(db, request);

        String resourceName = request.getName().trim();
        if (databaseRepository.existsByApplication_IdAndNameIgnoreCaseAndIdNot(appId, resourceName, databaseId)) {
            throw new AppValidationException(
                    "Une autre base utilise déjà le nom ressource « " + resourceName + " ».");
        }
        applyDatabaseScalars(db, request);
        if (AppDatabaseRules.usesRootPassword(db.getEngine())
                && request.getRootPassword() != null
                && !request.getRootPassword().isBlank()
                && !MASK.equals(request.getRootPassword())) {
            assertPasswordSafe(request.getRootPassword());
            db.setRootPassword(request.getRootPassword());
        }
        try {
            return mapDatabase(databaseRepository.saveAndFlush(db));
        } catch (DataIntegrityViolationException e) {
            throw new AppValidationException(
                    "Une base avec ce nom existe déjà dans cette application.");
        }
    }

    @Transactional
    public ClusterPruneResponse deleteDatabase(UUID appId, UUID databaseId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDatabase db = databaseRepository.findByIdAndApplication_Id(databaseId, appId)
                .orElseThrow(() -> new AppValidationException("Base introuvable dans cette application."));
        if (serviceRepository.countByDependsOnDatabaseId(databaseId) > 0) {
            throw new AppValidationException(
                    "Cette base est référencée par un ou plusieurs services. Retirez la dépendance d'abord.");
        }
        // Snapshot avant delete (nom K8s dérivé de l'entité)
        AppDatabase snapshot = new AppDatabase();
        snapshot.setName(db.getName());
        snapshot.setEngine(db.getEngine());
        databaseRepository.delete(db);
        databaseRepository.flush();
        return deploymentService.pruneRemovedDatabase(app, snapshot);
    }

    private void applyRootPasswordOnCreate(AppDatabase db, AppDatabaseRequest request) {
        DbEngine engine = request.getEngine();
        if (!AppDatabaseRules.usesRootPassword(engine)) {
            // Colonne NOT NULL : placeholder interne, jamais utiliséé dans les manifests Cassandra.
            db.setRootPassword("unused-" + UUID.randomUUID());
            return;
        }
        if (request.getRootPassword() == null || request.getRootPassword().isBlank()) {
            throw new AppValidationException(
                    "Le mot de passe est obligatoire pour créer cette base (" + engine + ").");
        }
        assertPasswordSafe(request.getRootPassword());
        db.setRootPassword(request.getRootPassword().trim());
    }

    private void applyDatabaseScalars(AppDatabase db, AppDatabaseRequest request) {
        DbEngine engine = request.getEngine();
        db.setName(request.getName().trim());
        db.setEngine(engine);
        db.setDbFamily(engine.family());
        db.setVersion(request.getVersion().trim());
        db.setDbName(AppDatabaseRules.normalizeLogicalDbName(engine, request.getDbName()));

        if (AppDatabaseRules.usesRootUser(engine)) {
            String user = request.getRootUser() == null ? "" : request.getRootUser().trim();
            db.setRootUser(user.isEmpty() ? "root" : user);
        } else {
            // MySQL/MariaDB : only ROOT_PASSWORD is mapped — keep a sentinel for NOT NULL column.
            db.setRootUser(request.getRootUser() != null && !request.getRootUser().isBlank()
                    ? request.getRootUser().trim() : "root");
        }

        db.setExposedPort(request.getExposedPort() != null ? request.getExposedPort()
                : engine.defaultPort());
        db.setStorageSize(orDefault(request.getStorageSize(), "1Gi").trim());
    }

    private void validateDatabaseRequest(AppDatabaseRequest request, boolean creating) {
        if (request.getEngine() == null) {
            throw new AppValidationException("Le moteur est obligatoire.");
        }
        DbEngine engine = request.getEngine();
        if (request.getDbFamily() != null && request.getDbFamily() != engine.family()) {
            throw new AppValidationException("Le moteur « " + engine
                    + " » n'appartient pas à la famille " + request.getDbFamily() + ".");
        }
        if (!AppDatabaseRules.createsLogicalDbAtStartup(engine) && engine == DbEngine.CASSANDRA) {
            // Keyspace non créé au boot — on accepte la déclaration mais on avertit via message clair
            // si la longueur/format est mauvais (règles ci-dessous). Un Job CQL pourra suivre.
        }

        String resourceName = request.getName() == null ? "" : request.getName().trim();
        if (!AppDatabaseRules.RESOURCE_NAME.matcher(resourceName).matches()) {
            throw new AppValidationException(
                    "Nom ressource invalide : minuscules, chiffres et tirets uniquement "
                            + "(ex. main-db), 2 à 50 caractères, doit commencer et finir par une lettre ou un chiffre.");
        }

        String logicalRaw = request.getDbName() == null ? "" : request.getDbName().trim();
        if (!AppDatabaseRules.isValidLogicalDbName(engine, logicalRaw)) {
            if (engine == DbEngine.REDIS) {
                throw new AppValidationException(
                        "Pour Redis, « Index / base logique » doit être un entier entre 0 et 15.");
            }
            if (engine == DbEngine.CASSANDRA) {
                throw new AppValidationException(
                        "Keyspace Cassandra invalide : minuscules, chiffres, _ ; max 48 caractères "
                                + "(commence par une lettre). Note : Cassandra ne crée pas le keyspace au démarrage.");
            }
            if (AppDatabaseRules.isReservedDbName(engine, logicalRaw)) {
                throw new AppValidationException(
                        "Le nom de base « " + logicalRaw + " » est réservé par " + engine + ".");
            }
            throw new AppValidationException(
                    "Nom de base logique invalide : commence par une lettre, puis lettres/chiffres/_ uniquement "
                            + "(ex. appdb).");
        }

        if (AppDatabaseRules.usesRootUser(engine)) {
            String user = request.getRootUser() == null ? "" : request.getRootUser().trim();
            if (!AppDatabaseRules.ROOT_USER.matcher(user).matches()) {
                throw new AppValidationException(
                        "Utilisateur invalide : commence par une lettre ou _, puis lettres/chiffres/_ (2–32 car.).");
            }
            if (AppDatabaseRules.isForbiddenRootUser(engine, user)) {
                throw new AppValidationException(
                        "Pour MySQL/MariaDB, n'utilisez pas « root » comme utilisateur applicatif "
                                + "(l'image refuse MYSQL_USER=root).");
            }
        }

        String version = request.getVersion() == null ? "" : request.getVersion().trim();
        if (!AppDatabaseRules.ENGINE_VERSION.matcher(version).matches()) {
            throw new AppValidationException(
                    "Version invalide : utilisez un tag d'image numérique (ex. 16, 16.2, 8.4, 10.11).");
        }
        ImageTagAvailabilityService.Result tagCheck = imageTagAvailability.check(engine, version);
        if (tagCheck == ImageTagAvailabilityService.Result.NOT_FOUND) {
            throw new AppValidationException(
                    "L'image « " + AppDatabaseRules.imageRef(engine, version)
                            + " » n'existe pas sur Docker Hub. Vérifiez la version.");
        }

        String storage = request.getStorageSize() == null || request.getStorageSize().isBlank()
                ? "1Gi" : request.getStorageSize().trim();
        if (!AppDatabaseRules.STORAGE_SIZE.matcher(storage).matches()) {
            throw new AppValidationException(
                    "Taille de volume invalide : format Kubernetes requis (ex. 512Mi, 1Gi, 10Gi).");
        }
        long mib = AppDatabaseRules.storageToMib(storage);
        if (mib > AppDatabaseRules.MAX_STORAGE_MIB) {
            throw new AppValidationException(
                    "Taille de volume trop grande (max " + (AppDatabaseRules.MAX_STORAGE_MIB / 1024) + "Gi).");
        }

        Integer port = request.getExposedPort();
        if (port != null && (port < 1 || port > 65535)) {
            throw new AppValidationException("Le port exposé doit être entre 1 et 65535.");
        }

        if (creating && AppDatabaseRules.usesRootPassword(engine)) {
            if (request.getRootPassword() == null || request.getRootPassword().isBlank()) {
                throw new AppValidationException(
                        "Le mot de passe est obligatoire pour créer cette base (" + engine + ").");
            }
            assertPasswordSafe(request.getRootPassword());
        } else if (request.getRootPassword() != null && !request.getRootPassword().isBlank()
                && !MASK.equals(request.getRootPassword())) {
            assertPasswordSafe(request.getRootPassword());
        }
    }

    private void assertPasswordSafe(String pwd) {
        String p = pwd.trim();
        if (!AppDatabaseRules.PASSWORD_SAFE.matcher(p).matches()) {
            throw new AppValidationException(
                    "Mot de passe invalide : 8–128 caractères ASCII imprimables, sans espace ni contrôle.");
        }
    }

    private void guardImmutableAfterDeploy(AppDatabase db, AppDatabaseRequest req) {
        boolean deployed = db.getGeneratedConnectionUrl() != null && !db.getGeneratedConnectionUrl().isBlank();
        if (!deployed) {
            return;
        }
        String wantedDb = AppDatabaseRules.normalizeLogicalDbName(req.getEngine(), req.getDbName());
        String wantedUser = req.getRootUser() == null ? db.getRootUser() : req.getRootUser().trim();
        if (db.getEngine() != req.getEngine()
                || !Objects.equals(db.getDbName(), wantedDb)
                || (AppDatabaseRules.usesRootUser(db.getEngine())
                && !Objects.equals(db.getRootUser(), wantedUser))) {
            throw new AppValidationException(
                    "Moteur, nom de base et utilisateur ne sont plus modifiables une fois la base déployée. "
                            + "Supprimez la base et recréez-la.");
        }
        if (AppDatabaseRules.majorOf(db.getVersion()) != AppDatabaseRules.majorOf(req.getVersion())) {
            throw new AppValidationException(
                    "Un changement de version majeure ne peut pas se faire sur un volume existant.");
        }
        String wantedStorage = orDefault(req.getStorageSize(), db.getStorageSize()).trim();
        long current = AppDatabaseRules.storageToMib(db.getStorageSize());
        long wanted = AppDatabaseRules.storageToMib(wantedStorage);
        if (wanted < current) {
            throw new AppValidationException(
                    "Un volume Kubernetes ne peut pas être réduit (actuel : " + db.getStorageSize() + ").");
        }
    }

    // =====================================================================
    // Env vars (CRUD dédié)
    // =====================================================================

    public List<EnvVarResponse> listEnvVars(UUID appId, UUID serviceId) {
        loadOwnedApp(appId);
        serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        return envVarRepository.findByAppService_Id(serviceId).stream()
                .map(this::mapEnvVar).collect(Collectors.toList());
    }

    @Transactional
    public EnvVarResponse addEnvVar(UUID appId, UUID serviceId, EnvVarRequest request) {
        loadOwnedApp(appId);
        AppService svc = serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        ServiceEnvVar envVar = new ServiceEnvVar();
        envVar.setAppService(svc);
        envVar.setVarKey(request.getVarKey());
        envVar.setVarValue(orNull(request.getVarValue()));
        envVar.setSecret(request.isSecret());
        return mapEnvVar(envVarRepository.save(envVar));
    }

    @Transactional
    public EnvVarResponse updateEnvVar(UUID appId, UUID serviceId, UUID envVarId, EnvVarRequest request) {
        loadOwnedApp(appId);
        serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        ServiceEnvVar envVar = envVarRepository.findByIdAndAppService_Id(envVarId, serviceId)
                .orElseThrow(() -> new AppValidationException("Variable introuvable."));
        envVar.setVarKey(request.getVarKey());
        envVar.setSecret(request.isSecret());
        if (request.getVarValue() != null && !MASK.equals(request.getVarValue())) {
            envVar.setVarValue(request.getVarValue());
        }
        return mapEnvVar(envVarRepository.save(envVar));
    }

    @Transactional
    public void deleteEnvVar(UUID appId, UUID serviceId, UUID envVarId) {
        loadOwnedApp(appId);
        serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        ServiceEnvVar envVar = envVarRepository.findByIdAndAppService_Id(envVarId, serviceId)
                .orElseThrow(() -> new AppValidationException("Variable introuvable."));
        envVarRepository.delete(envVar);
    }

    private void syncEnvVars(AppService svc, List<EnvVarRequest> requested) {
        if (requested == null) {
            return;
        }
        List<ServiceEnvVar> existing = svc.getEnvVars();
        List<UUID> keepIds = new ArrayList<>();
        for (EnvVarRequest req : requested) {
            ServiceEnvVar target = null;
            if (req.getId() != null) {
                target = existing.stream().filter(v -> v.getId().equals(req.getId())).findFirst().orElse(null);
            }
            if (target == null) {
                target = new ServiceEnvVar();
                target.setAppService(svc);
                existing.add(target);
            }
            target.setVarKey(req.getVarKey());
            target.setSecret(req.isSecret());
            if (req.getVarValue() != null && !MASK.equals(req.getVarValue())) {
                target.setVarValue(req.getVarValue());
            }
            if (target.getId() != null) {
                keepIds.add(target.getId());
            }
        }
        existing.removeIf(v -> v.getId() != null && !keepIds.contains(v.getId()));
    }

    // =====================================================================
    // Déploiements
    // =====================================================================

    @Transactional
    public AppDeploymentResponse deploy(UUID appId) {
        return deploy(appId, null);
    }

    @Transactional
    public AppDeploymentResponse deploy(UUID appId, ManagedDeployRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentService.deploy(app, ManagedDeployOptions.from(request));
        return mapDeployment(deployment, app);
    }

    /**
     * Aperçu infos / warnings avant déploiement (sélection de services + TTL).
     */
    @Transactional(readOnly = true)
    public DeployPreviewResponse previewDeploy(UUID appId, ManagedDeployRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        ManagedDeployOptions options = ManagedDeployOptions.from(request);
        ManagedApplication target = options.hasServiceFilter()
                ? deploymentValidationService.buildShadow(app, options.serviceIdsOrEmpty())
                : app;
        return deploymentValidationService.preview(target, options.ttlHours());
    }

    public List<AppDeploymentResponse> listDeployments(UUID appId) {
        ManagedApplication app = loadOwnedApp(appId);
        return deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .map(d -> mapDeployment(d, app))
                .collect(Collectors.toList());
    }

    @Transactional
    public AppDeploymentResponse getDeployment(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        // Réconcilie DEPLOYING coincé (ex. rebuild backend pods Ready mais UI encore Deploying)
        if (deployment.getStatus() == AppDeploymentStatus.DEPLOYING) {
            try {
                deploymentService.getCiDeployStatus(deploymentId);
                deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                        .orElse(deployment);
            } catch (Exception e) {
                log.debug("reconcile DEPLOYING {}: {}", deploymentId, e.getMessage());
            }
        }
        return mapDeployment(deployment, app);
    }

    @Transactional
    public AppDeploymentResponse teardownDeployment(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        return mapDeployment(deploymentService.teardown(deployment), app);
    }

    /**
     * Prolonge le TTL de l'environnement éphémère lié au déploiement (max 72 h depuis Ready).
     */
    @Transactional
    public AppDeploymentResponse extendDeploymentTtl(UUID appId, UUID deploymentId, int additionalHours) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));

        if (deployment.getStatus() != AppDeploymentStatus.RUNNING
                && deployment.getStatus() != AppDeploymentStatus.DEPLOYING) {
            throw new AppValidationException("TTL prolongé uniquement sur un déploiement RUNNING ou DEPLOYING.");
        }
        if (additionalHours < 1 || additionalHours > 24) {
            throw new AppValidationException("additionalHours doit être entre 1 et 24.");
        }

        UUID envId = deployment.getEphemeralEnvironmentId();
        if (envId == null) {
            throw new AppValidationException("Aucun environnement éphémère lié à ce déploiement.");
        }
        EphemeralEnvironment env = environmentRepository.findById(envId)
                .orElseThrow(() -> new AppValidationException("Environnement éphémère introuvable."));

        if (env.getStatus() == EnvironmentStatus.DESTROYED
                || env.getStatus() == EnvironmentStatus.EXPIRED) {
            throw new AppValidationException("Environnement déjà arrêté ou expiré — impossible de prolonger.");
        }
        if (env.getExpiresAt() == null && env.getReadyAt() == null) {
            throw new AppValidationException("TTL pas encore démarré (environnement pas Ready).");
        }

        final int maxTotalHours = 72;
        LocalDateTime ready = env.getReadyAt() != null ? env.getReadyAt() : LocalDateTime.now();
        LocalDateTime currentExpires = env.getExpiresAt() != null
                ? env.getExpiresAt()
                : ready.plusHours(env.getTtlHours() != null && env.getTtlHours() > 0 ? env.getTtlHours() : 4);
        LocalDateTime maxExpires = ready.plusHours(maxTotalHours);

        if (!currentExpires.isBefore(maxExpires)) {
            throw new AppValidationException("TTL déjà au maximum (" + maxTotalHours + " h depuis Ready).");
        }

        long hoursUntilCap = java.time.Duration.between(currentExpires, maxExpires).toHours();
        int applied = (int) Math.min(additionalHours, Math.max(1, hoursUntilCap));
        if (hoursUntilCap < 1) {
            // moins d'1 h avant le plafond : avance jusqu'au cap
            env.setExpiresAt(maxExpires);
            int ttlFromReady = (int) Math.max(1, java.time.Duration.between(ready, maxExpires).toHours());
            env.setTtlHours(ttlFromReady);
            applied = additionalHours;
        } else {
            env.extendLifetime(applied);
            if (env.getExpiresAt().isAfter(maxExpires)) {
                env.setExpiresAt(maxExpires);
            }
            int ttlFromReady = (int) Math.max(1, java.time.Duration.between(ready, env.getExpiresAt()).toHours());
            env.setTtlHours(Math.min(ttlFromReady, maxTotalHours));
        }

        if (env.getStatus() != EnvironmentStatus.RUNNING
                && env.getStatus() != EnvironmentStatus.BUILDING
                && env.getStatus() != EnvironmentStatus.PENDING) {
            env.setStatus(EnvironmentStatus.RUNNING);
            env.setDestroyedAt(null);
        }

        environmentRepository.save(env);

        // Aligne servicesState.ttlHours pour l'UI
        Map<String, Object> state = deployment.getServicesState();
        if (state != null) {
            state.put("ttlHours", env.getTtlHours());
            deployment.setServicesState(state);
            deploymentRepository.save(deployment);
        }

        log.info("TTL prolongé — deployment={} env={} +{}h → expiresAt={} ttlHours={}",
                deploymentId, envId, applied, env.getExpiresAt(), env.getTtlHours());
        return mapDeployment(deployment, app);
    }

    /**
     * Synchronise les variables d'environnement du service vers le(s) namespace(s) RUNNING
     * sans passer par le pipeline CI.
     */
    public RuntimeSyncResponse syncServiceRuntime(UUID appId, UUID serviceId) {
        ManagedApplication app = loadOwnedApp(appId);
        serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        return deploymentService.syncServiceRuntime(app, serviceId);
    }

    /**
     * Rebuild CI d'un seul service dans le namespace RUNNING (même déploiement, pas de nouveau NS).
     */
    @Transactional
    public AppDeploymentResponse rebuildService(UUID appId, UUID serviceId) {
        ManagedApplication app = loadOwnedApp(appId);
        serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        AppDeployment deployment = deploymentService.rebuildServiceInPlace(app, serviceId);
        return mapDeployment(deployment, app);
    }

    /**
     * Liste les pods du namespace d'un déploiement (observabilité cluster).
     */
    public Map<String, Object> listDeploymentPods(UUID appId, UUID deploymentId) {
        loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("namespace", deployment.getNamespace());
        out.put("deploymentId", deployment.getId());
        out.put("status", deployment.getStatus());

        if (deployment.getStatus() == AppDeploymentStatus.STOPPED
                || deployment.getStatus() == AppDeploymentStatus.FAILED) {
            out.put("pods", List.of());
            out.put("message", deployment.getStatus() == AppDeploymentStatus.STOPPED
                    ? "Environnement arrêté — aucun pod."
                    : "Déploiement en échec — pods non listés.");
            return out;
        }
        if (!k8sManifestApplyService.isConfigured()) {
            throw new AppValidationException("Cluster K8s non configuré.");
        }
        if (deployment.getNamespace() == null || deployment.getNamespace().isBlank()) {
            throw new AppValidationException("Namespace absent pour ce déploiement.");
        }
        try {
            out.put("pods", k8sManifestApplyService.listPods(deployment.getNamespace()));
        } catch (Exception e) {
            log.warn("listPods ns={}: {}", deployment.getNamespace(), e.getMessage());
            out.put("pods", List.of());
            out.put("message", "Namespace inaccessible (supprimé ou en cours de suppression).");
        }
        return out;
    }

    /**
     * Monitoring léger : métriques pods, alertes, health HTTP de l'URL publique.
     * <p>Ne tient <b>pas</b> de transaction JPA pendant les appels K8s / HTTP
     * (sinon le pool Hikari sature : active=10, waiting…).</p>
     */
    public Map<String, Object> getDeploymentMonitoring(UUID appId, UUID deploymentId) {
        MonitoringSnap snap = readOnlyTx.execute(status -> loadMonitoringSnap(appId, deploymentId));
        if (snap == null) {
            throw new AppValidationException("Déploiement introuvable.");
        }

        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("namespace", snap.namespace());
        out.put("deploymentId", snap.deploymentId());
        out.put("status", snap.status());
        out.put("checkedAt", Instant.now().toString());
        out.put("applicationName", snap.appName());
        out.put("applicationSlug", snap.appSlug());
        out.put("expiresAt", snap.expiresAtIso());

        if (snap.inactive()) {
            out.put("pods", List.of());
            out.put("workloads", List.of());
            out.put("services", List.of());
            out.put("events", List.of());
            out.put("alerts", List.of());
            out.put("summary", Map.of("totalPods", 0, "readyPods", 0, "alertCount", 0, "metricsAvailable", false));
            out.put("health", Map.of("checked", false, "message", "Environnement non actif"));
            return out;
        }
        if (!k8sManifestApplyService.isConfigured()) {
            throw new AppValidationException("Cluster K8s non configuré.");
        }
        if (snap.namespace() == null || snap.namespace().isBlank()) {
            throw new AppValidationException("Namespace absent pour ce déploiement.");
        }

        Map<String, Object> mon;
        try {
            mon = k8sManifestApplyService.getNamespaceMonitoring(snap.namespace());
        } catch (Exception e) {
            log.warn("monitoring ns={}: {}", snap.namespace(), e.getMessage());
            mon = new java.util.LinkedHashMap<>();
            mon.put("pods", List.of());
            mon.put("alerts", new java.util.ArrayList<Map<String, Object>>());
            mon.put("summary", Map.of("totalPods", 0, "readyPods", 0, "alertCount", 0, "metricsAvailable", false));
            mon.put("message", "Namespace inaccessible.");
        }
        out.putAll(mon);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> alerts = mon.get("alerts") instanceof List<?> list
                ? (List<Map<String, Object>>) list
                : new java.util.ArrayList<>();

        if (Boolean.FALSE.equals(snap.ingressApplied())) {
            Map<String, Object> a = new java.util.LinkedHashMap<>();
            a.put("severity", "warn");
            a.put("pod", null);
            a.put("workload", null);
            a.put("kind", "health");
            a.put("reason", "IngressNotApplied");
            a.put("message", snap.ingressError() != null
                    ? "Ingress non appliqué : " + snap.ingressError()
                    : "Ingress non appliqué — URL publique indisponible");
            alerts.add(a);
        }

        Map<String, Object> health = probeHttpHealth(snap.appUrl(), snap.healthPaths());
        out.put("health", health);
        out.put("appUrl", snap.appUrl());
        if (Boolean.FALSE.equals(health.get("ok")) && Boolean.TRUE.equals(health.get("checked"))) {
            Map<String, Object> a = new java.util.LinkedHashMap<>();
            a.put("severity", "warn");
            a.put("pod", null);
            a.put("workload", null);
            a.put("kind", "health");
            a.put("reason", "HealthCheckFailed");
            a.put("message", "Health URL : " + health.get("message"));
            if (health.get("url") != null) {
                a.put("object", String.valueOf(health.get("url")));
            }
            alerts.add(a);
        }
        out.put("alerts", alerts);
        Object summaryObj = out.get("summary");
        if (summaryObj instanceof Map<?, ?> summary) {
            Map<String, Object> s = new java.util.LinkedHashMap<>();
            summary.forEach((k, v) -> s.put(String.valueOf(k), v));
            s.put("alertCount", alerts.size());
            out.put("summary", s);
        }
        return out;
    }

    /** Données DB nécessaires au monitoring — chargées en transaction courte. */
    private MonitoringSnap loadMonitoringSnap(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));

        Instant expiresAt = null;
        if (deployment.getEphemeralEnvironmentId() != null) {
            EphemeralEnvironment env = environmentRepository.findById(deployment.getEphemeralEnvironmentId()).orElse(null);
            if (env != null) {
                expiresAt = toInstant(env.getExpiresAt());
            }
        }

        boolean inactive = deployment.getStatus() == AppDeploymentStatus.STOPPED
                || deployment.getStatus() == AppDeploymentStatus.FAILED;

        Map<String, Object> state = deployment.getServicesState();
        Boolean ingressApplied = null;
        Object ingressError = null;
        if (state != null) {
            if (state.get("ingressApplied") instanceof Boolean b) {
                ingressApplied = b;
            }
            ingressError = state.get("ingressError");
        }

        // Touch lazy services while TX is open
        List<String> healthPaths = collectHealthProbePaths(app);
        String appUrl = inactive ? null : pickPublicAppUrl(app, deployment);

        return new MonitoringSnap(
                deployment.getId(),
                deployment.getNamespace(),
                deployment.getStatus() != null ? deployment.getStatus().name() : null,
                app.getName(),
                app.getSlug(),
                expiresAt != null ? expiresAt.toString() : null,
                inactive,
                ingressApplied,
                ingressError != null ? String.valueOf(ingressError) : null,
                appUrl,
                healthPaths
        );
    }

    private record MonitoringSnap(
            UUID deploymentId,
            String namespace,
            String status,
            String appName,
            String appSlug,
            String expiresAtIso,
            boolean inactive,
            Boolean ingressApplied,
            String ingressError,
            String appUrl,
            List<String> healthPaths
    ) {}

    /**
     * Alertes runtime live + historique 24 h pour un déploiement.
     * Pas de {@code @Transactional} ici : le live appelle le monitoring K8s/HTTP
     * (ne doit pas retenir une connexion Hikari).
     */
    public Map<String, Object> listDeploymentAlerts(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        return deploymentRuntimeAlertService.listForDeployment(app, deployment);
    }

    /** Historique métriques namespace (échantillons DB). */
    @Transactional(readOnly = true)
    public Map<String, Object> getDeploymentMetricsHistory(
            UUID appId, UUID deploymentId, Instant from, Instant to) {
        loadOwnedApp(appId);
        deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        return deploymentMetricsSamplerService.history(appId, deploymentId, from, to);
    }

    /**
     * URL à afficher / sonder pour l'app : FRONTEND d'abord, sinon URL « racine »
     * (évite de prendre BACKEND …/api qui fausse le health et le bandeau).
     */
    private String pickPublicAppUrl(ManagedApplication app, AppDeployment deployment) {
        Map<String, Object> state = deployment.getServicesState();
        if (state == null || !(state.get("services") instanceof Map<?, ?> servicesRaw)) {
            return null;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> services = (Map<String, Object>) servicesRaw;

        for (AppService svc : app.getServices()) {
            if (svc.getRole() != AppServiceRole.FRONTEND) continue;
            Object row = services.get(svc.getName());
            String url = externalUrlOf(row);
            if (url != null) return url;
        }

        String firstRoot = null;
        String firstAny = null;
        for (AppService svc : app.getServices()) {
            Object row = services.get(svc.getName());
            String url = externalUrlOf(row);
            if (url == null) continue;
            if (firstAny == null) firstAny = url;
            if (svc.getRole() == AppServiceRole.BACKEND) continue;
            String path = url.replaceFirst("^https?://[^/]+", "");
            if (path.isEmpty() || "/".equals(path)) {
                return url;
            }
            if (firstRoot == null && !path.equals("/api") && !path.startsWith("/api/")) {
                firstRoot = url;
            }
        }
        if (firstRoot != null) return firstRoot;

        // Dernier recours : n'importe quelle URL non NodePort dans le state
        for (Object v : services.values()) {
            String url = externalUrlOf(v);
            if (url != null && !url.matches("^https?://\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+.*")) {
                return url;
            }
        }
        return firstAny;
    }

    private static String externalUrlOf(Object row) {
        if (!(row instanceof Map<?, ?> m)) return null;
        Object ext = m.get("externalUrl");
        if (ext == null) return null;
        String url = String.valueOf(ext).trim();
        return url.isEmpty() ? null : url;
    }

    /**
     * Chemins health prioritaires : config service + variantes Ingress path-based (/api/…).
     */
    private List<String> collectHealthProbePaths(ManagedApplication app) {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        if (app != null && app.getServices() != null) {
            for (AppService svc : app.getServices()) {
                String raw = svc.getHealthCheckPath();
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String path = raw.trim();
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }
                paths.add(path);
                // Exposé derrière /api (Traefik rewrite) — cas backend classique
                if (!path.startsWith("/api/") && !path.equals("/api")) {
                    paths.add("/api" + (path.startsWith("/") ? path : "/" + path));
                }
                String ctx = svc.getContextPath();
                if (ctx != null && !ctx.isBlank()) {
                    String c = ctx.trim();
                    if (!c.startsWith("/")) {
                        c = "/" + c;
                    }
                    if (c.endsWith("/")) {
                        c = c.substring(0, c.length() - 1);
                    }
                    if (!path.startsWith(c + "/") && !path.equals(c)) {
                        paths.add(c + path);
                    }
                }
            }
        }
        // Candidats multi-technologies (ordre : génériques d'abord, Spring ensuite, root en dernier)
        for (String p : List.of(
                "/api/health",
                "/health",
                "/api/healthz",
                "/healthz",
                "/api/ready",
                "/ready",
                "/readyz",
                "/livez",
                "/api/v1/health",
                "/v1/health",
                "/api/status",
                "/status",
                "/api/actuator/health",
                "/actuator/health",
                "/api/actuator/health/liveness",
                "/actuator/health/liveness",
                "/"
        )) {
            paths.add(p);
        }
        List<String> ordered = new ArrayList<>(paths);
        if (ordered.size() > MAX_HEALTH_PROBE_PATHS) {
            return new ArrayList<>(ordered.subList(0, MAX_HEALTH_PROBE_PATHS));
        }
        return ordered;
    }

    private Map<String, Object> probeHttpHealth(String appUrl, List<String> preferredPaths) {
        Map<String, Object> health = new java.util.LinkedHashMap<>();
        if (appUrl == null || appUrl.isBlank()) {
            health.put("checked", false);
            health.put("ok", null);
            health.put("url", null);
            health.put("message", "Pas d'URL publique");
            return health;
        }
        health.put("url", appUrl);
        String base = appUrl.endsWith("/") ? appUrl.substring(0, appUrl.length() - 1) : appUrl.trim();
        List<String> paths = preferredPaths != null && !preferredPaths.isEmpty()
                ? preferredPaths
                : List.of("/api/health", "/health", "/api/actuator/health", "/actuator/health", "/");

        java.net.URI publicUri;
        try {
            publicUri = java.net.URI.create(base);
        } catch (Exception e) {
            health.put("checked", false);
            health.put("ok", null);
            health.put("message", "URL invalide");
            return health;
        }
        String publicHost = publicUri.getHost();
        // Domaine custom / .local : le backend Docker ne résout pas le hosts Windows.
        // On sonde Traefik (IP master) avec le header Host = hostname public.
        boolean rewriteViaIngressIp = shouldProbeViaIngressIp(publicHost);
        String probeScheme = publicUri.getScheme() != null ? publicUri.getScheme() : "http";
        String probeAuthority = rewriteViaIngressIp
                ? (ingressProbeIp != null && !ingressProbeIp.isBlank() ? ingressProbeIp.trim() : "192.168.92.10")
                : (publicUri.getPort() > 0 ? publicHost + ":" + publicUri.getPort() : publicHost);
        String probeBase = probeScheme + "://" + probeAuthority;

        try {
            int lastCode = 0;
            String lastErr = null;
            String lastPublicTarget = null;
            String lastProbeTarget = null;
            List<String> tried = new ArrayList<>();
            for (String path : paths) {
                String pathPart = (path == null || path.isBlank()) ? "/" : path;
                if (!pathPart.startsWith("/")) {
                    pathPart = "/" + pathPart;
                }
                String publicTarget = "/".equals(pathPart) ? base + "/" : base + pathPart;
                String probeTarget = "/".equals(pathPart) ? probeBase + "/" : probeBase + pathPart;
                tried.add(pathPart);
                lastPublicTarget = publicTarget;
                lastProbeTarget = probeTarget;
                try {
                    int code = httpGetStatus(probeTarget, rewriteViaIngressIp ? publicHost : null);
                    lastCode = code;
                    if (code >= 200 && code < 300) {
                        health.put("checked", true);
                        health.put("ok", true);
                        health.put("statusCode", code);
                        health.put("probedUrl", publicTarget);
                        health.put("message", "HTTP " + code + " OK (" + pathPart + ")"
                                + (rewriteViaIngressIp ? " via Traefik+" + publicHost : ""));
                        health.put("triedPaths", tried);
                        return health;
                    }
                    if (code == 401 || code == 403) {
                        health.put("checked", true);
                        health.put("ok", true);
                        health.put("statusCode", code);
                        health.put("probedUrl", publicTarget);
                        health.put("message", "HTTP " + code + " (protégé, joignable) — " + pathPart);
                        health.put("triedPaths", tried);
                        return health;
                    }
                    if (code == 404 || code == 405) {
                        continue;
                    }
                } catch (Exception e) {
                    lastErr = e.getMessage();
                }
            }
            health.put("checked", true);
            health.put("ok", false);
            health.put("statusCode", lastCode > 0 ? lastCode : null);
            health.put("probedUrl", lastPublicTarget);
            health.put("triedPaths", tried);
            if (lastErr != null) {
                health.put("message", lastErr
                        + (rewriteViaIngressIp ? " (sonde " + lastProbeTarget + " Host=" + publicHost + ")" : ""));
            } else {
                health.put("message", "Aucun endpoint health trouvé (dernier HTTP " + lastCode + ")");
            }
        } catch (Exception e) {
            health.put("checked", true);
            health.put("ok", false);
            health.put("message", e.getMessage());
        }
        return health;
    }

    /**
     * Custom domain / .local hors nip.io → sonder via IP Traefik + Host header
     * (le fichier hosts Windows n'existe pas dans le conteneur backend).
     */
    private static boolean shouldProbeViaIngressIp(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String h = host.toLowerCase();
        if (h.endsWith(".nip.io")) {
            return false;
        }
        if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        return true;
    }

    /**
     * GET HTTP. Si hostHeader est fourni, force le header Host (requis pour Traefik
     * quand on sonde l'IP au lieu du DNS local Windows).
     * HttpURLConnection ignore Host — on utilise HttpClient + allowRestrictedHeaders.
     */
    private static int httpGetStatus(String url, String hostHeader) throws Exception {
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        var client = java.net.http.HttpClient.newBuilder()
                .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
                .connectTimeout(java.time.Duration.ofSeconds(3))
                .build();
        var builder = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(4))
                .GET();
        if (hostHeader != null && !hostHeader.isBlank()) {
            builder.header("Host", hostHeader);
        }
        java.net.http.HttpResponse<Void> response = client.send(
                builder.build(),
                java.net.http.HttpResponse.BodyHandlers.discarding());
        return response.statusCode();
    }

    /**
     * Logs d'un workload (label app) ou d'un pod nommé.
     */
    public Map<String, Object> getDeploymentLogs(UUID appId, UUID deploymentId, String workload, Integer tailLines) {
        loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        if (deployment.getStatus() == AppDeploymentStatus.STOPPED) {
            throw new AppValidationException("Environnement arrêté — logs indisponibles.");
        }
        if (!k8sManifestApplyService.isConfigured()) {
            throw new AppValidationException("Cluster K8s non configuré.");
        }
        if (workload == null || workload.isBlank()) {
            throw new AppValidationException("Paramètre workload requis (ex. front, api, db-mydb).");
        }
        int tail = tailLines != null ? tailLines : 300;
        return k8sManifestApplyService.getPodLogs(deployment.getNamespace(), workload.trim(), tail);
    }

    /**
     * Résumé live du pipeline GitLab CI lié au déploiement (jobs + statut).
     */
    public Map<String, Object> getDeploymentCiPipeline(UUID appId, UUID deploymentId) {
        loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        Long pipelineId = deployment.getGitlabPipelineId();
        if (pipelineId == null) {
            throw new AppValidationException("Aucun pipeline CI associé à ce déploiement.");
        }
        Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("pipelineId", summary.getOrDefault("id", pipelineId));
        out.put("status", summary.get("status"));
        out.put("webUrl", summary.get("webUrl"));
        out.put("ref", summary.get("ref"));
        out.put("jobStatusCount", summary.getOrDefault("jobStatusCount", Map.of()));
        out.put("jobs", summary.getOrDefault("jobs", List.of()));
        out.put("dataSource", "gitlab");
        return out;
    }

    /**
     * Logs texte d'un job GitLab du pipeline de ce déploiement.
     */
    public String getDeploymentCiJobLogs(UUID appId, UUID deploymentId, Long jobId) {
        loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        if (deployment.getGitlabPipelineId() == null) {
            throw new AppValidationException("Aucun pipeline CI associé à ce déploiement.");
        }
        if (jobId == null) {
            throw new AppValidationException("jobId requis.");
        }
        return gitLabService.getJobLogs(jobId);
    }

    // =====================================================================
    // Reveal secret (audit conseillé)
    // =====================================================================

    @Transactional(readOnly = true)
    public String revealSecret(UUID appId, RevealSecretRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        String value = switch (request.getType()) {
            case GIT_TOKEN -> serviceRepository.findByIdAndManagedApplication_Id(request.getTargetId(), appId)
                    .map(AppService::getGitToken)
                    .orElseThrow(() -> new AppValidationException("Service introuvable."));
            case DB_PASSWORD -> databaseRepository.findByIdAndApplication_Id(request.getTargetId(), appId)
                    .map(AppDatabase::getRootPassword)
                    .orElseThrow(() -> new AppValidationException("Base introuvable."));
            case ENV_VAR -> {
                ServiceEnvVar envVar = envVarRepository.findById(request.getTargetId())
                        .orElseThrow(() -> new AppValidationException("Variable introuvable."));
                if (envVar.getAppService() == null || envVar.getAppService().getManagedApplication() == null
                        || !envVar.getAppService().getManagedApplication().getId().equals(app.getId())) {
                    throw new AppValidationException("Variable hors de cette application.");
                }
                yield envVar.getVarValue();
            }
        };
        log.info("🔓 [audit] Révélation d'un secret {} (target={}) pour l'application {}",
                request.getType(), request.getTargetId(), appId);
        return value;
    }

    // =====================================================================
    // Mapping (masquage systématique des secrets)
    // =====================================================================

    private ManagedAppResponse mapApp(ManagedApplication app, boolean withDetail) {
        List<AppServiceResponse> services = app.getServices().stream()
                .map(this::mapService).collect(Collectors.toList());
        List<AppDatabaseResponse> databases = app.getDatabases().stream()
                .map(this::mapDatabase).collect(Collectors.toList());

        AppDeploymentResponse last = null;
        List<String> warnings = new ArrayList<>();
        if (withDetail) {
            AppDeployment lastEntity = deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(app.getId())
                    .stream().findFirst().orElse(null);
            if (lastEntity != null && lastEntity.getStatus() == AppDeploymentStatus.DEPLOYING) {
                try {
                    deploymentService.getCiDeployStatus(lastEntity.getId());
                    lastEntity = deploymentRepository.findById(lastEntity.getId()).orElse(lastEntity);
                } catch (Exception e) {
                    log.debug("reconcile lastDeployment DEPLOYING {}: {}", lastEntity.getId(), e.getMessage());
                }
            }
            last = lastEntity != null ? mapDeployment(lastEntity, app) : null;
            for (AppService svc : app.getServices()) {
                if (svc.getRole() == AppServiceRole.BACKEND && svc.getDependsOnDatabaseId() == null
                        && app.getDatabases().isEmpty()) {
                    warnings.add("Le backend « " + svc.getName() + " » n'est lié à aucune base de données.");
                }
            }
        }

        return ManagedAppResponse.builder()
                .id(app.getId())
                .name(app.getName())
                .slug(app.getSlug())
                .description(app.getDescription())
                .customHostname(app.getCustomHostname())
                .createdByUsername(app.getCreatedBy() != null ? app.getCreatedBy().getUsername() : null)
                .createdAt(app.getCreatedAt())
                .updatedAt(app.getUpdatedAt())
                .services(services)
                .databases(databases)
                .lastDeployment(last)
                .warnings(warnings)
                .build();
    }

    private AppServiceResponse mapService(AppService svc) {
        List<EnvVarResponse> envVars = svc.getEnvVars().stream()
                .map(this::mapEnvVar).collect(Collectors.toList());
        return AppServiceResponse.builder()
                .id(svc.getId())
                .name(svc.getName())
                .role(svc.getRole())
                .gitRepositoryUrl(svc.getGitRepositoryUrl())
                .hasGitToken(svc.getGitToken() != null && !svc.getGitToken().isEmpty())
                .gitBranch(svc.getGitBranch())
                .dockerfilePath(svc.getDockerfilePath())
                .buildContext(svc.getBuildContext())
                .exposedPort(svc.getExposedPort())
                .dependsOnServiceId(svc.getDependsOnServiceId())
                .dependsOnDatabaseId(svc.getDependsOnDatabaseId())
                .dbUrlEnvVar(svc.getDbUrlEnvVar())
                .replicas(svc.getReplicas())
                .healthCheckPath(svc.getHealthCheckPath())
                .contextPath(svc.getContextPath())
                .cpuRequest(svc.getCpuRequest())
                .cpuLimit(svc.getCpuLimit())
                .memoryRequest(svc.getMemoryRequest())
                .memoryLimit(svc.getMemoryLimit())
                .envVars(envVars)
                .createdAt(svc.getCreatedAt() != null
                        ? svc.getCreatedAt().atZone(ZoneId.systemDefault()).toInstant() : null)
                .updatedAt(null)
                .build();
    }

    private AppDatabaseResponse mapDatabase(AppDatabase db) {
        boolean hasPassword = db.getRootPassword() != null && !db.getRootPassword().isEmpty();
        return AppDatabaseResponse.builder()
                .id(db.getId())
                .name(db.getName())
                .dbFamily(db.getDbFamily())
                .engine(db.getEngine())
                .version(db.getVersion())
                .dbName(db.getDbName())
                .rootUser(db.getRootUser())
                .rootPassword(hasPassword ? MASK : null)
                .hasRootPassword(hasPassword)
                .exposedPort(db.getExposedPort())
                .storageSize(db.getStorageSize())
                .generatedConnectionUrl(connectionUrlService.maskConnectionUrl(db, db.getGeneratedConnectionUrl()))
                .createdAt(db.getCreatedAt())
                .updatedAt(db.getUpdatedAt())
                .build();
    }

    private EnvVarResponse mapEnvVar(ServiceEnvVar envVar) {
        return EnvVarResponse.builder()
                .id(envVar.getId())
                .varKey(envVar.getVarKey())
                .varValue(envVar.isSecret() ? MASK : envVar.getVarValue())
                .isSecret(envVar.isSecret())
                .build();
    }

    private AppDeploymentResponse mapDeployment(AppDeployment deployment, ManagedApplication app) {
        List<AppDatabaseResponse> databases = app.getDatabases().stream()
                .map(this::mapDatabase).collect(Collectors.toList());

        Instant serverTime = Instant.now();
        Integer ttlHours = null;
        Instant expiresAt = null;
        Instant readyAt = null;
        Long remainingSeconds = null;
        String gitBranch = null;

        UUID envId = deployment.getEphemeralEnvironmentId();
        if (envId != null) {
            EphemeralEnvironment env = environmentRepository.findById(envId).orElse(null);
            if (env != null) {
                ttlHours = env.getTtlHours();
                readyAt = toInstant(env.getReadyAt());
                expiresAt = toInstant(env.getExpiresAt());
                if (env.getGitBranch() != null && !env.getGitBranch().isBlank()) {
                    gitBranch = env.getGitBranch().trim();
                }

                // Déploiement RUNNING mais TTL jamais armé (onReady ignoré / env détruit trop tôt)
                if (deployment.getStatus() == AppDeploymentStatus.RUNNING
                        && (readyAt == null || expiresAt == null)) {
                    Instant base = deployment.getDeployedAt() != null
                            ? deployment.getDeployedAt()
                            : deployment.getCreatedAt();
                    int ttl = ttlHours != null && ttlHours > 0 ? ttlHours : 4;
                    if (base != null) {
                        readyAt = base;
                        expiresAt = base.plusSeconds(ttl * 3600L);
                        // Répare l'entité pour les prochains polls / scheduler
                        try {
                            LocalDateTime readyLdt = LocalDateTime.ofInstant(base, ZoneId.systemDefault());
                            env.setReadyAt(readyLdt);
                            env.setExpiresAt(readyLdt.plusHours(ttl));
                            if (env.getStatus() == EnvironmentStatus.DESTROYED
                                    || env.getStatus() == EnvironmentStatus.EXPIRED
                                    || env.getStatus() == EnvironmentStatus.PENDING
                                    || env.getStatus() == EnvironmentStatus.BUILDING) {
                                env.setStatus(EnvironmentStatus.RUNNING);
                                env.setDestroyedAt(null);
                            }
                            environmentRepository.save(env);
                            log.info("TTL réparé pour env {} — ready={}, expires={} ({}h)",
                                    envId, env.getReadyAt(), env.getExpiresAt(), ttl);
                        } catch (Exception e) {
                            log.warn("Impossible de réparer TTL env {}: {}", envId, e.getMessage());
                        }
                    }
                }

                if (expiresAt != null
                        && deployment.getStatus() != AppDeploymentStatus.STOPPED
                        && deployment.getStatus() != AppDeploymentStatus.FAILED) {
                    remainingSeconds = expiresAt.getEpochSecond() - serverTime.getEpochSecond();
                }
            }
        }
        // Fallback TTL depuis servicesState si env absent
        if (ttlHours == null && deployment.getServicesState() != null
                && deployment.getServicesState().get("ttlHours") instanceof Number n) {
            ttlHours = n.intValue();
        }

        return AppDeploymentResponse.builder()
                .id(deployment.getId())
                .namespace(deployment.getNamespace())
                .status(deployment.getStatus())
                .gitlabPipelineId(deployment.getGitlabPipelineId())
                .deployedAt(deployment.getDeployedAt())
                .servicesState(deployment.getServicesState())
                .createdAt(deployment.getCreatedAt())
                .updatedAt(deployment.getUpdatedAt())
                .databases(databases)
                .gitBranch(gitBranch)
                .ttlHours(ttlHours)
                .expiresAt(expiresAt)
                .readyAt(readyAt)
                .serverTime(serverTime)
                .remainingSeconds(remainingSeconds)
                .build();
    }

    private static Instant toInstant(LocalDateTime ldt) {
        if (ldt == null) {
            return null;
        }
        return ldt.atZone(ZoneId.systemDefault()).toInstant();
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private ManagedApplication loadOwnedApp(UUID id) {
        User user = getCurrentUser();
        return appRepository.findByIdAndCreatedBy(id, user)
                .orElseThrow(() -> new AppValidationException("Application introuvable."));
    }

    private String uniqueSlug(String name) {
        String base = AppNaming.slug(name);
        String slug = base;
        int attempt = 0;
        while (appRepository.existsBySlug(slug)) {
            attempt++;
            slug = base + "-" + Integer.toHexString(Objects.hash(name, attempt) & 0xffff);
        }
        return slug;
    }

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new AppValidationException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new AppValidationException("Utilisateur non trouvé."));
    }

    private static String orDefault(String value, String def) {
        return (value != null && !value.isBlank()) ? value : def;
    }

    private static String orNull(String value) {
        return (value != null && !value.isBlank() && !MASK.equals(value)) ? value : null;
    }
}
