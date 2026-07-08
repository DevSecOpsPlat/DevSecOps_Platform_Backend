package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.*;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import com.backend.devsecopsplatform_backend.repository.AppDatabaseRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.ServiceEnvVarRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
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
@RequiredArgsConstructor
public class ApplicationManagementService {

    private static final String MASK = AppConnectionUrlService.MASK;

    private final ManagedApplicationRepository appRepository;
    private final AppServiceRepository serviceRepository;
    private final AppDatabaseRepository databaseRepository;
    private final ServiceEnvVarRepository envVarRepository;
    private final AppDeploymentRepository deploymentRepository;
    private final UserRepository userRepository;
    private final AppConnectionUrlService connectionUrlService;
    private final AppDeploymentService deploymentService;
    private final ImageTagAvailabilityService imageTagAvailability;

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
        return mapApp(appRepository.save(app), true);
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
    public void deleteService(UUID appId, UUID serviceId) {
        loadOwnedApp(appId);
        AppService svc = serviceRepository.findByIdAndManagedApplication_Id(serviceId, appId)
                .orElseThrow(() -> new AppValidationException("Service introuvable dans cette application."));
        if (serviceRepository.countByDependsOnServiceId(serviceId) > 0) {
            throw new AppValidationException(
                    "Ce service est référencé par un ou plusieurs autres services. Retirez la dépendance d'abord.");
        }
        serviceRepository.delete(svc);
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
    public void deleteDatabase(UUID appId, UUID databaseId) {
        loadOwnedApp(appId);
        AppDatabase db = databaseRepository.findByIdAndApplication_Id(databaseId, appId)
                .orElseThrow(() -> new AppValidationException("Base introuvable dans cette application."));
        if (serviceRepository.countByDependsOnDatabaseId(databaseId) > 0) {
            throw new AppValidationException(
                    "Cette base est référencée par un ou plusieurs services. Retirez la dépendance d'abord.");
        }
        databaseRepository.delete(db);
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

    public List<AppDeploymentResponse> listDeployments(UUID appId) {
        ManagedApplication app = loadOwnedApp(appId);
        return deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(appId).stream()
                .map(d -> mapDeployment(d, app))
                .collect(Collectors.toList());
    }

    public AppDeploymentResponse getDeployment(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        return mapDeployment(deployment, app);
    }

    @Transactional
    public AppDeploymentResponse teardownDeployment(UUID appId, UUID deploymentId) {
        ManagedApplication app = loadOwnedApp(appId);
        AppDeployment deployment = deploymentRepository.findByIdAndApplication_Id(deploymentId, appId)
                .orElseThrow(() -> new AppValidationException("Déploiement introuvable."));
        return mapDeployment(deploymentService.teardown(deployment), app);
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
            last = deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(app.getId()).stream()
                    .findFirst().map(d -> mapDeployment(d, app)).orElse(null);
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
                .build();
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
