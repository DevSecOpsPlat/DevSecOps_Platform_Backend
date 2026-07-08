package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.*;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
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
        serviceRepository.delete(svc);
    }

    private void applyServiceScalars(AppService svc, AppServiceRequest request) {
        svc.setName(request.getName());
        svc.setRole(request.getRole());
        svc.setGitRepositoryUrl(request.getGitRepositoryUrl());
        svc.setGitBranch(orDefault(request.getGitBranch(), "main"));
        svc.setDockerfilePath(orDefault(request.getDockerfilePath(), "Dockerfile"));
        svc.setBuildContext(orDefault(request.getBuildContext(), "."));
        svc.setExposedPort(request.getExposedPort());
        svc.setDependsOnServiceId(request.getDependsOnServiceId());
        svc.setDependsOnDatabaseId(request.getDependsOnDatabaseId());
        svc.setDbUrlEnvVar(orDefault(request.getDbUrlEnvVar(), "DATABASE_URL"));
        svc.setReplicas(request.getReplicas() != null ? request.getReplicas() : 1);
        svc.setHealthCheckPath(request.getHealthCheckPath());
        svc.setCpuRequest(orDefault(request.getCpuRequest(), "100m"));
        svc.setCpuLimit(orDefault(request.getCpuLimit(), "500m"));
        svc.setMemoryRequest(orDefault(request.getMemoryRequest(), "128Mi"));
        svc.setMemoryLimit(orDefault(request.getMemoryLimit(), "512Mi"));
    }

    private void validateServiceRequest(ManagedApplication app, AppServiceRequest request, UUID selfId) {
        if (request.getDependsOnDatabaseId() != null) {
            boolean exists = app.getDatabases().stream()
                    .anyMatch(d -> d.getId().equals(request.getDependsOnDatabaseId()));
            if (!exists) {
                if (app.getDatabases().isEmpty()) {
                    throw new AppValidationException(
                            "Un backend nécessite une base de données. Ajoutez d'abord une base ou retirez la dépendance.");
                }
                throw new AppValidationException("La base de données liée n'existe pas dans cette application.");
            }
        }
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
    }

    // =====================================================================
    // Databases
    // =====================================================================

    @Transactional
    public AppDatabaseResponse addDatabase(UUID appId, AppDatabaseRequest request) {
        ManagedApplication app = loadOwnedApp(appId);
        validateDatabaseRequest(request);

        AppDatabase db = new AppDatabase();
        db.setApplication(app);
        applyDatabaseScalars(db, request);
        db.setRootPassword(orNull(request.getRootPassword()));
        return mapDatabase(databaseRepository.save(db));
    }

    @Transactional
    public AppDatabaseResponse updateDatabase(UUID appId, UUID databaseId, AppDatabaseRequest request) {
        loadOwnedApp(appId);
        AppDatabase db = databaseRepository.findByIdAndApplication_Id(databaseId, appId)
                .orElseThrow(() -> new AppValidationException("Base introuvable dans cette application."));
        validateDatabaseRequest(request);
        applyDatabaseScalars(db, request);
        if (request.getRootPassword() != null && !request.getRootPassword().isBlank()
                && !MASK.equals(request.getRootPassword())) {
            db.setRootPassword(request.getRootPassword());
        }
        return mapDatabase(databaseRepository.save(db));
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

    private void applyDatabaseScalars(AppDatabase db, AppDatabaseRequest request) {
        db.setName(request.getName());
        db.setDbFamily(request.getDbFamily());
        db.setEngine(request.getEngine());
        db.setVersion(request.getVersion());
        db.setDbName(request.getDbName());
        db.setRootUser(request.getRootUser());
        db.setExposedPort(request.getExposedPort() != null ? request.getExposedPort()
                : request.getEngine().defaultPort());
        db.setStorageSize(orDefault(request.getStorageSize(), "1Gi"));
    }

    private void validateDatabaseRequest(AppDatabaseRequest request) {
        if (request.getEngine().family() != request.getDbFamily()) {
            throw new AppValidationException("Le moteur « " + request.getEngine()
                    + " » n'appartient pas à la famille " + request.getDbFamily() + ".");
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
