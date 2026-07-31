package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbFamily;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import lombok.Builder;
import lombok.Value;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Générateur de manifestes Kubernetes d'une application managée (rôle "K8sManifestGenerator"
 * du cadrage §1). Ne fait que produire des chaînes YAML — rien n'est appliqué ici.
 *
 * <p>Sortie organisée en deux ensembles distincts : les manifestes des bases (à appliquer et
 * attendre {@code Ready} en premier via {@code kubectl wait -l tier=database}) puis ceux des
 * services. Manifestes idempotents (destinés à {@code kubectl apply}).</p>
 *
 * <p>Base : Deployment (NoSQL) ou StatefulSet (SQL) sur l'image officielle
 * {@code <engine>:<version>} + Service ClusterIP {@code db-<name>} + PVC {@code storage_size} +
 * Secret credentials (variables d'env attendues par l'image selon le moteur), label
 * {@code tier: database}.</p>
 *
 * <p>Service : Deployment (replicas, image {@code $CI_REGISTRY_IMAGE/<name>:<tag>},
 * imagePullSecrets) + Service ClusterIP + Ingress/NodePort d'exposition externe + probes +
 * requests/limits. Les {@code service_env_var} secrètes passent par un Secret ; l'URL BD est
 * injectée via le Secret de la base sous {@code db_url_env_var}.</p>
 */
@Service
public class AppK8sManifestService {

    private static final String CONNECTION_URL_KEY = "CONNECTION_URL";
    private static final String JDBC_URL_KEY = "JDBC_URL";

    private final AppConnectionUrlService connectionUrlService;

    public AppK8sManifestService(AppConnectionUrlService connectionUrlService) {
        this.connectionUrlService = connectionUrlService;
    }

    @Value
    @Builder
    public static class ManifestOptions {
        String registryServer;    // ex. registry.gitlab.com (pour l'imagePullSecret)
        String registryUsername;
        String registryPassword;
        String pullSecretName;     // ex. gitlab-registry
        boolean ingressEnabled;
        String ingressDomain;      // ex. 192.168.130.138.nip.io → app-<ns>.<domain>
        /**
         * Hostname override (custom domain). Si renseigné, remplace
         * {@code app-{ns}.{ingressDomain}} pour l'Ingress applicatif.
         */
        String customHostname;
        boolean pathBasedRouting; // true = un hôte /app + chemins /api ; false = hôte par service
        /** Images complètes, validées par nom K8s, pour le déploiement atomique multi-service. */
        Map<String, String> resolvedServiceImages;
        /** Contrôleur ingress : {@code traefik} (K3s) ou {@code nginx}. */
        String ingressController;
        /** ingressClassName (ex. traefik sur K3s). */
        String ingressClassName;
        /** TTL namespace (heures) — annotation pour opérations / schedulers. */
        Integer namespaceTtlHours;
        /** ID déploiement — annotation sur le namespace. */
        String deploymentId;
        /** Active ResourceQuota + LimitRange sur le namespace. */
        boolean resourceQuotaEnabled;
        String namespaceCpuQuota;
        String namespaceMemoryQuota;
    }

    private String resolveServiceImage(String k8sName, ManifestOptions opts) {
        Map<String, String> images = opts.getResolvedServiceImages();
        if (images != null) {
            String mapped = images.get(k8sName);
            if (mapped != null && !mapped.isBlank() && !mapped.contains("${")) {
                return mapped.trim();
            }
        }
        throw new AppValidationException("Image CI résolue manquante pour le service: " + k8sName);
    }

    // =====================================================================
    // Bundles
    // =====================================================================

    /**
     * Prélude + bases : Namespace, imagePullSecret, puis pour chaque base
     * Secret + PVC + (Deployment|StatefulSet) + Service. À appliquer en premier.
     */
    public String generateDatabaseBundle(ManagedApplication app, String namespace, ManifestOptions opts) {
        List<Map<String, Object>> docs = new ArrayList<>();
        docs.add(namespaceManifest(namespace, opts));
        docs.add(imagePullSecretManifest(namespace, opts));
        if (opts.isResourceQuotaEnabled()) {
            docs.add(resourceQuotaManifest(namespace, opts));
            docs.add(limitRangeManifest(namespace));
        }

        for (AppDatabase db : app.getDatabases()) {
            String svcName = connectionUrlService.serviceName(db);
            boolean sql = db.getEngine().family() == DbFamily.SQL;
            docs.add(dbCredentialsSecret(db, namespace, svcName));
            if (!sql) {
                docs.add(dbPvc(db, namespace, svcName));
            }
            docs.add(sql ? dbStatefulSet(db, namespace, svcName) : dbDeployment(db, namespace, svcName));
            docs.add(dbService(db, namespace, svcName));
        }
        return dumpAll(docs);
    }

    /**
     * Services : pour chaque service Secret (env secrètes) + Deployment + Service +
     * Ingress/NodePort. À appliquer après que les bases soient Ready.
     */
    public String generateServiceBundle(ManagedApplication app, String namespace, ManifestOptions opts) {
        return generateServiceWaveBundle(app, namespace, opts, app.getServices(), true);
    }

    /**
     * Manifestes d'une vague de services (sans namespace). L'Ingress est ajouté uniquement
     * sur la dernière vague ({@code includeIngress=true}).
     */
    public String generateServiceWaveBundle(
            ManagedApplication app,
            String namespace,
            ManifestOptions opts,
            List<AppService> waveServices,
            boolean includeIngress
    ) {
        List<Map<String, Object>> docs = new ArrayList<>();
        for (AppService svc : waveServices) {
            String name = AppNaming.k8sName(svc.getName());
            Map<String, Object> secret = serviceSecret(svc, namespace, name);
            if (secret != null) {
                docs.add(secret);
            }
            docs.add(serviceDeployment(app, svc, namespace, name, opts));
            if (svc.getExposedPort() != null) {
                docs.add(serviceClusterIp(svc, namespace, name));
            }
        }
        if (includeIngress) {
            appendIngressDocs(app, namespace, opts, docs);
        }
        return dumpAll(docs);
    }

    /**
     * Ingress + Middleware Traefik uniquement — à appliquer après que les workloads soient Ready
     * (évite qu'un hang CRD bloque l'attente pods / le statut CI).
     */
    public String generateIngressBundle(ManagedApplication app, String namespace, ManifestOptions opts) {
        List<Map<String, Object>> docs = new ArrayList<>();
        appendIngressDocs(app, namespace, opts, docs);
        return dumpAll(docs);
    }

    private void appendIngressDocs(
            ManagedApplication app,
            String namespace,
            ManifestOptions opts,
            List<Map<String, Object>> docs
    ) {
        if (opts.isIngressEnabled() && opts.isPathBasedRouting()) {
            docs.addAll(applicationPathMiddlewares(app, namespace, opts));
            Map<String, Object> ingress = applicationIngress(app, namespace, opts);
            if (ingress != null) {
                docs.add(ingress);
            }
        } else {
            for (AppService svc : app.getServices()) {
                if (isExternallyExposed(svc) && svc.getExposedPort() != null) {
                    String name = AppNaming.k8sName(svc.getName());
                    if (opts.isIngressEnabled()) {
                        docs.add(serviceIngress(svc, namespace, name, opts));
                    } else {
                        docs.add(serviceNodePort(svc, namespace, name));
                    }
                }
            }
        }
    }

    // =====================================================================
    // Namespace + imagePullSecret
    // =====================================================================

    private Map<String, Object> namespaceManifest(String namespace, ManifestOptions opts) {
        Map<String, Object> m = base("v1", "Namespace");
        Map<String, Object> metadata = meta(namespace, null);
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("app.kubernetes.io/managed-by", "devsecops-platform");
        if (opts.getDeploymentId() != null && !opts.getDeploymentId().isBlank()) {
            labels.put("devsecops.platform/deployment-id", opts.getDeploymentId().trim());
        }
        metadata.put("labels", labels);

        Map<String, String> annotations = new LinkedHashMap<>();
        if (opts.getNamespaceTtlHours() != null && opts.getNamespaceTtlHours() > 0) {
            annotations.put("devsecops.platform/ttl-hours", String.valueOf(opts.getNamespaceTtlHours()));
        }
        if (!annotations.isEmpty()) {
            metadata.put("annotations", annotations);
        }
        m.put("metadata", metadata);
        return m;
    }

    private Map<String, Object> resourceQuotaManifest(String namespace, ManifestOptions opts) {
        String cpu = opts.getNamespaceCpuQuota() != null ? opts.getNamespaceCpuQuota() : "4";
        String memory = opts.getNamespaceMemoryQuota() != null ? opts.getNamespaceMemoryQuota() : "8Gi";

        Map<String, Object> hard = new LinkedHashMap<>();
        hard.put("requests.cpu", cpu);
        hard.put("requests.memory", memory);
        hard.put("limits.cpu", cpu);
        hard.put("limits.memory", memory);
        hard.put("pods", "20");
        hard.put("persistentvolumeclaims", "10");

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("hard", hard);

        Map<String, Object> m = base("v1", "ResourceQuota");
        m.put("metadata", meta("env-quota", namespace));
        m.put("spec", spec);
        return m;
    }

    private Map<String, Object> limitRangeManifest(String namespace) {
        Map<String, Object> defaultRequest = Map.of("cpu", "50m", "memory", "64Mi");
        Map<String, Object> defaultLimit = Map.of("cpu", "1", "memory", "1Gi");
        Map<String, Object> limit = new LinkedHashMap<>();
        limit.put("type", "Container");
        limit.put("defaultRequest", defaultRequest);
        limit.put("default", defaultLimit);

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("limits", List.of(limit));

        Map<String, Object> m = base("v1", "LimitRange");
        m.put("metadata", meta("env-limits", namespace));
        m.put("spec", spec);
        return m;
    }

    private Map<String, Object> imagePullSecretManifest(String namespace, ManifestOptions opts) {
        String server = opts.getRegistryServer();
        String user = opts.getRegistryUsername() != null ? opts.getRegistryUsername() : "";
        String pass = opts.getRegistryPassword() != null ? opts.getRegistryPassword() : "";
        String auth = Base64.getEncoder().encodeToString((user + ":" + pass).getBytes());
        String dockerConfig = "{\"auths\":{\"" + server + "\":{\"username\":\"" + user + "\",\"password\":\""
                + pass + "\",\"auth\":\"" + auth + "\"}}}";

        Map<String, Object> m = base("v1", "Secret");
        m.put("metadata", meta(opts.getPullSecretName(), namespace));
        m.put("type", "kubernetes.io/dockerconfigjson");
        Map<String, Object> stringData = new LinkedHashMap<>();
        stringData.put(".dockerconfigjson", dockerConfig);
        m.put("stringData", stringData);
        return m;
    }

    // =====================================================================
    // Databases
    // =====================================================================

    private Map<String, Object> dbCredentialsSecret(AppDatabase db, String namespace, String svcName) {
        Map<String, Object> m = base("v1", "Secret");
        m.put("metadata", meta(svcName + "-credentials", namespace));
        Map<String, Object> data = new LinkedHashMap<>();
        // Utilisateur effectif (MySQL/MariaDB → root), pas la valeur formulaire brute si trompeuse.
        data.put("ROOT_USER", nz(AppDatabaseRules.effectiveRootUser(db)));
        data.put("ROOT_PASSWORD", nz(db.getRootPassword()));
        data.put("DB_NAME", nz(db.getDbName()));
        data.put(CONNECTION_URL_KEY, nz(connectionUrlService.buildApplicationConnectionUrl(db, namespace)));
        data.put(JDBC_URL_KEY, nz(connectionUrlService.buildConnectionUrl(db, namespace)));
        m.put("stringData", data);
        return m;
    }

    private Map<String, Object> dbPvc(AppDatabase db, String namespace, String svcName) {
        Map<String, Object> m = base("v1", "PersistentVolumeClaim");
        m.put("metadata", meta(svcName + "-data", namespace));
        m.put("spec", pvcSpec(db.getStorageSize()));
        return m;
    }

    private Map<String, Object> pvcSpec(String storageSize) {
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("accessModes", List.of("ReadWriteOnce"));
        Map<String, Object> resources = new LinkedHashMap<>();
        Map<String, Object> requests = new LinkedHashMap<>();
        requests.put("storage", storageSize != null ? storageSize : "1Gi");
        resources.put("requests", requests);
        spec.put("resources", resources);
        return spec;
    }

    /** Deployment pour les bases NoSQL (PVC séparé). */
    private Map<String, Object> dbDeployment(AppDatabase db, String namespace, String svcName) {
        int port = dbPort(db);
        Map<String, Object> container = dbContainer(db, svcName);
        container.put("volumeMounts", List.of(volumeMount(svcName + "-data", dbDataPath(db))));

        Map<String, Object> podSpec = new LinkedHashMap<>();
        podSpec.put("containers", List.of(container));
        podSpec.put("volumes", List.of(pvcVolume(svcName + "-data", svcName + "-data")));

        Map<String, Object> m = base("apps/v1", "Deployment");
        Map<String, Object> metadata = meta(svcName, namespace);
        metadata.put("labels", dbLabels(svcName));
        m.put("metadata", metadata);
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("replicas", 1);
        Map<String, Object> selector = new LinkedHashMap<>();
        selector.put("matchLabels", Map.of("app", svcName));
        spec.put("selector", selector);
        spec.put("template", podTemplate(dbLabels(svcName), podSpec));
        m.put("spec", spec);
        return m;
    }

    /** StatefulSet pour les bases SQL (volumeClaimTemplates). */
    private Map<String, Object> dbStatefulSet(AppDatabase db, String namespace, String svcName) {
        int port = dbPort(db);
        Map<String, Object> container = dbContainer(db, svcName);
        container.put("volumeMounts", List.of(volumeMount("data", dbDataPath(db))));

        Map<String, Object> podSpec = new LinkedHashMap<>();
        podSpec.put("containers", List.of(container));

        Map<String, Object> m = base("apps/v1", "StatefulSet");
        Map<String, Object> metadata = meta(svcName, namespace);
        metadata.put("labels", dbLabels(svcName));
        m.put("metadata", metadata);
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("serviceName", svcName);
        spec.put("replicas", 1);
        Map<String, Object> selector = new LinkedHashMap<>();
        selector.put("matchLabels", Map.of("app", svcName));
        spec.put("selector", selector);
        spec.put("template", podTemplate(dbLabels(svcName), podSpec));

        Map<String, Object> vct = new LinkedHashMap<>();
        vct.put("metadata", Map.of("name", "data"));
        vct.put("spec", pvcSpec(db.getStorageSize()));
        spec.put("volumeClaimTemplates", List.of(vct));

        m.put("spec", spec);
        return m;
    }

    private Map<String, Object> dbContainer(AppDatabase db, String svcName) {
        int containerListenPort = db.getEngine().defaultPort();
        Map<String, Object> container = new LinkedHashMap<>();
        container.put("name", svcName);
        container.put("image", dbImage(db));
        container.put("imagePullPolicy", "IfNotPresent");
        // Toujours le port natif du moteur dans le conteneur.
        container.put("ports", List.of(containerPort(containerListenPort)));
        List<Map<String, Object>> env = dbEnv(db, svcName + "-credentials");
        if (!env.isEmpty()) {
            container.put("env", env);
        }
        if (db.getEngine() == DbEngine.REDIS
                && db.getRootPassword() != null
                && !db.getRootPassword().isBlank()) {
            // Mot de passe via Secret (REDIS_PASSWORD), pas en clair dans le manifest.
            container.put("command", List.of("sh", "-c"));
            container.put("args", List.of("exec redis-server --requirepass \"$REDIS_PASSWORD\""));
        }
        container.put("readinessProbe", tcpProbe(containerListenPort, 10, 10));
        container.put("livenessProbe", tcpProbe(containerListenPort, 30, 20));
        container.put("resources", resources("100m", "1000m", "256Mi", "1Gi"));
        return container;
    }

    /** Variables d'env attendues par l'image officielle, alimentées depuis le Secret credentials. */
    private List<Map<String, Object>> dbEnv(AppDatabase db, String secretName) {
        List<Map<String, Object>> env = new ArrayList<>();
        switch (db.getEngine()) {
            case POSTGRES -> {
                env.add(envFromSecret("POSTGRES_USER", secretName, "ROOT_USER"));
                env.add(envFromSecret("POSTGRES_PASSWORD", secretName, "ROOT_PASSWORD"));
                env.add(envFromSecret("POSTGRES_DB", secretName, "DB_NAME"));
                env.add(envPlain("PGDATA", "/var/lib/postgresql/data/pgdata"));
            }
            case MARIADB -> {
                // rootUser n'est PAS mappé (pas de MARIADB_USER) — seul le root password l'est.
                env.add(envFromSecret("MARIADB_ROOT_PASSWORD", secretName, "ROOT_PASSWORD"));
                env.add(envFromSecret("MARIADB_DATABASE", secretName, "DB_NAME"));
            }
            case MYSQL -> {
                // rootUser n'est PAS mappé (MYSQL_USER=root ferait échouer l'entrypoint).
                env.add(envFromSecret("MYSQL_ROOT_PASSWORD", secretName, "ROOT_PASSWORD"));
                env.add(envFromSecret("MYSQL_DATABASE", secretName, "DB_NAME"));
            }
            case MONGODB -> {
                env.add(envFromSecret("MONGO_INITDB_ROOT_USERNAME", secretName, "ROOT_USER"));
                env.add(envFromSecret("MONGO_INITDB_ROOT_PASSWORD", secretName, "ROOT_PASSWORD"));
                env.add(envFromSecret("MONGO_INITDB_DATABASE", secretName, "DB_NAME"));
            }
            case REDIS -> {
                // Mot de passe via args --requirepass (voir dbContainer). Secret conservé pour l'URL.
                env.add(envFromSecret("REDIS_PASSWORD", secretName, "ROOT_PASSWORD"));
            }
            case CASSANDRA -> {
                // Pas d'auth env sur l'image officielle ; keyspace non créé au boot.
            }
        }
        return env;
    }

    private Map<String, Object> dbService(AppDatabase db, String namespace, String svcName) {
        int servicePort = dbPort(db); // exposedPort (ce que consomment les apps)
        int targetPort = db.getEngine().defaultPort(); // port réellement écouté dans le conteneur
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("selector", Map.of("app", svcName));
        spec.put("ports", List.of(servicePort(servicePort, targetPort)));
        spec.put("type", "ClusterIP");
        Map<String, Object> m = base("v1", "Service");
        m.put("metadata", meta(svcName, namespace));
        m.put("spec", spec);
        return m;
    }

    // =====================================================================
    // Application services
    // =====================================================================

    private Map<String, Object> serviceSecret(AppService svc, String namespace, String name) {
        Map<String, Object> data = new LinkedHashMap<>();
        for (ServiceEnvVar var : svc.getEnvVars()) {
            if (var.isSecret()) {
                data.put(var.getVarKey(), nz(var.getVarValue()));
            }
        }
        if (data.isEmpty()) {
            return null;
        }
        Map<String, Object> m = base("v1", "Secret");
        m.put("metadata", meta(name + "-secrets", namespace));
        m.put("stringData", data);
        return m;
    }

    private Map<String, Object> serviceDeployment(ManagedApplication app, AppService svc, String namespace,
                                                  String name, ManifestOptions opts) {
        Integer port = svc.getExposedPort();

        List<Map<String, Object>> env = new ArrayList<>();
        for (ServiceEnvVar var : svc.getEnvVars()) {
            if (var.isSecret()) {
                env.add(envFromSecret(var.getVarKey(), name + "-secrets", var.getVarKey()));
            } else {
                env.add(envPlain(var.getVarKey(),
                        resolveServiceUrlPlaceholders(nz(var.getVarValue()), app, svc, namespace)));
            }
        }
        // Injection BD : URL (+ user/password hors URL pour les engines JDBC / Cassandra).
        if (svc.getDependsOnDatabaseId() != null
                && AppServiceRules.canDependOnDatabase(svc.getRole())) {
            AppDatabase db = findDb(app, svc.getDependsOnDatabaseId());
            if (db != null) {
                String dbSvc = connectionUrlService.serviceName(db);
                String secret = dbSvc + "-credentials";
                String urlEnv = (svc.getDbUrlEnvVar() != null && !svc.getDbUrlEnvVar().isBlank())
                        ? svc.getDbUrlEnvVar() : "DATABASE_URL";
                String urlSecretKey = requiresJdbcUrl(urlEnv) ? JDBC_URL_KEY : CONNECTION_URL_KEY;
                env.add(envFromSecret(urlEnv, secret, urlSecretKey));
                if (AppDatabaseRules.credentialsOutsideUrl(db.getEngine())) {
                    env.add(envFromSecret("DATABASE_USER", secret, "ROOT_USER"));
                    env.add(envFromSecret("DATABASE_PASSWORD", secret, "ROOT_PASSWORD"));
                }
            }
        }
        AppService dependency = findServiceDependency(app, svc);
        if (svc.getRole() == AppServiceRole.FRONTEND && resolveFrontendApiBackend(app, svc) != null) {
            for (String alias : List.of(
                    "API_URL",
                    "PUBLIC_API_URL",
                    "VITE_API_URL",
                    "VUE_APP_API_URL",
                    "REACT_APP_API_URL",
                    "NEXT_PUBLIC_API_URL",
                    "NUXT_PUBLIC_API_BASE",
                    "ANGULAR_API_URL")) {
                addPlainEnvIfAbsent(env, alias, "/api");
            }
            addPlainEnvIfAbsent(env, "DEPENDENCY_URL", "/api");
        } else if (dependency != null && dependency.getExposedPort() != null) {
            String dependencyUrl = internalServiceUrl(dependency, namespace);
            addPlainEnvIfAbsent(env, "DEPENDENCY_URL", dependencyUrl);
            addPlainEnvIfAbsent(env, "UPSTREAM_URL", dependencyUrl);
            addPlainEnvIfAbsent(env, "SERVICE_URL", dependencyUrl);
        }

        Map<String, Object> container = new LinkedHashMap<>();
        container.put("name", name);
        container.put("image", resolveServiceImage(name, opts));
        container.put("imagePullPolicy", "Always");
        if (port != null) {
            container.put("ports", List.of(containerPort(port)));
            if (svc.getHealthCheckPath() != null && !svc.getHealthCheckPath().isBlank()) {
                String probePath = resolveHealthProbePath(svc);
                container.put("readinessProbe", httpProbe(probePath, port, 10, 5));
                container.put("livenessProbe", httpProbe(probePath, port, 30, 15));
            } else {
                container.put("readinessProbe", tcpProbe(port, 10, 10));
                container.put("livenessProbe", tcpProbe(port, 30, 20));
            }
        }
        if (!env.isEmpty()) {
            container.put("env", env);
        }
        container.put("resources", resources(
                orDefault(svc.getCpuRequest(), "100m"),
                orDefault(svc.getCpuLimit(), "500m"),
                orDefault(svc.getMemoryRequest(), "128Mi"),
                orDefault(svc.getMemoryLimit(), "256Mi")));

        Map<String, Object> podSpec = new LinkedHashMap<>();
        List<Map<String, Object>> initContainers = buildInitContainers(app, svc);
        if (!initContainers.isEmpty()) {
            podSpec.put("initContainers", initContainers);
        }
        podSpec.put("containers", List.of(container));
        podSpec.put("imagePullSecrets", List.of(Map.of("name", opts.getPullSecretName())));

        int replicas = svc.getReplicas() != null ? svc.getReplicas() : 1;
        Map<String, Object> m = base("apps/v1", "Deployment");
        m.put("metadata", meta(name, namespace));
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("replicas", replicas);
        Map<String, Object> selector = new LinkedHashMap<>();
        selector.put("matchLabels", Map.of("app", name));
        spec.put("selector", selector);
        Map<String, Object> labels = new LinkedHashMap<>();
        labels.put("app", name);
        labels.put("tier", svc.getRole().name().toLowerCase());
        spec.put("template", podTemplate(labels, podSpec));
        m.put("spec", spec);
        return m;
    }

    private static boolean requiresJdbcUrl(String envName) {
        String normalized = envName != null ? envName.trim().toUpperCase() : "";
        return normalized.contains("JDBC") || normalized.startsWith("SPRING_DATASOURCE_");
    }

    /**
     * initContainers d'attente : un service dépendant ne démarre pas tant que ses dépendances
     * ne répondent pas en TCP (ordonnancement en vagues §3.3, complément du kubectl wait BD).
     */
    private List<Map<String, Object>> buildInitContainers(ManagedApplication app, AppService svc) {
        List<Map<String, Object>> inits = new ArrayList<>();
        if (svc.getDependsOnDatabaseId() != null) {
            AppDatabase db = findDb(app, svc.getDependsOnDatabaseId());
            if (db != null) {
                String host = connectionUrlService.serviceName(db);
                inits.add(waitForContainer("wait-for-" + host, host, dbPort(db)));
            }
        }
        if (svc.getDependsOnServiceId() != null) {
            AppService dep = findSvc(app, svc.getDependsOnServiceId());
            if (dep != null && dep.getExposedPort() != null) {
                String host = AppNaming.k8sName(dep.getName());
                inits.add(waitForContainer("wait-for-" + host, host, dep.getExposedPort()));
            }
        }
        return inits;
    }

    private Map<String, Object> waitForContainer(String name, String host, int port) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("name", name);
        c.put("image", "busybox:1.36");
        c.put("command", List.of("sh", "-c",
                "until nc -z " + host + " " + port + "; do echo waiting for " + host + ":" + port
                        + "; sleep 3; done"));
        return c;
    }

    private Map<String, Object> serviceClusterIp(AppService svc, String namespace, String name) {
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("selector", Map.of("app", name));
        spec.put("ports", List.of(servicePort(svc.getExposedPort(), svc.getExposedPort())));
        // ClusterIP + Ingress Traefik (:80) = scalable multi-apps (évite 1 NodePort/LB par app)
        spec.put("type", "ClusterIP");
        Map<String, Object> m = base("v1", "Service");
        m.put("metadata", meta(name, namespace));
        m.put("spec", spec);
        return m;
    }

    private Map<String, Object> serviceNodePort(AppService svc, String namespace, String name) {
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("selector", Map.of("app", name));
        spec.put("ports", List.of(servicePort(svc.getExposedPort(), svc.getExposedPort())));
        spec.put("type", "NodePort");
        Map<String, Object> m = base("v1", "Service");
        m.put("metadata", meta(name + "-external", namespace));
        m.put("spec", spec);
        return m;
    }

    private Map<String, Object> serviceIngress(AppService svc, String namespace, String name, ManifestOptions opts) {
        String host = resolveServiceHost(name, namespace, opts);

        Map<String, Object> backendService = new LinkedHashMap<>();
        backendService.put("name", name);
        Map<String, Object> portMap = new LinkedHashMap<>();
        portMap.put("number", svc.getExposedPort());
        backendService.put("port", portMap);
        Map<String, Object> backend = new LinkedHashMap<>();
        backend.put("service", backendService);

        Map<String, Object> path = new LinkedHashMap<>();
        path.put("path", "/");
        path.put("pathType", "Prefix");
        path.put("backend", backend);

        Map<String, Object> http = new LinkedHashMap<>();
        http.put("paths", List.of(path));
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("host", host);
        rule.put("http", http);

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("rules", List.of(rule));
        applyIngressClassName(spec, opts);

        Map<String, Object> m = base("networking.k8s.io/v1", "Ingress");
        Map<String, Object> metadata = meta(name, namespace);
        Map<String, String> annotations = ingressAnnotations(opts, false, "/");
        if (!annotations.isEmpty()) {
            metadata.put("annotations", annotations);
        }
        m.put("metadata", metadata);
        m.put("spec", spec);
        return m;
    }

    /** Hostname Ingress applicatif (custom ou app-ns.domain). */
    static String resolveAppHost(String namespace, ManifestOptions opts) {
        if (opts != null && opts.getCustomHostname() != null && !opts.getCustomHostname().isBlank()) {
            return opts.getCustomHostname().trim().toLowerCase();
        }
        String domain = opts != null && opts.getIngressDomain() != null ? opts.getIngressDomain() : "nip.io";
        return "app-" + namespace + "." + domain;
    }

    private static String resolveServiceHost(String k8sName, String namespace, ManifestOptions opts) {
        if (opts != null && opts.getCustomHostname() != null && !opts.getCustomHostname().isBlank()) {
            // Domaine custom → un seul hôte (path-based) ; host per-service déconseillé
            return opts.getCustomHostname().trim().toLowerCase();
        }
        String domain = opts != null && opts.getIngressDomain() != null ? opts.getIngressDomain() : "nip.io";
        return k8sName + "-" + namespace + "." + domain;
    }

    /**
     * Un seul Ingress pour toute l'application. Le frontend est monté sur {@code /}, le
     * backend primaire sur {@code /api}, puis les éventuels autres services sur
     * {@code /<nom>}. {@code /api} est réécrit vers le chemin métier du backend
     * ({@code contextPath}, ex. {@code /projet}) ou simplement retiré s'il est vide.
     */
    private Map<String, Object> applicationIngress(ManagedApplication app, String namespace, ManifestOptions opts) {
        List<AppService> exposed = app.getServices().stream()
                .filter(this::isExternallyExposed)
                .filter(s -> s.getExposedPort() != null)
                .toList();
        if (exposed.isEmpty()) {
            return null;
        }

        AppService primary = exposed.stream()
                .filter(s -> s.getRole() == AppServiceRole.FRONTEND)
                .findFirst()
                .orElse(exposed.get(0));
        AppService primaryBackend = resolveFrontendApiBackend(app, primary);

        String host = resolveAppHost(namespace, opts);
        List<Map<String, Object>> paths = new ArrayList<>();
        boolean needsNginxRewrite = false;
        boolean traefik = isTraefikIngress(opts);
        String nginxRewriteTarget = "/$2";

        for (AppService svc : exposed) {
            String name = AppNaming.k8sName(svc.getName());
            boolean isPrimary = java.util.Objects.equals(svc.getId(), primary.getId());
            boolean isApiBackend = primaryBackend != null
                    && java.util.Objects.equals(svc.getId(), primaryBackend.getId());

            Map<String, Object> port = new LinkedHashMap<>();
            port.put("number", svc.getExposedPort());
            Map<String, Object> backendService = new LinkedHashMap<>();
            backendService.put("name", name);
            backendService.put("port", port);
            Map<String, Object> backend = new LinkedHashMap<>();
            backend.put("service", backendService);

            Map<String, Object> path = new LinkedHashMap<>();
            if (isPrimary) {
                path.put("path", "/");
                path.put("pathType", "Prefix");
            } else if (traefik) {
                path.put("path", isApiBackend ? "/api" : "/" + name);
                path.put("pathType", "Prefix");
            } else {
                String prefix = isApiBackend ? "/api" : "/" + name;
                path.put("path", prefix + "(/|$)(.*)");
                path.put("pathType", "ImplementationSpecific");
                needsNginxRewrite = true;
                if (isApiBackend) {
                    String context = AppServiceRules.normalizeContextPath(svc.getContextPath());
                    nginxRewriteTarget = context == null ? "/$2" : context + "/$2";
                }
            }
            path.put("backend", backend);
            paths.add(path);
        }

        Map<String, Object> http = new LinkedHashMap<>();
        http.put("paths", paths);
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("host", host);
        rule.put("http", http);

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("rules", List.of(rule));
        applyIngressClassName(spec, opts);

        Map<String, Object> m = base("networking.k8s.io/v1", "Ingress");
        Map<String, Object> metadata = meta("app-ingress", namespace);
        Map<String, String> annotations = ingressAnnotations(opts, needsNginxRewrite, nginxRewriteTarget);
        List<String> middlewareRefs = traefikMiddlewareRefs(namespace, app, primary, primaryBackend);
        if (!middlewareRefs.isEmpty()) {
            annotations.put("traefik.ingress.kubernetes.io/router.middlewares",
                    String.join(",", middlewareRefs));
        }
        if (!annotations.isEmpty()) {
            metadata.put("annotations", annotations);
        }
        m.put("metadata", metadata);
        m.put("spec", spec);
        return m;
    }

    private List<Map<String, Object>> applicationPathMiddlewares(
            ManagedApplication app,
            String namespace,
            ManifestOptions opts
    ) {
        if (!isTraefikIngress(opts)) {
            return List.of();
        }
        List<AppService> exposed = app.getServices().stream()
                .filter(this::isExternallyExposed)
                .filter(s -> s.getExposedPort() != null)
                .toList();
        AppService primary = exposed.stream()
                .filter(s -> s.getRole() == AppServiceRole.FRONTEND)
                .findFirst()
                .orElse(exposed.isEmpty() ? null : exposed.get(0));
        if (primary == null) {
            return List.of();
        }
        AppService primaryBackend = resolveFrontendApiBackend(app, primary);
        List<Map<String, Object>> middlewares = new ArrayList<>();

        String backendContext = primaryBackend == null
                ? null
                : AppServiceRules.normalizeContextPath(primaryBackend.getContextPath());
        if (primaryBackend != null && backendContext != null) {
            Map<String, Object> rewrite = base("traefik.io/v1alpha1", "Middleware");
            rewrite.put("metadata", meta("app-api-rewrite", namespace));
            Map<String, Object> replace = new LinkedHashMap<>();
            replace.put("regex", "^/api(.*)$");
            replace.put("replacement", backendContext + "$1");
            rewrite.put("spec", Map.of("replacePathRegex", replace));
            middlewares.add(rewrite);
        }

        List<String> stripPrefixes = new ArrayList<>();
        for (AppService service : exposed) {
            if (java.util.Objects.equals(service.getId(), primary.getId())) {
                continue;
            }
            boolean isApiBackend = primaryBackend != null
                    && java.util.Objects.equals(service.getId(), primaryBackend.getId());
            if (isApiBackend) {
                if (backendContext == null) {
                    stripPrefixes.add("/api");
                }
            } else {
                stripPrefixes.add("/" + AppNaming.k8sName(service.getName()));
            }
        }
        if (!stripPrefixes.isEmpty()) {
            Map<String, Object> strip = base("traefik.io/v1alpha1", "Middleware");
            strip.put("metadata", meta("app-strip-prefix", namespace));
            strip.put("spec", Map.of("stripPrefix", Map.of("prefixes", stripPrefixes)));
            middlewares.add(strip);
        }
        return middlewares;
    }

    private List<String> traefikMiddlewareRefs(
            String namespace,
            ManagedApplication app,
            AppService primary,
            AppService primaryBackend
    ) {
        List<String> refs = new ArrayList<>();
        if (primaryBackend != null
                && AppServiceRules.normalizeContextPath(primaryBackend.getContextPath()) != null) {
            refs.add(namespace + "-app-api-rewrite@kubernetescrd");
        }
        boolean needsStrip = app.getServices().stream()
                .filter(this::isExternallyExposed)
                .filter(s -> s.getExposedPort() != null)
                .anyMatch(service -> {
                    if (java.util.Objects.equals(service.getId(), primary.getId())) {
                        return false;
                    }
                    boolean isApiBackend = primaryBackend != null
                            && java.util.Objects.equals(service.getId(), primaryBackend.getId());
                    if (isApiBackend) {
                        return AppServiceRules.normalizeContextPath(primaryBackend.getContextPath()) == null;
                    }
                    return true;
                });
        if (needsStrip) {
            refs.add(namespace + "-app-strip-prefix@kubernetescrd");
        }
        return refs;
    }

    private void applyIngressClassName(Map<String, Object> spec, ManifestOptions opts) {
        if (opts.getIngressClassName() != null && !opts.getIngressClassName().isBlank()) {
            spec.put("ingressClassName", opts.getIngressClassName().trim());
        }
    }

    private boolean isTraefikIngress(ManifestOptions opts) {
        String controller = opts.getIngressController();
        return controller == null || controller.isBlank() || "traefik".equalsIgnoreCase(controller.trim());
    }

    private Map<String, String> ingressAnnotations(
            ManifestOptions opts,
            boolean needsNginxRewrite,
            String nginxRewriteTarget
    ) {
        if (isTraefikIngress(opts)) {
            Map<String, String> traefik = new LinkedHashMap<>();
            traefik.put("traefik.ingress.kubernetes.io/router.entrypoints", "web");
            // Vite (et d'autres) rejettent/bloquent le Host nip.io → 504 via Traefik
            traefik.put("traefik.ingress.kubernetes.io/service.passhostheader", "false");
            return traefik;
        }
        if (needsNginxRewrite) {
            Map<String, String> nginx = new LinkedHashMap<>();
            nginx.put("nginx.ingress.kubernetes.io/rewrite-target",
                    nginxRewriteTarget == null || nginxRewriteTarget.isBlank() ? "/$2" : nginxRewriteTarget);
            nginx.put("nginx.ingress.kubernetes.io/use-regex", "true");
            return nginx;
        }
        return Map.of("nginx.ingress.kubernetes.io/rewrite-target", "/");
    }

    // =====================================================================
    // Building blocks
    // =====================================================================

    private Map<String, Object> podTemplate(Map<String, Object> labels, Map<String, Object> podSpec) {
        Map<String, Object> template = new LinkedHashMap<>();
        Map<String, Object> tmplMeta = new LinkedHashMap<>();
        tmplMeta.put("labels", labels);
        template.put("metadata", tmplMeta);
        template.put("spec", podSpec);
        return template;
    }

    private Map<String, Object> dbLabels(String svcName) {
        Map<String, Object> labels = new LinkedHashMap<>();
        labels.put("app", svcName);
        labels.put("tier", "database");
        return labels;
    }

    private Map<String, Object> containerPort(int port) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("containerPort", port);
        return p;
    }

    private Map<String, Object> servicePort(int port, int targetPort) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("port", port);
        p.put("targetPort", targetPort);
        p.put("protocol", "TCP");
        return p;
    }

    private Map<String, Object> envPlain(String name, String value) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("name", name);
        e.put("value", value);
        return e;
    }

    private void addPlainEnvIfAbsent(List<Map<String, Object>> env, String name, String value) {
        boolean exists = env.stream().anyMatch(item -> name.equals(item.get("name")));
        if (!exists) {
            env.add(envPlain(name, value));
        }
    }

    private AppService findServiceDependency(ManagedApplication app, AppService service) {
        if (service.getDependsOnServiceId() == null) {
            return null;
        }
        return app.getServices().stream()
                .filter(candidate -> service.getDependsOnServiceId().equals(candidate.getId()))
                .findFirst()
                .orElse(null);
    }

    private AppService resolveFrontendApiBackend(ManagedApplication app, AppService frontend) {
        AppService declaredDependency = findServiceDependency(app, frontend);
        if (declaredDependency != null
                && declaredDependency.getRole() == AppServiceRole.BACKEND
                && declaredDependency.getExposedPort() != null
                && isExternallyExposed(declaredDependency)) {
            return declaredDependency;
        }
        return app.getServices().stream()
                .filter(service -> service.getRole() == AppServiceRole.BACKEND)
                .filter(this::isExternallyExposed)
                .filter(service -> service.getExposedPort() != null)
                .findFirst()
                .orElse(null);
    }

    private String internalServiceUrl(AppService service, String namespace) {
        String base = "http://" + AppNaming.k8sName(service.getName()) + "."
                + namespace + ".svc.cluster.local:" + service.getExposedPort();
        String context = AppServiceRules.normalizeContextPath(service.getContextPath());
        return context == null ? base : base + context;
    }

    private String resolveHealthProbePath(AppService service) {
        String path = service.getHealthCheckPath().trim();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        String context = AppServiceRules.normalizeContextPath(service.getContextPath());
        if (context == null || path.equals(context) || path.startsWith(context + "/")) {
            return path;
        }
        return context + path;
    }

    private String resolveServiceUrlPlaceholders(
            String value,
            ManagedApplication app,
            AppService service,
            String namespace
    ) {
        AppService dependency = findServiceDependency(app, service);
        String dependencyUrl = null;
        if (service.getRole() == AppServiceRole.FRONTEND && resolveFrontendApiBackend(app, service) != null) {
            dependencyUrl = "/api";
        } else if (dependency != null && dependency.getExposedPort() != null) {
            dependencyUrl = internalServiceUrl(dependency, namespace);
        }
        String resolved = value.replace("${PUBLIC_API_URL}",
                service.getRole() == AppServiceRole.FRONTEND ? "/api" : "");
        if (dependencyUrl != null) {
            resolved = resolved.replace("${DEPENDENCY_URL}", dependencyUrl);
        }
        return resolved;
    }

    private Map<String, Object> envFromSecret(String name, String secretName, String key) {
        Map<String, Object> secretKeyRef = new LinkedHashMap<>();
        secretKeyRef.put("name", secretName);
        secretKeyRef.put("key", key);
        Map<String, Object> valueFrom = new LinkedHashMap<>();
        valueFrom.put("secretKeyRef", secretKeyRef);
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("name", name);
        e.put("valueFrom", valueFrom);
        return e;
    }

    private Map<String, Object> volumeMount(String name, String path) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("name", name);
        v.put("mountPath", path);
        return v;
    }

    private Map<String, Object> pvcVolume(String name, String claimName) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("name", name);
        Map<String, Object> pvc = new LinkedHashMap<>();
        pvc.put("claimName", claimName);
        v.put("persistentVolumeClaim", pvc);
        return v;
    }

    private Map<String, Object> tcpProbe(int port, int initialDelay, int period) {
        Map<String, Object> tcp = new LinkedHashMap<>();
        tcp.put("port", port);
        Map<String, Object> probe = new LinkedHashMap<>();
        probe.put("tcpSocket", tcp);
        probe.put("initialDelaySeconds", initialDelay);
        probe.put("periodSeconds", period);
        probe.put("failureThreshold", 10);
        return probe;
    }

    private Map<String, Object> httpProbe(String path, int port, int initialDelay, int period) {
        Map<String, Object> http = new LinkedHashMap<>();
        http.put("path", path);
        http.put("port", port);
        Map<String, Object> probe = new LinkedHashMap<>();
        probe.put("httpGet", http);
        probe.put("initialDelaySeconds", initialDelay);
        probe.put("periodSeconds", period);
        probe.put("failureThreshold", 10);
        return probe;
    }

    private Map<String, Object> resources(String cpuReq, String cpuLim, String memReq, String memLim) {
        Map<String, Object> requests = new LinkedHashMap<>();
        requests.put("cpu", cpuReq);
        requests.put("memory", memReq);
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("cpu", cpuLim);
        limits.put("memory", memLim);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("requests", requests);
        r.put("limits", limits);
        return r;
    }

    private Map<String, Object> base(String apiVersion, String kind) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("apiVersion", apiVersion);
        m.put("kind", kind);
        return m;
    }

    private Map<String, Object> meta(String name, String namespace) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        if (namespace != null) {
            m.put("namespace", namespace);
        }
        return m;
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private boolean isExternallyExposed(AppService svc) {
        return svc.getRole() == AppServiceRole.FRONTEND || svc.getRole() == AppServiceRole.BACKEND;
    }

    private int dbPort(AppDatabase db) {
        return db.getExposedPort() != null ? db.getExposedPort() : db.getEngine().defaultPort();
    }

    private String dbImage(AppDatabase db) {
        String version = (db.getVersion() != null && !db.getVersion().isBlank()) ? db.getVersion() : "latest";
        return switch (db.getEngine()) {
            case MARIADB -> "mariadb:" + version;
            case MYSQL -> "mysql:" + version;
            case POSTGRES -> "postgres:" + version;
            case MONGODB -> "mongo:" + version;
            case REDIS -> "redis:" + version;
            case CASSANDRA -> "cassandra:" + version;
        };
    }

    private String dbDataPath(AppDatabase db) {
        return switch (db.getEngine()) {
            case MARIADB, MYSQL -> "/var/lib/mysql";
            case POSTGRES -> "/var/lib/postgresql/data";
            case MONGODB -> "/data/db";
            case REDIS -> "/data";
            case CASSANDRA -> "/var/lib/cassandra";
        };
    }

    private AppDatabase findDb(ManagedApplication app, UUID id) {
        return app.getDatabases().stream().filter(d -> d.getId().equals(id)).findFirst().orElse(null);
    }

    private AppService findSvc(ManagedApplication app, UUID id) {
        return app.getServices().stream().filter(s -> s.getId().equals(id)).findFirst().orElse(null);
    }

    private static String nz(String s) {
        return s != null ? s : "";
    }

    private static String orDefault(String s, String def) {
        return (s != null && !s.isBlank()) ? s : def;
    }

    private String dumpAll(List<Map<String, Object>> docs) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        Yaml yaml = new Yaml(options);
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> doc : docs) {
            sb.append("---\n");
            sb.append(yaml.dump(doc));
        }
        return sb.toString();
    }
}
