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
        String ingressDomain;      // ex. local → <svc>-<ns>.local
        String imageTag;
        /** Image complète fournie par le pipeline CI (remplace le template CI_REGISTRY_IMAGE). */
        String resolvedServiceImage;
    }

    /**
     * Image d'un service : {@code $CI_REGISTRY_IMAGE/<name>:<tag>}. Le préfixe registre est
     * résolu par le pipeline (envsubst) qui connaît {@code $CI_REGISTRY_IMAGE}.
     */
    public String serviceImage(AppService svc, String imageTag) {
        return "${CI_REGISTRY_IMAGE}/" + AppNaming.k8sName(svc.getName()) + ":" + imageTag;
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
        docs.add(namespaceManifest(namespace));
        docs.add(imagePullSecretManifest(namespace, opts));

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
        List<Map<String, Object>> docs = new ArrayList<>();
        for (AppService svc : app.getServices()) {
            String name = AppNaming.k8sName(svc.getName());
            Map<String, Object> secret = serviceSecret(svc, namespace, name);
            if (secret != null) {
                docs.add(secret);
            }
            docs.add(serviceDeployment(app, svc, namespace, name, opts));
            // ClusterIP seulement si un port d'écoute est défini (FRONTEND/BACKEND).
            // WORKER sans port : pas de Service — aucun Ingress non plus.
            if (svc.getExposedPort() != null) {
                docs.add(serviceClusterIp(svc, namespace, name));
            }
            if (isExternallyExposed(svc) && svc.getExposedPort() != null) {
                if (opts.isIngressEnabled()) {
                    docs.add(serviceIngress(svc, namespace, name, opts));
                } else {
                    docs.add(serviceNodePort(svc, namespace, name));
                }
            }
        }
        return dumpAll(docs);
    }

    // =====================================================================
    // Namespace + imagePullSecret
    // =====================================================================

    private Map<String, Object> namespaceManifest(String namespace) {
        Map<String, Object> m = base("v1", "Namespace");
        m.put("metadata", meta(namespace, null));
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
        data.put(CONNECTION_URL_KEY, nz(connectionUrlService.buildConnectionUrl(db, namespace)));
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
        m.put("metadata", meta(svcName, namespace));
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
        m.put("metadata", meta(svcName, namespace));
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
                env.add(envPlain(var.getVarKey(), nz(var.getVarValue())));
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
                env.add(envFromSecret(urlEnv, secret, CONNECTION_URL_KEY));
                if (AppDatabaseRules.credentialsOutsideUrl(db.getEngine())) {
                    env.add(envFromSecret("DATABASE_USER", secret, "ROOT_USER"));
                    env.add(envFromSecret("DATABASE_PASSWORD", secret, "ROOT_PASSWORD"));
                }
            }
        }

        Map<String, Object> container = new LinkedHashMap<>();
        container.put("name", name);
        String image = opts.getResolvedServiceImage() != null && !opts.getResolvedServiceImage().isBlank()
                ? opts.getResolvedServiceImage().trim()
                : serviceImage(svc, opts.getImageTag());
        container.put("image", image);
        container.put("imagePullPolicy", "Always");
        if (port != null) {
            container.put("ports", List.of(containerPort(port)));
            if (svc.getHealthCheckPath() != null && !svc.getHealthCheckPath().isBlank()) {
                container.put("readinessProbe", httpProbe(svc.getHealthCheckPath(), port, 10, 5));
                container.put("livenessProbe", httpProbe(svc.getHealthCheckPath(), port, 30, 15));
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
        String host = name + "-" + namespace + "." + opts.getIngressDomain();

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

        Map<String, Object> m = base("networking.k8s.io/v1", "Ingress");
        Map<String, Object> metadata = meta(name, namespace);
        metadata.put("annotations", Map.of("nginx.ingress.kubernetes.io/rewrite-target", "/"));
        m.put("metadata", metadata);
        m.put("spec", spec);
        return m;
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
