package com.backend.devsecopsplatform_backend.service.appmgmt;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.StatefulSet;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.dsl.Resource;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Applique des manifestes Kubernetes sur K3s via l'API REST (client Fabric8).
 */
@Service
@Slf4j
public class K8sManifestApplyService {

    @Value("${deployment.k8s.api-url:}")
    private String apiUrl;

    @Value("${deployment.k8s.token:}")
    private String token;

    @Value("${deployment.k8s.insecure-skip-tls-verify:true}")
    private boolean insecureSkipTlsVerify;

    @Value("${deployment.k8s.deploy-wait-timeout-seconds:300}")
    private int deployWaitTimeoutSeconds;

    @Value("${deployment.k8s.rollback-on-failure:true}")
    private boolean rollbackOnFailure;

    private volatile KubernetesClient kubernetesClient;

    public boolean isConfigured() {
        return apiUrl != null && !apiUrl.isBlank() && token != null && !token.isBlank();
    }

    public void ensureNamespaceReadyForApply(String namespace) throws IOException {
        if (namespace == null || namespace.isBlank()) {
            return;
        }
        requireConfigured();
        var existing = client().namespaces().withName(namespace).get();
        if (existing == null) {
            return;
        }
        String phase = existing.getStatus() != null ? existing.getStatus().getPhase() : null;
        if (!"Terminating".equals(phase)) {
            return;
        }
        log.info("Namespace {} en Terminating — attente suppression avant apply", namespace);
        try {
            client().namespaces().withName(namespace)
                    .waitUntilCondition(Objects::isNull, 180, TimeUnit.SECONDS);
            log.info("Namespace {} supprimé — apply peut continuer", namespace);
        } catch (Exception e) {
            throw new IOException(
                    "Namespace " + namespace + " bloqué en Terminating — attendez la fin de suppression ou forcez le delete",
                    e);
        }
    }

    public void applyManifests(String multiDocYaml) throws IOException {
        requireConfigured();
        if (multiDocYaml == null || multiDocYaml.isBlank()) {
            throw new IllegalArgumentException("Manifestes Kubernetes vides");
        }
        if (multiDocYaml.contains("${CI_REGISTRY_IMAGE}") || multiDocYaml.contains("${IMAGE_")) {
            throw new AppValidationException(
                    "Manifestes Kubernetes contenant une image CI non résolue");
        }

        try (ByteArrayInputStream input = new ByteArrayInputStream(multiDocYaml.getBytes(StandardCharsets.UTF_8))) {
            List<HasMetadata> resources = client().load(input).items();
            for (HasMetadata resource : resources) {
                String kind = resource.getKind();
                String name = resource.getMetadata() != null ? resource.getMetadata().getName() : "?";
                log.info("Fabric8 apply {}/{}", kind, name);
                try {
                    applyResource(resource);
                } catch (Exception e) {
                    // Ingress souvent bloqué par le webhook nginx → ne pas faire échouer tout le déploiement
                    if ("Ingress".equalsIgnoreCase(kind)) {
                        log.warn("Ingress {}/{} non appliqué (non bloquant) : {}",
                                kind, name, e.getMessage());
                        continue;
                    }
                    throw e;
                }
            }
            log.info("Fabric8 apply OK — {} ressource(s)", resources.size());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Fabric8 apply échoué : " + e.getMessage(), e);
        }
    }

    public Integer getServiceNodePort(String namespace, String serviceName) {
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || serviceName == null || serviceName.isBlank()) {
            return null;
        }
        try {
            var svc = client().services().inNamespace(namespace).withName(serviceName).get();
            if (svc == null || svc.getSpec() == null || svc.getSpec().getPorts() == null
                    || svc.getSpec().getPorts().isEmpty()) {
                return null;
            }
            var port = svc.getSpec().getPorts().get(0);
            // LoadBalancer K3s : accès via IP nœud + port du service (hostPort)
            String type = svc.getSpec().getType();
            if ("LoadBalancer".equalsIgnoreCase(type) && port.getPort() != null) {
                return port.getPort();
            }
            if (port.getNodePort() != null && port.getNodePort() > 0) {
                return port.getNodePort();
            }
            return port.getPort();
        } catch (Exception e) {
            log.debug("service port {}/{}: {}", namespace, serviceName, e.getMessage());
            return null;
        }
    }

    public boolean isDeploymentReady(String namespace, String deploymentName) {
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || deploymentName == null || deploymentName.isBlank()) {
            return false;
        }
        try {
            Deployment d = client().apps().deployments()
                    .inNamespace(namespace)
                    .withName(deploymentName)
                    .get();
            if (d == null) {
                return false;
            }
            return workloadReady(
                    d.getSpec() != null ? d.getSpec().getReplicas() : null,
                    d.getStatus() != null ? d.getStatus().getReadyReplicas() : null);
        } catch (Exception e) {
            log.debug("deployment pas ready {}/{}: {}", namespace, deploymentName, e.getMessage());
            return false;
        }
    }

    public boolean hasWorkloads(String namespace) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return false;
        }
        try {
            return !client().apps().deployments().inNamespace(namespace).list().getItems().isEmpty()
                    || !client().apps().statefulSets().inNamespace(namespace).list().getItems().isEmpty();
        } catch (Exception e) {
            log.debug("workload list {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    public boolean areAllDeploymentsReady(String namespace) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return false;
        }
        try {
            List<Deployment> deployments = client().apps().deployments()
                    .inNamespace(namespace).list().getItems();
            List<StatefulSet> statefulSets = client().apps().statefulSets()
                    .inNamespace(namespace).list().getItems();

            if (deployments.isEmpty() && statefulSets.isEmpty()) {
                return false;
            }

            return workloadsReady(deployments, statefulSets);
        } catch (Exception e) {
            log.debug("ready check {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    /**
     * Attend que les workloads {@code tier=database} soient Ready (vague 0).
     * Retourne immédiatement si aucune base n'est déployée dans le namespace.
     */
    public void waitUntilDatabasesReady(String namespace) throws IOException {
        waitUntilWorkloadsReady(namespace, "database");
    }

    /**
     * Attend que tous les Deployments et StatefulSets du namespace soient Ready.
     */
    public void waitUntilAllWorkloadsReady(String namespace) throws IOException {
        waitUntilWorkloadsReady(namespace, null);
    }

    /**
     * Attend que les Deployments nommés (vague service) soient Ready.
     */
    public void waitUntilNamedDeploymentsReady(String namespace, Collection<String> deploymentNames) throws IOException {
        if (deploymentNames == null || deploymentNames.isEmpty()) {
            return;
        }
        requireConfigured();
        long deadline = System.currentTimeMillis() + deployWaitTimeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            boolean allReady = true;
            for (String name : deploymentNames) {
                if (name == null || name.isBlank()) {
                    continue;
                }
                if (!isDeploymentReady(namespace, name)) {
                    allReady = false;
                    break;
                }
            }
            if (allReady) {
                log.info("Vague service ready dans {} — {}", namespace, deploymentNames);
                return;
            }
            sleepPoll();
        }
        throw new IOException("Timeout attente vague service dans " + namespace
                + " après " + deployWaitTimeoutSeconds + "s — deployments=" + deploymentNames);
    }

    public boolean isRollbackOnFailureEnabled() {
        return rollbackOnFailure;
    }

    public void rollbackNamespace(String namespace) {
        if (!rollbackOnFailure || namespace == null || namespace.isBlank()) {
            return;
        }
        try {
            deleteNamespace(namespace);
            log.info("Rollback namespace {} après échec déploiement", namespace);
        } catch (Exception e) {
            log.warn("Rollback namespace {} échoué: {}", namespace, e.getMessage());
        }
    }

    private void applyResource(HasMetadata resource) {
        String kind = resource.getKind();
        String name = resource.getMetadata() != null ? resource.getMetadata().getName() : "?";
        String ns = resource.getMetadata() != null ? resource.getMetadata().getNamespace() : null;
        Resource<HasMetadata> op;
        if (ns != null && !ns.isBlank() && !"Namespace".equals(kind)) {
            op = client().resource(resource).inNamespace(ns);
        } else {
            op = client().resource(resource);
        }
        try {
            op.forceConflicts().serverSideApply();
            return;
        } catch (Exception e) {
            log.debug("serverSideApply échoué pour {}/{} — fallback create/update: {}",
                    kind, name, e.getMessage());
        }
        // Ne pas utiliser createOrReplace() : pour Ingress il attend une adresse LB
        // (souvent absente sur K3s/nip.io) et timeout à 1s → échec du déploiement entier.
        try {
            if (op.get() == null) {
                op.create();
            } else {
                op.update();
            }
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Apply " + kind + "/" + name + " échoué : " + e.getMessage(), e);
        }
    }

    private void waitUntilWorkloadsReady(String namespace, String tierLabel) throws IOException {
        requireConfigured();
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("namespace requis");
        }

        long deadline = System.currentTimeMillis() + deployWaitTimeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try {
                List<Deployment> deployments = listDeployments(namespace, tierLabel);
                List<StatefulSet> statefulSets = listStatefulSets(namespace, tierLabel);

                if (deployments.isEmpty() && statefulSets.isEmpty()) {
                    if (tierLabel != null) {
                        log.info("Aucune base (tier={}) dans {} — vague BD ignorée", tierLabel, namespace);
                        return;
                    }
                    sleepPoll();
                    continue;
                }

                if (workloadsReady(deployments, statefulSets)) {
                    log.info("Workloads ready dans {} (tier={})", namespace, tierLabel != null ? tierLabel : "all");
                    return;
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                log.debug("poll ready {}/{}: {}", namespace, tierLabel, e.getMessage());
            }
            sleepPoll();
        }
        throw new IOException("Timeout attente Ready dans " + namespace
                + " après " + deployWaitTimeoutSeconds + "s"
                + (tierLabel != null ? " (tier=" + tierLabel + ")" : ""));
    }

    private List<Deployment> listDeployments(String namespace, String tierLabel) {
        var op = client().apps().deployments().inNamespace(namespace);
        if (tierLabel != null && !tierLabel.isBlank()) {
            return op.withLabel("tier", tierLabel).list().getItems();
        }
        return op.list().getItems();
    }

    private List<StatefulSet> listStatefulSets(String namespace, String tierLabel) {
        var op = client().apps().statefulSets().inNamespace(namespace);
        if (tierLabel != null && !tierLabel.isBlank()) {
            return op.withLabel("tier", tierLabel).list().getItems();
        }
        return op.list().getItems();
    }

    private boolean workloadsReady(List<Deployment> deployments, List<StatefulSet> statefulSets) {
        for (Deployment d : deployments) {
            if (!workloadReady(
                    d.getSpec() != null ? d.getSpec().getReplicas() : null,
                    d.getStatus() != null ? d.getStatus().getReadyReplicas() : null)) {
                return false;
            }
        }
        for (StatefulSet ss : statefulSets) {
            if (!workloadReady(
                    ss.getSpec() != null ? ss.getSpec().getReplicas() : null,
                    ss.getStatus() != null ? ss.getStatus().getReadyReplicas() : null)) {
                return false;
            }
        }
        return true;
    }

    private void sleepPoll() throws IOException {
        try {
            Thread.sleep(3_000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Attente Ready interrompue", e);
        }
    }

    public void deleteNamespace(String namespace) throws IOException {
        if (namespace == null || namespace.isBlank()) {
            return;
        }
        requireConfigured();
        try {
            var deleted = client().namespaces().withName(namespace).delete();
            if (deleted == null || deleted.isEmpty()) {
                log.warn("Namespace {} introuvable ou déjà supprimé", namespace);
                return;
            }
            try {
                client().namespaces().withName(namespace)
                        .waitUntilCondition(Objects::isNull, 120, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.warn("Timeout attente suppression namespace {}: {}", namespace, e.getMessage());
            }
            log.info("Fabric8 delete namespace {} OK", namespace);
        } catch (Exception e) {
            throw new IOException("Fabric8 delete namespace échoué : " + e.getMessage(), e);
        }
    }

    @PreDestroy
    void closeClient() {
        if (kubernetesClient != null) {
            kubernetesClient.close();
            kubernetesClient = null;
        }
    }

    private KubernetesClient client() {
        if (!isConfigured()) {
            throw new IllegalStateException("K8S_API_URL / K8S_TOKEN non configurés");
        }
        if (kubernetesClient == null) {
            synchronized (this) {
                if (kubernetesClient == null) {
                    Config config = new ConfigBuilder()
                            .withMasterUrl(apiUrl.trim())
                            .withOauthToken(token.trim())
                            .withTrustCerts(insecureSkipTlsVerify)
                            .withConnectionTimeout(10_000)
                            .withRequestTimeout(deployWaitTimeoutSeconds * 1000)
                            .build();
                    kubernetesClient = new KubernetesClientBuilder().withConfig(config).build();
                    log.info("Client Fabric8 initialisé — API {}", apiUrl.trim());
                }
            }
        }
        return kubernetesClient;
    }

    private void requireConfigured() {
        if (!isConfigured()) {
            throw new IllegalStateException("K8S_API_URL / K8S_TOKEN non configurés sur le backend");
        }
    }

    private boolean workloadReady(Integer desired, Integer ready) {
        int want = desired != null ? desired : 0;
        if (want == 0) {
            return true;
        }
        int have = ready != null ? ready : 0;
        return have >= want;
    }
}
