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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    /** Timeout HTTP par requête Fabric8 (apply Ingress/Middleware inclus). */
    @Value("${deployment.k8s.request-timeout-seconds:45}")
    private int requestTimeoutSeconds;

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
                    .waitUntilCondition(Objects::isNull, 60, TimeUnit.SECONDS);
            log.info("Namespace {} supprimé — apply peut continuer", namespace);
            return;
        } catch (Exception waitEx) {
            log.warn("Namespace {} toujours Terminating après 60s — force finalize: {}",
                    namespace, waitEx.getMessage());
        }
        forceFinalizeNamespace(namespace);
        try {
            client().namespaces().withName(namespace)
                    .waitUntilCondition(Objects::isNull, 90, TimeUnit.SECONDS);
            log.info("Namespace {} supprimé après force-finalize — apply peut continuer", namespace);
        } catch (Exception e) {
            throw new IOException(
                    "Namespace " + namespace + " bloqué en Terminating malgré force-finalize — "
                            + "supprimez manuellement les finalizers (voir COMMANDES-RUN.txt)",
                    e);
        }
    }

    /**
     * Retire les finalizers du namespace (et tente un delete pods/PVC) pour débloquer Terminating.
     */
    public void forceFinalizeNamespace(String namespace) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return;
        }
        try {
            // Best-effort : pods / PVC souvent responsables du blocage
            try {
                client().pods().inNamespace(namespace).withGracePeriod(0).delete();
            } catch (Exception e) {
                log.debug("force delete pods {}: {}", namespace, e.getMessage());
            }
            try {
                client().persistentVolumeClaims().inNamespace(namespace).delete();
            } catch (Exception e) {
                log.debug("force delete pvc {}: {}", namespace, e.getMessage());
            }
            client().namespaces().withName(namespace).edit(ns -> {
                if (ns.getMetadata() != null) {
                    ns.getMetadata().setFinalizers(new ArrayList<>());
                }
                return ns;
            });
            log.info("Force-finalize appliqué sur namespace {}", namespace);
        } catch (Exception e) {
            log.warn("Force-finalize namespace {} échoué: {}", namespace, e.getMessage());
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
                    // Ingress / Middleware Traefik : webhook ou CRD lent → ne pas bloquer le déploiement
                    if (isNonBlockingApplyKind(kind)) {
                        log.warn("{}/{} non appliqué (non bloquant) : {}",
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

    /**
     * Liste les pods d'un namespace (phase, ready, restarts, label app).
     */
    public List<Map<String, Object>> listPods(String namespace) {
        requireConfigured();
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("namespace requis");
        }
        List<Map<String, Object>> result = new ArrayList<>();
        var pods = client().pods().inNamespace(namespace).list().getItems();
        for (var pod : pods) {
            if (pod.getMetadata() == null) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", pod.getMetadata().getName());
            String workload = null;
            if (pod.getMetadata().getLabels() != null) {
                workload = pod.getMetadata().getLabels().get("app");
            }
            row.put("workload", workload);
            String phase = pod.getStatus() != null ? pod.getStatus().getPhase() : "Unknown";
            row.put("phase", phase);
            int restarts = 0;
            boolean ready = false;
            String reason = null;
            if (pod.getStatus() != null && pod.getStatus().getContainerStatuses() != null
                    && !pod.getStatus().getContainerStatuses().isEmpty()) {
                var cs = pod.getStatus().getContainerStatuses().get(0);
                restarts = cs.getRestartCount() != null ? cs.getRestartCount() : 0;
                ready = Boolean.TRUE.equals(cs.getReady());
                if (cs.getState() != null && cs.getState().getWaiting() != null) {
                    reason = cs.getState().getWaiting().getReason();
                } else if (cs.getState() != null && cs.getState().getTerminated() != null) {
                    reason = cs.getState().getTerminated().getReason();
                }
            }
            row.put("ready", ready);
            row.put("restarts", restarts);
            row.put("reason", reason);
            result.add(row);
        }
        return result;
    }

    /**
     * Vue monitoring namespace : pods enrichis (requests/limits + usage metrics si metrics-server)
     * et alertes dérivées.
     */
    public Map<String, Object> getNamespaceMonitoring(String namespace) {
        requireConfigured();
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("namespace requis");
        }
        Map<String, PodMetricUsage> usageByPod = fetchPodMetrics(namespace);
        // Enrichit réseau + disque via kubelet stats/summary (cAdvisor)
        usageByPod = enrichWithKubeletStats(namespace, usageByPod);
        List<Map<String, Object>> pods = new ArrayList<>();
        List<Map<String, Object>> alerts = new ArrayList<>();
        var items = client().pods().inNamespace(namespace).list().getItems();
        int readyCount = 0;
        int total = 0;
        for (var pod : items) {
            if (pod.getMetadata() == null) {
                continue;
            }
            total++;
            Map<String, Object> row = new LinkedHashMap<>();
            String name = pod.getMetadata().getName();
            row.put("name", name);
            String workload = null;
            if (pod.getMetadata().getLabels() != null) {
                workload = pod.getMetadata().getLabels().get("app");
            }
            row.put("workload", workload);
            String phase = pod.getStatus() != null ? pod.getStatus().getPhase() : "Unknown";
            row.put("phase", phase);
            int restarts = 0;
            boolean ready = false;
            String reason = null;
            if (pod.getStatus() != null && pod.getStatus().getContainerStatuses() != null
                    && !pod.getStatus().getContainerStatuses().isEmpty()) {
                for (var cs : pod.getStatus().getContainerStatuses()) {
                    restarts += cs.getRestartCount() != null ? cs.getRestartCount() : 0;
                    if (!Boolean.TRUE.equals(cs.getReady())) {
                        ready = false;
                    } else if (pod.getStatus().getContainerStatuses().size() == 1
                            || allContainersReady(pod)) {
                        ready = allContainersReady(pod);
                    }
                    if (cs.getState() != null && cs.getState().getWaiting() != null
                            && cs.getState().getWaiting().getReason() != null) {
                        reason = cs.getState().getWaiting().getReason();
                    } else if (cs.getState() != null && cs.getState().getTerminated() != null
                            && cs.getState().getTerminated().getReason() != null) {
                        reason = cs.getState().getTerminated().getReason();
                    }
                    if (cs.getLastState() != null && cs.getLastState().getTerminated() != null
                            && "OOMKilled".equals(cs.getLastState().getTerminated().getReason())) {
                        reason = "OOMKilled";
                    }
                }
                ready = allContainersReady(pod);
            }
            if (ready && "Running".equals(phase)) {
                readyCount++;
            }
            row.put("ready", ready);
            row.put("restarts", restarts);
            row.put("reason", reason);
            row.put("node", pod.getSpec() != null ? pod.getSpec().getNodeName() : null);
            row.put("startTime", pod.getStatus() != null && pod.getStatus().getStartTime() != null
                    ? pod.getStatus().getStartTime() : null);
            if (pod.getMetadata().getCreationTimestamp() != null) {
                row.put("createdAt", pod.getMetadata().getCreationTimestamp());
            }

            ResourceRequests limits = extractResources(pod);
            row.put("cpuRequest", limits.cpuRequest);
            row.put("cpuLimit", limits.cpuLimit);
            row.put("memoryRequest", limits.memoryRequest);
            row.put("memoryLimit", limits.memoryLimit);

            PodMetricUsage usage = usageByPod.get(name);
            if (usage != null) {
                row.put("cpuUsage", usage.cpu);
                row.put("memoryUsage", usage.memory);
                row.put("cpuUsageCores", usage.cpuCores);
                // millicores précis (ex: 1.37) — le front affiche même les toutes petites valeurs
                row.put("cpuUsageMillicores", Math.round(usage.cpuCores * 1_000_000.0) / 1000.0);
                row.put("memoryUsageBytes", usage.memoryBytes);
                row.put("networkRxBytes", usage.networkRxBytes);
                row.put("networkTxBytes", usage.networkTxBytes);
                row.put("fsUsedBytes", usage.fsUsedBytes);
                row.put("fsCapacityBytes", usage.fsCapacityBytes);
                if (usage.networkRxBytes > 0 || usage.networkTxBytes > 0) {
                    row.put("networkRx", formatBytes(usage.networkRxBytes));
                    row.put("networkTx", formatBytes(usage.networkTxBytes));
                }
                if (usage.fsUsedBytes > 0) {
                    row.put("fsUsed", formatBytes(usage.fsUsedBytes));
                    if (usage.fsCapacityBytes > 0) {
                        row.put("fsCapacity", formatBytes(usage.fsCapacityBytes));
                    }
                }
            } else {
                row.put("cpuUsage", null);
                row.put("memoryUsage", null);
            }

            if ("CrashLoopBackOff".equals(reason) || "ImagePullBackOff".equals(reason)
                    || "ErrImagePull".equals(reason)) {
                alerts.add(alert("error", name, workload,
                        reason + " — pod en panne de démarrage"));
            } else if ("OOMKilled".equals(reason)) {
                alerts.add(alert("error", name, workload, "OOMKilled — mémoire insuffisante"));
            } else if ("Pending".equals(phase)) {
                alerts.add(alert("warn", name, workload, "Pod Pending (scheduling / quota)"));
            } else if ("Failed".equals(phase)) {
                alerts.add(alert("error", name, workload, "Pod Failed"));
            } else if ("Running".equals(phase) && !ready) {
                alerts.add(alert("warn", name, workload, "Running mais pas Ready (probes ?)"));
            } else if (restarts >= 3) {
                alerts.add(alert("warn", name, workload, "Restarts élevés : " + restarts));
            }
            pods.add(row);
        }

        List<Map<String, Object>> workloads = listWorkloads(namespace);
        if (workloads.isEmpty()) {
            workloads = deriveWorkloadsFromPods(pods);
        }
        List<Map<String, Object>> services = listServices(namespace);
        List<Map<String, Object>> events = listRecentEvents(namespace, 25);

        double totalCpu = 0;
        long totalMem = 0;
        long totalRx = 0;
        long totalTx = 0;
        long totalFs = 0;
        for (Map<String, Object> p : pods) {
            Object c = p.get("cpuUsageCores");
            Object m = p.get("memoryUsageBytes");
            if (c instanceof Number n) {
                totalCpu += n.doubleValue();
            } else if (p.get("cpuUsage") instanceof String cpuStr) {
                totalCpu += parseCpuToCores(cpuStr);
            }
            if (m instanceof Number n) {
                totalMem += n.longValue();
            } else if (p.get("memoryUsage") instanceof String memStr) {
                totalMem += parseMemoryToBytes(memStr);
            }
            if (p.get("networkRxBytes") instanceof Number n) {
                totalRx += n.longValue();
            }
            if (p.get("networkTxBytes") instanceof Number n) {
                totalTx += n.longValue();
            }
            if (p.get("fsUsedBytes") instanceof Number n) {
                totalFs += n.longValue();
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalPods", total);
        summary.put("readyPods", readyCount);
        summary.put("alertCount", alerts.size());
        summary.put("metricsAvailable", !usageByPod.isEmpty());
        summary.put("workloadCount", workloads.size());
        summary.put("serviceCount", services.size());
        // précision : millicores (ex 3.47) + cores
        summary.put("totalCpuMillicores", Math.round(totalCpu * 1_000_000.0) / 1000.0);
        summary.put("totalCpuCores", Math.round(totalCpu * 1_000_000.0) / 1_000_000.0);
        summary.put("totalMemoryBytes", totalMem);
        summary.put("totalMemoryMi", Math.round(totalMem / (1024.0 * 1024.0) * 100.0) / 100.0);
        summary.put("totalNetworkRxBytes", totalRx);
        summary.put("totalNetworkTxBytes", totalTx);
        summary.put("totalFsUsedBytes", totalFs);
        summary.put("totalNetworkRx", formatBytes(totalRx));
        summary.put("totalNetworkTx", formatBytes(totalTx));
        summary.put("totalFsUsed", formatBytes(totalFs));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("namespace", namespace);
        out.put("pods", pods);
        out.put("workloads", workloads);
        out.put("services", services);
        out.put("events", events);
        out.put("alerts", alerts);
        out.put("summary", summary);
        out.put("quota", fetchResourceQuotaStatus(namespace, summary));
        return out;
    }

    /**
     * Lit ResourceQuota/env-quota (hard vs used alloué) + compare usage réel metrics-server.
     */
    private Map<String, Object> fetchResourceQuotaStatus(String namespace, Map<String, Object> summary) {
        Map<String, Object> quota = new LinkedHashMap<>();
        quota.put("enabled", false);
        quota.put("name", "env-quota");
        try {
            var rq = client().resourceQuotas().inNamespace(namespace).withName("env-quota").get();
            if (rq == null || rq.getStatus() == null) {
                return quota;
            }
            quota.put("enabled", true);
            Map<String, String> hard = new LinkedHashMap<>();
            Map<String, String> used = new LinkedHashMap<>();
            if (rq.getStatus().getHard() != null) {
                rq.getStatus().getHard().forEach((k, v) -> hard.put(k, v != null ? v.toString() : null));
            }
            if (rq.getStatus().getUsed() != null) {
                rq.getStatus().getUsed().forEach((k, v) -> used.put(k, v != null ? v.toString() : null));
            }
            // Spec hard fallback
            if (hard.isEmpty() && rq.getSpec() != null && rq.getSpec().getHard() != null) {
                rq.getSpec().getHard().forEach((k, v) -> hard.put(k, v != null ? v.toString() : null));
            }
            quota.put("hard", hard);
            quota.put("used", used);

            double hardCpu = parseCpuToCores(firstNonBlank(hard, "requests.cpu", "cpu"));
            double usedCpu = parseCpuToCores(firstNonBlank(used, "requests.cpu", "cpu"));
            long hardMem = parseMemoryToBytes(firstNonBlank(hard, "requests.memory", "memory"));
            long usedMem = parseMemoryToBytes(firstNonBlank(used, "requests.memory", "memory"));

            Map<String, Object> pctAllocated = new LinkedHashMap<>();
            pctAllocated.put("cpu", hardCpu > 0 ? round4(usedCpu / hardCpu) : null);
            pctAllocated.put("memory", hardMem > 0 ? round4((double) usedMem / hardMem) : null);
            quota.put("pctAllocated", pctAllocated);

            Double actualCpuCores = summary.get("totalCpuCores") instanceof Number n
                    ? n.doubleValue() : null;
            Long actualMem = summary.get("totalMemoryBytes") instanceof Number n
                    ? n.longValue() : null;
            Map<String, Object> usage = new LinkedHashMap<>();
            usage.put("cpuCores", actualCpuCores);
            usage.put("memoryBytes", actualMem);
            quota.put("usage", usage);

            Map<String, Object> pctActual = new LinkedHashMap<>();
            pctActual.put("cpu", hardCpu > 0 && actualCpuCores != null ? round4(actualCpuCores / hardCpu) : null);
            pctActual.put("memory", hardMem > 0 && actualMem != null ? round4((double) actualMem / hardMem) : null);
            quota.put("pctActualVsHard", pctActual);
            quota.put("hardCpu", hardCpu > 0 ? hardCpu : null);
            quota.put("hardMemoryBytes", hardMem > 0 ? hardMem : null);
            quota.put("usedCpu", usedCpu);
            quota.put("usedMemoryBytes", usedMem);
        } catch (Exception e) {
            log.debug("ResourceQuota ns={}: {}", namespace, e.getMessage());
            quota.put("message", "Quota inaccessible: " + e.getMessage());
        }
        return quota;
    }

    private static String firstNonBlank(Map<String, String> map, String... keys) {
        if (map == null) return null;
        for (String k : keys) {
            String v = map.get(k);
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static double round4(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }

    /** Fallback si list Deployments/STS échoue (RBAC) : agrège les labels app des pods. */
    private List<Map<String, Object>> deriveWorkloadsFromPods(List<Map<String, Object>> pods) {
        Map<String, int[]> byName = new LinkedHashMap<>();
        for (Map<String, Object> p : pods) {
            Object wl = p.get("workload");
            String name = wl != null && !String.valueOf(wl).isBlank()
                    ? String.valueOf(wl) : String.valueOf(p.get("name"));
            int[] counters = byName.computeIfAbsent(name, k -> new int[]{0, 0});
            counters[0]++; // desired ≈ pod count
            if (Boolean.TRUE.equals(p.get("ready")) && "Running".equals(String.valueOf(p.get("phase")))) {
                counters[1]++;
            }
        }
        List<Map<String, Object>> list = new ArrayList<>();
        for (var e : byName.entrySet()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("kind", "Workload");
            row.put("name", e.getKey());
            row.put("desired", e.getValue()[0]);
            row.put("ready", e.getValue()[1]);
            row.put("available", e.getValue()[1]);
            row.put("updated", e.getValue()[1]);
            row.put("healthy", e.getValue()[0] > 0 && e.getValue()[1] >= e.getValue()[0]);
            list.add(row);
        }
        return list;
    }

    private List<Map<String, Object>> listWorkloads(String namespace) {
        List<Map<String, Object>> list = new ArrayList<>();
        try {
            for (var d : client().apps().deployments().inNamespace(namespace).list().getItems()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("kind", "Deployment");
                row.put("name", d.getMetadata() != null ? d.getMetadata().getName() : "?");
                int desired = d.getSpec() != null && d.getSpec().getReplicas() != null
                        ? d.getSpec().getReplicas() : 0;
                int ready = d.getStatus() != null && d.getStatus().getReadyReplicas() != null
                        ? d.getStatus().getReadyReplicas() : 0;
                int available = d.getStatus() != null && d.getStatus().getAvailableReplicas() != null
                        ? d.getStatus().getAvailableReplicas() : 0;
                int updated = d.getStatus() != null && d.getStatus().getUpdatedReplicas() != null
                        ? d.getStatus().getUpdatedReplicas() : 0;
                row.put("desired", desired);
                row.put("ready", ready);
                row.put("available", available);
                row.put("updated", updated);
                row.put("healthy", desired > 0 && ready >= desired);
                list.add(row);
            }
            for (var s : client().apps().statefulSets().inNamespace(namespace).list().getItems()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("kind", "StatefulSet");
                row.put("name", s.getMetadata() != null ? s.getMetadata().getName() : "?");
                int desired = s.getSpec() != null && s.getSpec().getReplicas() != null
                        ? s.getSpec().getReplicas() : 0;
                int ready = s.getStatus() != null && s.getStatus().getReadyReplicas() != null
                        ? s.getStatus().getReadyReplicas() : 0;
                row.put("desired", desired);
                row.put("ready", ready);
                row.put("available", ready);
                row.put("updated", s.getStatus() != null && s.getStatus().getUpdatedReplicas() != null
                        ? s.getStatus().getUpdatedReplicas() : 0);
                row.put("healthy", desired > 0 && ready >= desired);
                list.add(row);
            }
        } catch (Exception e) {
            log.warn("listWorkloads {}: {}", namespace, e.toString());
        }
        return list;
    }

    private List<Map<String, Object>> listServices(String namespace) {
        List<Map<String, Object>> list = new ArrayList<>();
        try {
            for (var svc : client().services().inNamespace(namespace).list().getItems()) {
                if (svc.getMetadata() == null) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", svc.getMetadata().getName());
                row.put("type", svc.getSpec() != null ? svc.getSpec().getType() : "ClusterIP");
                row.put("clusterIP", svc.getSpec() != null ? svc.getSpec().getClusterIP() : null);
                List<String> ports = new ArrayList<>();
                if (svc.getSpec() != null && svc.getSpec().getPorts() != null) {
                    for (var p : svc.getSpec().getPorts()) {
                        String port = String.valueOf(p.getPort());
                        if (p.getTargetPort() != null) {
                            port += "→" + String.valueOf(p.getTargetPort());
                        }
                        if (p.getName() != null) {
                            port = p.getName() + ":" + port;
                        }
                        ports.add(port);
                    }
                }
                row.put("ports", ports);
                list.add(row);
            }
        } catch (Exception e) {
            log.warn("listServices {}: {}", namespace, e.toString());
        }
        return list;
    }

    private List<Map<String, Object>> listRecentEvents(String namespace, int limit) {
        List<Map<String, Object>> list = new ArrayList<>();
        try {
            List<io.fabric8.kubernetes.api.model.Event> items;
            try {
                items = new ArrayList<>(client().v1().events().inNamespace(namespace).list().getItems());
            } catch (Exception primary) {
                log.debug("events v1 API fallback: {}", primary.toString());
                items = new ArrayList<>(client().resources(io.fabric8.kubernetes.api.model.Event.class)
                        .inNamespace(namespace).list().getItems());
            }
            items.sort((a, b) -> {
                String ta = eventTime(a);
                String tb = eventTime(b);
                return tb.compareTo(ta);
            });
            int n = 0;
            for (var ev : items) {
                if (n >= limit) {
                    break;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("type", ev.getType());
                row.put("reason", ev.getReason());
                row.put("message", ev.getMessage());
                row.put("count", ev.getCount());
                row.put("object", ev.getInvolvedObject() != null
                        ? ev.getInvolvedObject().getKind() + "/" + ev.getInvolvedObject().getName()
                        : null);
                row.put("lastTimestamp", eventTime(ev).isBlank() ? null : eventTime(ev));
                list.add(row);
                n++;
            }
        } catch (Exception e) {
            log.warn("listRecentEvents {}: {}", namespace, e.toString());
        }
        return list;
    }

    private static String eventTime(io.fabric8.kubernetes.api.model.Event ev) {
        if (ev.getLastTimestamp() != null && !ev.getLastTimestamp().isBlank()) {
            return ev.getLastTimestamp();
        }
        if (ev.getEventTime() != null && ev.getEventTime().getTime() != null) {
            return ev.getEventTime().getTime();
        }
        if (ev.getMetadata() != null && ev.getMetadata().getCreationTimestamp() != null) {
            return ev.getMetadata().getCreationTimestamp();
        }
        return "";
    }

    private static boolean allContainersReady(io.fabric8.kubernetes.api.model.Pod pod) {
        if (pod.getStatus() == null || pod.getStatus().getContainerStatuses() == null
                || pod.getStatus().getContainerStatuses().isEmpty()) {
            return false;
        }
        return pod.getStatus().getContainerStatuses().stream()
                .allMatch(cs -> Boolean.TRUE.equals(cs.getReady()));
    }

    private static Map<String, Object> alert(String severity, String pod, String workload, String message) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("severity", severity);
        a.put("pod", pod);
        a.put("workload", workload);
        a.put("message", message);
        return a;
    }

    private record ResourceRequests(
            String cpuRequest, String cpuLimit, String memoryRequest, String memoryLimit
    ) {}

    private record PodMetricUsage(
            String cpu,
            String memory,
            double cpuCores,
            long memoryBytes,
            long networkRxBytes,
            long networkTxBytes,
            long fsUsedBytes,
            long fsCapacityBytes
    ) {
        PodMetricUsage withNetworkAndFs(long rx, long tx, long fsUsed, long fsCap) {
            return new PodMetricUsage(cpu, memory, cpuCores, memoryBytes, rx, tx, fsUsed, fsCap);
        }
    }

    private ResourceRequests extractResources(io.fabric8.kubernetes.api.model.Pod pod) {
        String cpuReq = null, cpuLim = null, memReq = null, memLim = null;
        if (pod.getSpec() != null && pod.getSpec().getContainers() != null) {
            for (var c : pod.getSpec().getContainers()) {
                if (c.getResources() == null) {
                    continue;
                }
                if (c.getResources().getRequests() != null) {
                    var cpu = c.getResources().getRequests().get("cpu");
                    var mem = c.getResources().getRequests().get("memory");
                    if (cpu != null) {
                        cpuReq = cpu.toString();
                    }
                    if (mem != null) {
                        memReq = mem.toString();
                    }
                }
                if (c.getResources().getLimits() != null) {
                    var cpu = c.getResources().getLimits().get("cpu");
                    var mem = c.getResources().getLimits().get("memory");
                    if (cpu != null) {
                        cpuLim = cpu.toString();
                    }
                    if (mem != null) {
                        memLim = mem.toString();
                    }
                }
            }
        }
        return new ResourceRequests(cpuReq, cpuLim, memReq, memLim);
    }

    private Map<String, PodMetricUsage> fetchPodMetrics(String namespace) {
        Map<String, PodMetricUsage> out = new LinkedHashMap<>();
        if (apiUrl == null || apiUrl.isBlank() || token == null || token.isBlank()) {
            return out;
        }
        try {
            String base = apiUrl.trim().replaceAll("/+$", "");
            String url = base + "/apis/metrics.k8s.io/v1beta1/namespaces/"
                    + namespace + "/pods";
            java.net.http.HttpClient.Builder httpBuilder = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(5));
            if (insecureSkipTlsVerify) {
                javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                        new javax.net.ssl.X509TrustManager() {
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                return new java.security.cert.X509Certificate[0];
                            }
                            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                        }
                };
                javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS");
                ssl.init(null, trustAll, new java.security.SecureRandom());
                httpBuilder.sslContext(ssl);
            }
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(8))
                    .header("Authorization", "Bearer " + token.trim())
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            java.net.http.HttpResponse<String> resp = httpBuilder.build()
                    .send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                log.debug("metrics-server HTTP {} pour {}", resp.statusCode(), namespace);
                return out;
            }
            com.fasterxml.jackson.databind.JsonNode root =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(resp.body());
            var items = root.get("items");
            if (items == null || !items.isArray()) {
                return out;
            }
            for (var item : items) {
                String podName = item.path("metadata").path("name").asText(null);
                if (podName == null) {
                    continue;
                }
                double cpuCores = 0;
                long memBytes = 0;
                var containers = item.get("containers");
                if (containers != null && containers.isArray()) {
                    for (var c : containers) {
                        cpuCores += parseCpuToCores(c.path("usage").path("cpu").asText("0"));
                        memBytes += parseMemoryToBytes(c.path("usage").path("memory").asText("0"));
                    }
                }
                out.put(podName, new PodMetricUsage(
                        formatCpu(cpuCores),
                        formatMemory(memBytes),
                        cpuCores,
                        memBytes,
                        0L, 0L, 0L, 0L));
            }
        } catch (Exception e) {
            log.debug("metrics-server indisponible pour {}: {}", namespace, e.getMessage());
        }
        return out;
    }

    /**
     * Enrichit usage CPU/MEM avec réseau + filesystem via kubelet /stats/summary (proxy API).
     */
    private Map<String, PodMetricUsage> enrichWithKubeletStats(
            String namespace,
            Map<String, PodMetricUsage> base
    ) {
        Map<String, PodMetricUsage> out = new LinkedHashMap<>(base);
        if (apiUrl == null || apiUrl.isBlank() || token == null || token.isBlank()) {
            return out;
        }
        try {
            java.util.Set<String> nodes = new java.util.LinkedHashSet<>();
            for (var pod : client().pods().inNamespace(namespace).list().getItems()) {
                if (pod.getSpec() != null && pod.getSpec().getNodeName() != null) {
                    nodes.add(pod.getSpec().getNodeName());
                }
            }
            if (nodes.isEmpty()) {
                return out;
            }
            String baseUrl = apiUrl.trim().replaceAll("/+$", "");
            java.net.http.HttpClient http = buildK8sHttpClient();
            for (String node : nodes) {
                try {
                    String url = baseUrl + "/api/v1/nodes/"
                            + java.net.URLEncoder.encode(node, java.nio.charset.StandardCharsets.UTF_8)
                                    .replace("+", "%20")
                            + "/proxy/stats/summary";
                    java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(url))
                            .timeout(java.time.Duration.ofSeconds(6))
                            .header("Authorization", "Bearer " + token.trim())
                            .header("Accept", "application/json")
                            .GET()
                            .build();
                    java.net.http.HttpResponse<String> resp = http.send(
                            req, java.net.http.HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                        log.debug("kubelet stats node={} HTTP {}", node, resp.statusCode());
                        continue;
                    }
                    com.fasterxml.jackson.databind.JsonNode root =
                            new com.fasterxml.jackson.databind.ObjectMapper().readTree(resp.body());
                    var podsNode = root.get("pods");
                    if (podsNode == null || !podsNode.isArray()) {
                        continue;
                    }
                    for (var p : podsNode) {
                        String ns = p.path("podRef").path("namespace").asText("");
                        String podName = p.path("podRef").path("name").asText(null);
                        if (podName == null || !namespace.equals(ns)) {
                            continue;
                        }
                        long rx = p.path("network").path("rxBytes").asLong(0);
                        long tx = p.path("network").path("txBytes").asLong(0);
                        long fsUsed = p.path("ephemeral-storage").path("usedBytes").asLong(0);
                        long fsCap = p.path("ephemeral-storage").path("capacityBytes").asLong(0);
                        // fallback rootfs / volumes
                        if (fsUsed <= 0 && p.has("volume")) {
                            for (var v : p.get("volume")) {
                                fsUsed += v.path("usedBytes").asLong(0);
                                fsCap += v.path("capacityBytes").asLong(0);
                            }
                        }
                        PodMetricUsage prev = out.get(podName);
                        if (prev != null) {
                            out.put(podName, prev.withNetworkAndFs(rx, tx, fsUsed, fsCap));
                        } else {
                            // pas de metrics-server : au moins réseau/disque
                            out.put(podName, new PodMetricUsage(
                                    null, null, 0, 0, rx, tx, fsUsed, fsCap));
                        }
                    }
                } catch (Exception nodeEx) {
                    log.debug("kubelet stats node={}: {}", node, nodeEx.getMessage());
                }
            }
        } catch (Exception e) {
            log.debug("enrichWithKubeletStats {}: {}", namespace, e.getMessage());
        }
        return out;
    }

    private java.net.http.HttpClient buildK8sHttpClient() throws Exception {
        java.net.http.HttpClient.Builder httpBuilder = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5));
        if (insecureSkipTlsVerify) {
            javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[0];
                        }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    }
            };
            javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS");
            ssl.init(null, trustAll, new java.security.SecureRandom());
            httpBuilder.sslContext(ssl);
        }
        return httpBuilder.build();
    }

    private static double parseCpuToCores(String raw) {
        if (raw == null || raw.isBlank() || "0".equals(raw)) {
            return 0;
        }
        String s = raw.trim();
        try {
            if (s.endsWith("n")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) / 1_000_000_000.0;
            }
            if (s.endsWith("u")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) / 1_000_000.0;
            }
            if (s.endsWith("m")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) / 1000.0;
            }
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long parseMemoryToBytes(String raw) {
        if (raw == null || raw.isBlank() || "0".equals(raw)) {
            return 0;
        }
        String s = raw.trim();
        try {
            if (s.endsWith("Ki")) {
                return Long.parseLong(s.substring(0, s.length() - 2)) * 1024L;
            }
            if (s.endsWith("Mi")) {
                return Long.parseLong(s.substring(0, s.length() - 2)) * 1024L * 1024L;
            }
            if (s.endsWith("Gi")) {
                return Long.parseLong(s.substring(0, s.length() - 2)) * 1024L * 1024L * 1024L;
            }
            if (s.endsWith("Ti")) {
                return Long.parseLong(s.substring(0, s.length() - 2)) * 1024L * 1024L * 1024L * 1024L;
            }
            if (s.endsWith("k")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 1000L;
            }
            if (s.endsWith("M")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 1_000_000L;
            }
            if (s.endsWith("G")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 1_000_000_000L;
            }
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String formatCpu(double cores) {
        if (cores <= 0) {
            return "0";
        }
        double micro = cores * 1_000_000.0;
        double milli = cores * 1000.0;
        // très petit : microcores (µ) pour ne jamais afficher 0
        if (milli < 0.1) {
            return String.format(java.util.Locale.ROOT, "%.0fµ", Math.max(1, Math.round(micro)));
        }
        if (milli < 10) {
            return String.format(java.util.Locale.ROOT, "%.2fm", milli);
        }
        if (cores < 1) {
            return String.format(java.util.Locale.ROOT, "%.1fm", milli);
        }
        return String.format(java.util.Locale.ROOT, "%.3f", cores);
    }

    private static String formatMemory(long bytes) {
        if (bytes <= 0) {
            return "0";
        }
        return formatBytes(bytes);
    }

    private static String formatBytes(long bytes) {
        if (bytes <= 0) {
            return "0";
        }
        if (bytes < 1024L) {
            return bytes + "B";
        }
        if (bytes < 1024L * 1024L) {
            return String.format(java.util.Locale.ROOT, "%.1fKi", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024L * 1024L) {
            return String.format(java.util.Locale.ROOT, "%.1fMi", bytes / (1024.0 * 1024.0));
        }
        return String.format(java.util.Locale.ROOT, "%.2fGi", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    /**
     * Logs d'un pod (ou du premier pod du workload label app=…).
     */
    public Map<String, Object> getPodLogs(String namespace, String workloadOrPod, int tailLines) {
        requireConfigured();
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("namespace requis");
        }
        int tail = Math.min(Math.max(tailLines, 50), 2000);
        String podName = resolvePodName(namespace, workloadOrPod);
        if (podName == null) {
            throw new AppValidationException(
                    "Aucun pod trouvé pour « " + workloadOrPod + " » dans " + namespace);
        }
        try {
            String logs = client().pods().inNamespace(namespace).withName(podName)
                    .tailingLines(tail)
                    .getLog();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("namespace", namespace);
            out.put("pod", podName);
            out.put("workload", workloadOrPod);
            out.put("tailLines", tail);
            out.put("logs", logs != null ? logs : "");
            return out;
        } catch (AppValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new AppValidationException(
                    "Impossible de lire les logs de " + podName + " : " + e.getMessage());
        }
    }

    private String resolvePodName(String namespace, String workloadOrPod) {
        if (workloadOrPod == null || workloadOrPod.isBlank()) {
            return null;
        }
        var direct = client().pods().inNamespace(namespace).withName(workloadOrPod).get();
        if (direct != null) {
            return workloadOrPod;
        }
        var labeled = client().pods().inNamespace(namespace)
                .withLabel("app", workloadOrPod)
                .list()
                .getItems();
        if (labeled.isEmpty()) {
            return null;
        }
        // Préférer un pod Running ready, sinon le premier.
        for (var pod : labeled) {
            if (pod.getStatus() != null && "Running".equals(pod.getStatus().getPhase())) {
                return pod.getMetadata().getName();
            }
        }
        return labeled.get(0).getMetadata().getName();
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
            log.warn("ready check {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    /**
     * Ready uniquement si chaque workload attendu a au moins un pod Running+Ready
     * (évite le faux SUCCESS quand un service n'a encore aucun pod).
     */
    public boolean areExpectedWorkloadsReady(String namespace, Collection<String> expectedWorkloadNames) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return false;
        }
        if (expectedWorkloadNames == null || expectedWorkloadNames.isEmpty()) {
            return areAllDeploymentsReady(namespace);
        }
        for (String name : expectedWorkloadNames) {
            if (name == null || name.isBlank()) {
                continue;
            }
            boolean depOrStsReady = isDeploymentReady(namespace, name) || isStatefulSetReady(namespace, name);
            boolean podsReady = areWorkloadPodsReady(namespace, name);
            if (!depOrStsReady && !podsReady) {
                return false;
            }
        }
        return true;
    }

    public boolean isStatefulSetReady(String namespace, String name) {
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || name == null || name.isBlank()) {
            return false;
        }
        try {
            StatefulSet ss = client().apps().statefulSets()
                    .inNamespace(namespace).withName(name).get();
            if (ss == null) {
                return false;
            }
            return workloadReady(
                    ss.getSpec() != null ? ss.getSpec().getReplicas() : null,
                    ss.getStatus() != null ? ss.getStatus().getReadyReplicas() : null);
        } catch (Exception e) {
            log.debug("statefulset pas ready {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    /**
     * True si le namespace a au moins un pod et que tous sont Running + Ready
     * (aucun Pending / Failed). Préférer {@link #areExpectedWorkloadsReady}.
     */
    public boolean areAllPodsReady(String namespace) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return false;
        }
        try {
            var pods = client().pods().inNamespace(namespace).list().getItems();
            if (pods == null || pods.isEmpty()) {
                return false;
            }
            for (var pod : pods) {
                String phase = pod.getStatus() != null ? pod.getStatus().getPhase() : null;
                if ("Succeeded".equals(phase)) {
                    continue; // Job / one-shot
                }
                if (!"Running".equals(phase)) {
                    return false;
                }
                if (!isPodContainersReady(pod)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            log.warn("pods ready check {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    private static boolean isPodContainersReady(io.fabric8.kubernetes.api.model.Pod pod) {
        if (pod.getStatus() == null || pod.getStatus().getContainerStatuses() == null
                || pod.getStatus().getContainerStatuses().isEmpty()) {
            return false;
        }
        return pod.getStatus().getContainerStatuses().stream()
                .allMatch(cs -> Boolean.TRUE.equals(cs.getReady()));
    }

    /**
     * Au moins un pod Running+Ready pour le label {@code app=<workloadName>}.
     */
    public boolean areWorkloadPodsReady(String namespace, String workloadName) {
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || workloadName == null || workloadName.isBlank()) {
            return false;
        }
        try {
            var pods = client().pods().inNamespace(namespace)
                    .withLabel("app", workloadName)
                    .list()
                    .getItems();
            if (pods == null || pods.isEmpty()) {
                return false;
            }
            for (var pod : pods) {
                String phase = pod.getStatus() != null ? pod.getStatus().getPhase() : null;
                if (!"Running".equals(phase) || !isPodContainersReady(pod)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            log.debug("workload pods ready {}/{}: {}", namespace, workloadName, e.getMessage());
            return false;
        }
    }

    public boolean hasAnyIngress(String namespace) {
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return false;
        }
        try {
            var items = client().network().v1().ingresses().inNamespace(namespace).list().getItems();
            return items != null && !items.isEmpty();
        } catch (Exception e) {
            log.debug("ingress check {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    /**
     * Attend que les workloads {@code tier=database} soient Ready (vague 0).
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
        long lastLog = 0L;
        while (System.currentTimeMillis() < deadline) {
            boolean allReady = true;
            for (String name : deploymentNames) {
                if (name == null || name.isBlank()) {
                    continue;
                }
                boolean depReady = isDeploymentReady(namespace, name);
                boolean podsReady = areWorkloadPodsReady(namespace, name);
                if (!depReady && !podsReady) {
                    allReady = false;
                    long now = System.currentTimeMillis();
                    if (now - lastLog > 15_000L) {
                        Deployment d = client().apps().deployments()
                                .inNamespace(namespace).withName(name).get();
                        Integer want = d != null && d.getSpec() != null ? d.getSpec().getReplicas() : null;
                        Integer have = d != null && d.getStatus() != null ? d.getStatus().getReadyReplicas() : null;
                        log.info("Attente Ready {}/{} — replicas={}/{} podsReady={}",
                                namespace, name, have, want, podsReady);
                        lastLog = now;
                    }
                    break;
                }
                if (!depReady && podsReady) {
                    log.info("Vague {}/{} : pods Ready (Deployment pas FullyAvailable — on continue)",
                            namespace, name);
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

    /**
     * Force un rollout restart pour que les pods rechargent Secrets / env mis à jour.
     */
    public void restartDeployment(String namespace, String deploymentName) {
        requireConfigured();
        if (namespace == null || namespace.isBlank() || deploymentName == null || deploymentName.isBlank()) {
            throw new IllegalArgumentException("namespace et deploymentName requis");
        }
        Deployment deployment = client().apps().deployments().inNamespace(namespace).withName(deploymentName).get();
        if (deployment == null) {
            throw new IllegalStateException(
                    "Deployment " + deploymentName + " introuvable dans " + namespace);
        }
        client().apps().deployments().inNamespace(namespace).withName(deploymentName)
                .rolling().restart();
        log.info("Rollout restart Deployment/{}/{}", namespace, deploymentName);
    }

    /**
     * Met à jour le nombre de replicas via le subresource Scale.
     * Nécessaire car server-side apply ignore souvent {@code spec.replicas}
     * (champ géré séparément par Kubernetes).
     */
    public void scaleDeployment(String namespace, String deploymentName, int replicas) {
        requireConfigured();
        if (namespace == null || namespace.isBlank() || deploymentName == null || deploymentName.isBlank()) {
            throw new IllegalArgumentException("namespace et deploymentName requis");
        }
        int desired = Math.max(1, replicas);
        Deployment deployment = client().apps().deployments().inNamespace(namespace).withName(deploymentName).get();
        if (deployment == null) {
            throw new IllegalStateException(
                    "Deployment " + deploymentName + " introuvable dans " + namespace);
        }
        Integer current = deployment.getSpec() != null ? deployment.getSpec().getReplicas() : null;
        if (current != null && current == desired) {
            log.debug("Scale {}/{} déjà à {} — skip", namespace, deploymentName, desired);
            return;
        }
        client().apps().deployments().inNamespace(namespace).withName(deploymentName).scale(desired);
        log.info("Scale Deployment/{}/{} : {} → {}", namespace, deploymentName, current, desired);
    }

    /** Supprime un Secret s'il existe (ex. plus aucune env secrète). */
    public void deleteSecretIfExists(String namespace, String secretName) {
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || secretName == null || secretName.isBlank()) {
            return;
        }
        try {
            var secret = client().secrets().inNamespace(namespace).withName(secretName).get();
            if (secret != null) {
                client().secrets().inNamespace(namespace).withName(secretName).delete();
                log.info("Secret {}/{} supprimé", namespace, secretName);
            }
        } catch (Exception e) {
            log.warn("Suppression Secret {}/{} ignorée: {}", namespace, secretName, e.getMessage());
        }
    }

    /**
     * Supprime les ressources K8s d'un service applicatif (Deployment, Service, Secret, Ingress).
     * Ne touche pas au namespace ni aux autres services.
     */
    public List<String> deleteAppServiceResources(String namespace, String k8sName) {
        List<String> removed = new ArrayList<>();
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || k8sName == null || k8sName.isBlank()) {
            return removed;
        }
        String name = k8sName.trim();
        if (deleteDeploymentIfExists(namespace, name)) {
            removed.add("Deployment/" + name);
        }
        if (deleteServiceIfExists(namespace, name)) {
            removed.add("Service/" + name);
        }
        if (deleteServiceIfExists(namespace, name + "-external")) {
            removed.add("Service/" + name + "-external");
        }
        if (deleteSecretNamed(namespace, name + "-secrets")) {
            removed.add("Secret/" + name + "-secrets");
        }
        if (deleteIngressIfExists(namespace, name)) {
            removed.add("Ingress/" + name);
        }
        return removed;
    }

    /** Ressources d'une base managée ({@code db-<name>}). */
    public List<String> deleteDatabaseResources(String namespace, String dbSvcName) {
        List<String> removed = new ArrayList<>();
        if (!isConfigured() || namespace == null || namespace.isBlank()
                || dbSvcName == null || dbSvcName.isBlank()) {
            return removed;
        }
        String name = dbSvcName.trim();
        if (deleteDeploymentIfExists(namespace, name)) {
            removed.add("Deployment/" + name);
        }
        if (deleteStatefulSetIfExists(namespace, name)) {
            removed.add("StatefulSet/" + name);
        }
        if (deleteServiceIfExists(namespace, name)) {
            removed.add("Service/" + name);
        }
        if (deleteSecretNamed(namespace, name + "-credentials")) {
            removed.add("Secret/" + name + "-credentials");
        }
        if (deletePvcIfExists(namespace, name + "-data")) {
            removed.add("PersistentVolumeClaim/" + name + "-data");
        }
        return removed;
    }

    /** Ingress path-based + middlewares Traefik partagés. */
    public List<String> deleteSharedAppIngress(String namespace) {
        List<String> removed = new ArrayList<>();
        if (!isConfigured() || namespace == null || namespace.isBlank()) {
            return removed;
        }
        if (deleteIngressIfExists(namespace, "app-ingress")) {
            removed.add("Ingress/app-ingress");
        }
        if (deleteTraefikMiddlewareIfExists(namespace, "app-api-rewrite")) {
            removed.add("Middleware/app-api-rewrite");
        }
        if (deleteTraefikMiddlewareIfExists(namespace, "app-strip-prefix")) {
            removed.add("Middleware/app-strip-prefix");
        }
        return removed;
    }

    private boolean deleteDeploymentIfExists(String namespace, String name) {
        try {
            Deployment d = client().apps().deployments().inNamespace(namespace).withName(name).get();
            if (d == null) {
                return false;
            }
            client().apps().deployments().inNamespace(namespace).withName(name).delete();
            log.info("Deployment {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression Deployment {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deleteStatefulSetIfExists(String namespace, String name) {
        try {
            StatefulSet ss = client().apps().statefulSets().inNamespace(namespace).withName(name).get();
            if (ss == null) {
                return false;
            }
            client().apps().statefulSets().inNamespace(namespace).withName(name).delete();
            log.info("StatefulSet {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression StatefulSet {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deleteServiceIfExists(String namespace, String name) {
        try {
            var svc = client().services().inNamespace(namespace).withName(name).get();
            if (svc == null) {
                return false;
            }
            client().services().inNamespace(namespace).withName(name).delete();
            log.info("Service {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression Service {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deleteSecretNamed(String namespace, String name) {
        try {
            var secret = client().secrets().inNamespace(namespace).withName(name).get();
            if (secret == null) {
                return false;
            }
            client().secrets().inNamespace(namespace).withName(name).delete();
            log.info("Secret {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression Secret {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deletePvcIfExists(String namespace, String name) {
        try {
            var pvc = client().persistentVolumeClaims().inNamespace(namespace).withName(name).get();
            if (pvc == null) {
                return false;
            }
            client().persistentVolumeClaims().inNamespace(namespace).withName(name).delete();
            log.info("PVC {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression PVC {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deleteIngressIfExists(String namespace, String name) {
        try {
            var ing = client().network().v1().ingresses().inNamespace(namespace).withName(name).get();
            if (ing == null) {
                return false;
            }
            client().network().v1().ingresses().inNamespace(namespace).withName(name).delete();
            log.info("Ingress {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression Ingress {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
    }

    private boolean deleteTraefikMiddlewareIfExists(String namespace, String name) {
        try {
            var rdc = new io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext.Builder()
                    .withGroup("traefik.io")
                    .withVersion("v1alpha1")
                    .withKind("Middleware")
                    .withPlural("middlewares")
                    .withNamespaced(true)
                    .build();
            var existing = client().genericKubernetesResources(rdc).inNamespace(namespace).withName(name).get();
            if (existing == null) {
                return false;
            }
            client().genericKubernetesResources(rdc).inNamespace(namespace).withName(name).delete();
            log.info("Middleware {}/{} supprimé", namespace, name);
            return true;
        } catch (Exception e) {
            log.warn("Suppression Middleware {}/{}: {}", namespace, name, e.getMessage());
            return false;
        }
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

    private static boolean isNonBlockingApplyKind(String kind) {
        return "Ingress".equalsIgnoreCase(kind) || "Middleware".equalsIgnoreCase(kind);
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
                    // Ne pas abandonner immédiatement : l'API peut être légèrement en retard
                    // après apply, ou les labels metadata absents sur d'anciens manifests.
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
                    int reqMs = Math.max(10, requestTimeoutSeconds) * 1000;
                    Config config = new ConfigBuilder()
                            .withMasterUrl(apiUrl.trim())
                            .withOauthToken(token.trim())
                            .withTrustCerts(insecureSkipTlsVerify)
                            .withConnectionTimeout(10_000)
                            .withRequestTimeout(reqMs)
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
