package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DeploymentMetricSample;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.DeploymentMetricSampleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Échantillonne les métriques namespace des déploiements RUNNING (historique long terme).
 */
@Service
@Slf4j
public class DeploymentMetricsSamplerService {

    private final AppDeploymentRepository deploymentRepository;
    private final DeploymentMetricSampleRepository sampleRepository;
    private final K8sManifestApplyService k8sManifestApplyService;

    @Value("${deployment.metrics.sample-enabled:true}")
    private boolean sampleEnabled;

    @Value("${deployment.metrics.retention-days:7}")
    private int retentionDays;

    public DeploymentMetricsSamplerService(
            AppDeploymentRepository deploymentRepository,
            DeploymentMetricSampleRepository sampleRepository,
            K8sManifestApplyService k8sManifestApplyService
    ) {
        this.deploymentRepository = deploymentRepository;
        this.sampleRepository = sampleRepository;
        this.k8sManifestApplyService = k8sManifestApplyService;
    }

    /**
     * Échantillonne les métriques K8s hors transaction longue, puis persiste.
     */
    public void sampleRunningDeployments() {
        if (!sampleEnabled || !k8sManifestApplyService.isConfigured()) {
            return;
        }
        // EntityGraph application (findByStatus) — session courte via le repo
        List<AppDeployment> running = deploymentRepository.findByStatus(AppDeploymentStatus.RUNNING);
        Instant now = Instant.now();
        int n = 0;
        for (AppDeployment d : running) {
            try {
                if (sampleOne(d, now)) {
                    n++;
                }
            } catch (Exception e) {
                log.debug("Sample métriques {}: {}", d.getId(), e.getMessage());
            }
        }
        Instant cutoff = now.minus(Math.max(1, retentionDays), ChronoUnit.DAYS);
        int deleted = sampleRepository.deleteBySampledAtBefore(cutoff);
        if (n > 0 || deleted > 0) {
            log.info("Métriques: {} échantillon(s), {} ancien(s) purgé(s)", n, deleted);
        }
    }

    private boolean sampleOne(AppDeployment deployment, Instant now) {
        if (deployment.getNamespace() == null || deployment.getNamespace().isBlank()) {
            return false;
        }
        ManagedApplication app = deployment.getApplication();
        if (app == null) {
            return false;
        }
        Map<String, Object> mon;
        try {
            mon = k8sManifestApplyService.getNamespaceMonitoring(deployment.getNamespace());
        } catch (Exception e) {
            return false;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = mon.get("summary") instanceof Map<?, ?> m
                ? (Map<String, Object>) m
                : Map.of();

        DeploymentMetricSample s = new DeploymentMetricSample();
        s.setDeploymentId(deployment.getId());
        s.setApplicationId(app.getId());
        s.setNamespace(deployment.getNamespace());
        s.setSampledAt(now);
        s.setCpuMillicores(asDouble(summary.get("totalCpuMillicores")));
        s.setMemoryBytes(asLong(summary.get("totalMemoryBytes")));
        s.setNetworkRxBytes(asLong(summary.get("totalNetworkRxBytes")));
        s.setNetworkTxBytes(asLong(summary.get("totalNetworkTxBytes")));
        s.setFsUsedBytes(asLong(summary.get("totalFsUsedBytes")));
        s.setReadyPods(asInt(summary.get("readyPods")));
        s.setTotalPods(asInt(summary.get("totalPods")));
        sampleRepository.save(s);
        return true;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> history(UUID appId, UUID deploymentId, Instant from, Instant to) {
        Instant end = to != null ? to : Instant.now();
        Instant start = from != null ? from : end.minus(24, ChronoUnit.HOURS);
        List<DeploymentMetricSample> rows = sampleRepository
                .findByDeploymentIdAndSampledAtBetweenOrderBySampledAtAsc(deploymentId, start, end);
        List<Map<String, Object>> points = new ArrayList<>();
        for (DeploymentMetricSample s : rows) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("t", s.getSampledAt() != null ? s.getSampledAt().toString() : null);
            p.put("cpuMilli", s.getCpuMillicores());
            p.put("memBytes", s.getMemoryBytes());
            p.put("memMi", s.getMemoryBytes() != null
                    ? Math.round(s.getMemoryBytes() / (1024.0 * 1024.0) * 100.0) / 100.0
                    : null);
            p.put("netRx", s.getNetworkRxBytes());
            p.put("netTx", s.getNetworkTxBytes());
            p.put("fsUsed", s.getFsUsedBytes());
            p.put("readyPods", s.getReadyPods());
            p.put("totalPods", s.getTotalPods());
            points.add(p);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("deploymentId", deploymentId);
        out.put("applicationId", appId);
        out.put("from", start.toString());
        out.put("to", end.toString());
        out.put("retentionDays", retentionDays);
        out.put("points", points);
        out.put("count", points.size());
        return out;
    }

    private static Double asDouble(Object o) {
        return o instanceof Number n ? n.doubleValue() : null;
    }

    private static Long asLong(Object o) {
        return o instanceof Number n ? n.longValue() : null;
    }

    private static Integer asInt(Object o) {
        return o instanceof Number n ? n.intValue() : null;
    }
}
