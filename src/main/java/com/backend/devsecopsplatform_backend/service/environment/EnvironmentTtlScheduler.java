package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.service.appmgmt.K8sManifestApplyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EnvironmentTtlScheduler {

    private final EphemeralEnvironmentRepository environmentRepository;
    private final EnvironmentLifecycleService lifecycle;
    private final K8sManifestApplyService k8sManifestApplyService;

    /**
     * Passe logique : marque EXPIRED les environnements vivants dont le TTL est dépassé.
     * FAILED est immunisé (ne devient jamais EXPIRED).
     */
    @Scheduled(fixedDelayString = "${env.ttl-check-interval-ms:60000}")
    @Transactional
    public void markExpiredEnvironments() {
        LocalDateTime now = LocalDateTime.now();

        List<EphemeralEnvironment> candidates = environmentRepository
                .findByStatusNotInAndExpiresAtBefore(EnvironmentLifecycleService.TTL_IMMUNE, now);

        for (EphemeralEnvironment env : candidates) {
            String reason = "TTL de " + env.getTtlHours() + " h atteint";
            log.info("⏰ Env {} (id={}) TTL dépassé (expiresAt={}) → EXPIRED",
                    env.getEnvironmentName(), env.getId(), env.getExpiresAt());
            lifecycle.onExpired(env.getId(), reason);
        }
    }

    /**
     * Passe physique : supprime le namespace K8s puis marque DESTROYED.
     */
    @Scheduled(fixedDelayString = "${env.cleanup-interval-ms:120000}")
    @Transactional
    public void cleanupDeadEnvironments() {
        List<EphemeralEnvironment> dead = environmentRepository
                .findByStatusIn(EnvironmentLifecycleService.CLEANUP_CANDIDATES);

        for (EphemeralEnvironment env : dead) {
            String namespace = env.getNamespace();
            if (namespace != null && !namespace.isBlank()) {
                try {
                    k8sManifestApplyService.deleteNamespace(namespace);
                    log.info("🧹 Namespace {} supprimé pour env {}", namespace, env.getId());
                } catch (Exception e) {
                    log.warn("⚠️ Suppression namespace {} échouée pour env {}: {}",
                            namespace, env.getId(), e.getMessage());
                    continue;
                }
            }
            lifecycle.onDestroyed(env.getId(), "Ressources Kubernetes supprimées");
        }
    }
}
