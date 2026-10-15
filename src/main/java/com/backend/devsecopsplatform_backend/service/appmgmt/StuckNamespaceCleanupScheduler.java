package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Balayage périodique cluster-wide des namespaces restés bloqués en Terminating -- voir
 * {@link K8sManifestApplyService#sweepStuckNamespaces}. Complète {@code deleteNamespace()} (qui ne
 * réagit qu'au moment précis où LUI fait le teardown) : un namespace bloqué par n'importe quel
 * autre chemin (process interrompu en cours de route, etc.) serait sinon jamais nettoyé.
 * Sans ce filet, un namespace bloqué peut faire échouer silencieusement TOUT nouveau déploiement
 * réutilisant le même hostname personnalisé (conflit d'Ingress/EndpointSlices avec Traefik,
 * "503 no available server") -- observé en pratique le 28 août 2026 (aoo 1, bloqué 29h+, plusieurs
 * redéploiements successifs cassés jusqu'à nettoyage manuel).
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class StuckNamespaceCleanupScheduler {

    private final K8sManifestApplyService k8sManifestApplyService;

    @Value("${scan.posture.stuck-namespace-min-age-ms:300000}")
    private long minStuckAgeMs;

    @Scheduled(fixedDelayString = "${scan.posture.stuck-namespace-sweep-ms:300000}")
    public void sweep() {
        try {
            int cleaned = k8sManifestApplyService.sweepStuckNamespaces(
                    Duration.ofMillis(Math.max(minStuckAgeMs, 60_000)));
            if (cleaned > 0) {
                log.info("Balayage namespaces bloqués : {} nettoyé(s)", cleaned);
            }
        } catch (Exception e) {
            log.warn("Échec balayage namespaces bloqués: {}", e.getMessage());
        }
    }
}
