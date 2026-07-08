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

import java.util.List;

/**
 * Réconciliation K8s : détecte RUNNING ↔ DEGRADED selon readyReplicas.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EnvironmentReconcileScheduler {

    private final EphemeralEnvironmentRepository environmentRepository;
    private final EnvironmentLifecycleService lifecycle;
    private final K8sManifestApplyService k8sManifestApplyService;

    @Scheduled(fixedDelayString = "${env.reconcile-interval-ms:30000}")
    @Transactional
    public void reconcileAlive() {
        List<EphemeralEnvironment> alive = environmentRepository
                .findByStatusIn(EnvironmentLifecycleService.ALIVE);

        for (EphemeralEnvironment env : alive) {
            String namespace = env.getNamespace();
            if (namespace == null || namespace.isBlank()) {
                continue;
            }
            boolean ready = k8sManifestApplyService.areAllDeploymentsReady(namespace);
            if (ready) {
                lifecycle.onReady(env.getId(), env.getUrl());
            } else if (env.getStatus() == EnvironmentStatus.RUNNING) {
                lifecycle.onDegraded(env.getId(), "Aucun pod prêt dans le namespace");
            }
        }
    }
}
