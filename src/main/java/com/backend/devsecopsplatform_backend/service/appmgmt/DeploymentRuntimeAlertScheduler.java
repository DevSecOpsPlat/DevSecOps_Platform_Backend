package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Poll périodique des environnements RUNNING pour lever des alertes runtime.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class DeploymentRuntimeAlertScheduler {

    private final DeploymentRuntimeAlertService alertService;

    @Scheduled(fixedDelayString = "${deployment.alerts.scan-interval-ms:120000}")
    public void scan() {
        try {
            alertService.scanRunningDeployments();
        } catch (Exception e) {
            log.warn("Échec scan alertes runtime: {}", e.getMessage());
        }
    }
}
