package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class DeploymentMetricsSamplerScheduler {

    private final DeploymentMetricsSamplerService samplerService;

    @Scheduled(fixedDelayString = "${deployment.metrics.sample-interval-ms:300000}")
    public void sample() {
        try {
            samplerService.sampleRunningDeployments();
        } catch (Exception e) {
            log.warn("Échec échantillonnage métriques: {}", e.getMessage());
        }
    }
}
