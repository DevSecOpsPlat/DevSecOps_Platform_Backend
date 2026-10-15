package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Rafraîchit en arrière-plan le cache du commit HEAD (obsolescence d'un service scanné/déployé),
 * pour que {@link ManagedAppScanService#securityPosture} n'ait jamais à faire un appel GitHub live
 * (jusqu'à 10s par service, en boucle séquentielle) dans le chemin d'une requête HTTP -- l'indicateur
 * "obsolète" reste correct à quelques minutes près, un compromis acceptable pour un badge informatif,
 * pas un hard gate.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class HeadCacheRefreshScheduler {

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final ManagedAppScanService managedAppScanService;

    @Value("${scan.posture.head-check-ttl-ms:300000}")
    private long headCheckTtlMs;

    @Scheduled(fixedDelayString = "${scan.posture.head-check-refresh-ms:180000}")
    public void refresh() {
        try {
            LocalDateTime cutoff = LocalDateTime.now().minus(Duration.ofMillis(Math.max(headCheckTtlMs, 30_000)));
            List<PipelineExecution> stale = pipelineExecutionRepository
                    .findByHeadCheckedAtIsNullOrHeadCheckedAtBefore(cutoff, PageRequest.of(0, 200));
            if (stale.isEmpty()) {
                return;
            }
            log.debug("HeadCacheRefreshScheduler : {} exécution(s) à rafraîchir", stale.size());
            managedAppScanService.refreshHeadCacheIfStale(stale);
        } catch (Exception e) {
            log.warn("Échec rafraîchissement cache HEAD: {}", e.getMessage());
        }
    }
}
