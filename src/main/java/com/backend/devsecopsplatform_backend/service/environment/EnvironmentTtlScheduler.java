package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EnvironmentTtlScheduler {

    private final EphemeralEnvironmentRepository environmentRepository;

    /**
     * Vérifie périodiquement les environnements qui ont dépassé leur TTL
     * et les marque comme EXPIRED.
     */
    @Scheduled(fixedDelayString = "${env.ttl-check-interval-ms:60000}")
    @Transactional
    public void markExpiredEnvironments() {
        LocalDateTime now = LocalDateTime.now();

        List<EphemeralEnvironment> candidates = environmentRepository
                .findByStatusNotInAndExpiresAtBefore(
                        EnumSet.of(EnvironmentStatus.DESTROYED, EnvironmentStatus.EXPIRED),
                        now
                );

        if (candidates.isEmpty()) {
            return;
        }

        for (EphemeralEnvironment env : candidates) {
            log.info("⏰ Environnement {} (id={}) a dépassé son TTL (expiresAt={}) → EXPIRED",
                    env.getEnvironmentName(), env.getId(), env.getExpiresAt());
            env.setStatus(EnvironmentStatus.EXPIRED);
        }

        environmentRepository.saveAll(candidates);
    }
}

