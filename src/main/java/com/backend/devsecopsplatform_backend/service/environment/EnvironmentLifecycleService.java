package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/**
 * Propriétaire unique des transitions d'état des environnements éphémères.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EnvironmentLifecycleService {

  public static final Set<EnvironmentStatus> ALIVE = EnumSet.of(
      EnvironmentStatus.PENDING,
      EnvironmentStatus.BUILDING,
      EnvironmentStatus.RUNNING,
      EnvironmentStatus.DEGRADED
  );

  public static final Set<EnvironmentStatus> TTL_IMMUNE = EnumSet.of(
      EnvironmentStatus.DESTROYED,
      EnvironmentStatus.EXPIRED,
      EnvironmentStatus.FAILED
  );

  public static final Set<EnvironmentStatus> CLEANUP_CANDIDATES = EnumSet.of(
      EnvironmentStatus.EXPIRED,
      EnvironmentStatus.FAILED
  );

  private final EphemeralEnvironmentRepository environmentRepository;

  /** URL publique uniquement si l'environnement sert du trafic (RUNNING). */
  public static String publicUrlOrNull(EphemeralEnvironment e) {
    if (e == null || e.getStatus() != EnvironmentStatus.RUNNING) {
      return null;
    }
    String url = e.getUrl();
    if (url == null || url.isBlank()) {
      return null;
    }
    return url.trim();
  }

  @Transactional
  public void onBuilding(UUID environmentId) {
    transition(environmentId, EnvironmentStatus.BUILDING, null, false);
  }

  @Transactional
  public void onReady(UUID environmentId, String publicUrl) {
    EphemeralEnvironment env = load(environmentId);
    EnvironmentStatus from = env.getStatus();
    if (from != EnvironmentStatus.PENDING
        && from != EnvironmentStatus.BUILDING
        && from != EnvironmentStatus.DEGRADED) {
      log.debug("onReady ignoré pour env {} (état {})", environmentId, from);
      return;
    }
    if (publicUrl != null && !publicUrl.isBlank()) {
      env.setUrl(publicUrl.trim());
    }
    if (env.getReadyAt() == null) {
      env.setReadyAt(LocalDateTime.now());
    }
    applyTransition(env, EnvironmentStatus.RUNNING, null, false);
    environmentRepository.save(env);
    log.info("✅ Env {} prêt → RUNNING", environmentId);
  }

  @Transactional
  public void onDegraded(UUID environmentId, String reason) {
    transition(environmentId, EnvironmentStatus.DEGRADED, reason, false);
  }

  /**
   * Pipeline CI en échec : ne fait échouer l'environnement que s'il n'a jamais démarré.
   */
  @Transactional
  public void onPipelineFailed(UUID environmentId, String reason) {
    EphemeralEnvironment env = load(environmentId);
    EnvironmentStatus from = env.getStatus();
    if (from != EnvironmentStatus.PENDING && from != EnvironmentStatus.BUILDING) {
      log.debug("Pipeline échoué mais env {} reste {} (monotone)", environmentId, from);
      return;
    }
    applyTransition(env, EnvironmentStatus.FAILED, reason, true);
    environmentRepository.save(env);
    log.info("❌ Env {} → FAILED ({})", environmentId, reason);
  }

  @Transactional
  public void onExpired(UUID environmentId, String reason) {
    transition(environmentId, EnvironmentStatus.EXPIRED, reason, true);
  }

  @Transactional
  public void onDestroyed(UUID environmentId, String reason) {
    EphemeralEnvironment env = load(environmentId);
    if (env.getStatus() == EnvironmentStatus.DESTROYED) {
      return;
    }
    applyTransition(env, EnvironmentStatus.DESTROYED, reason, true);
    env.setDestroyedAt(LocalDateTime.now());
    environmentRepository.save(env);
    log.info("🗑️ Env {} → DESTROYED ({})", environmentId, reason);
  }

  private void transition(UUID environmentId, EnvironmentStatus to, String reason, boolean terminated) {
    EphemeralEnvironment env = load(environmentId);
    if (!isLegalTransition(env.getStatus(), to)) {
      log.warn("Transition refusée {} → {} pour env {}", env.getStatus(), to, environmentId);
      return;
    }
    applyTransition(env, to, reason, terminated);
    environmentRepository.save(env);
  }

  private void applyTransition(
      EphemeralEnvironment env,
      EnvironmentStatus to,
      String reason,
      boolean terminated
  ) {
    env.setStatus(to);
    if (reason != null && !reason.isBlank()) {
      env.setStatusReason(reason);
    }
    if (terminated && env.getTerminatedAt() == null) {
      env.setTerminatedAt(LocalDateTime.now());
    }
  }

  private boolean isLegalTransition(EnvironmentStatus from, EnvironmentStatus to) {
    if (from == to) {
      return true;
    }
    return switch (from) {
      case PENDING -> to == EnvironmentStatus.BUILDING
          || to == EnvironmentStatus.RUNNING
          || to == EnvironmentStatus.FAILED
          || to == EnvironmentStatus.EXPIRED;
      case BUILDING -> to == EnvironmentStatus.RUNNING
          || to == EnvironmentStatus.FAILED
          || to == EnvironmentStatus.DEGRADED
          || to == EnvironmentStatus.EXPIRED;
      case RUNNING -> to == EnvironmentStatus.DEGRADED
          || to == EnvironmentStatus.EXPIRED;
      case DEGRADED -> to == EnvironmentStatus.RUNNING
          || to == EnvironmentStatus.EXPIRED;
      case FAILED, EXPIRED -> to == EnvironmentStatus.DESTROYED;
      case DESTROYED -> false;
    };
  }

  private EphemeralEnvironment load(UUID environmentId) {
    return environmentRepository.findById(environmentId)
        .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable: " + environmentId));
  }
}
