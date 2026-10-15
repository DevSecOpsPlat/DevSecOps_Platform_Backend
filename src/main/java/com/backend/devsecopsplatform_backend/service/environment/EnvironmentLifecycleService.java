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

  /**
   * Statuts exclus du passage TTL → EXPIRED.
   * PENDING/BUILDING : le TTL ne démarre qu'au Ready (expiresAt provisoire à la création).
   */
  public static final Set<EnvironmentStatus> TTL_IMMUNE = EnumSet.of(
      EnvironmentStatus.PENDING,
      EnvironmentStatus.BUILDING,
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

  /**
   * Un déploiement CI vient d'être (re)planifié pour cet environnement -- typiquement un retry
   * GitLab sur un job {@code deploy:trigger-backend} qui avait échoué (timeout d'attente Ready).
   * Contrairement à {@link #onBuilding}, résiste explicitement à un état FAILED/EXPIRED/DESTROYED :
   * un tel retry réutilise le même environnement et le même namespace, et un nouvel apply K8s
   * vient de le repeupler -- il ne doit plus être ramassé par {@code cleanupDeadEnvironments()}
   * (qui balaie les environnements FAILED/EXPIRED sans savoir qu'un apply vient de les repeupler).
   *
   * <p>Bug réel trouvé en direct le 4 septembre 2026 : l'apply K8s réussissait (namespace, données
   * recréés), mais {@code onBuilding()} refusait la transition FAILED → BUILDING (machine à états
   * volontairement monotone pour tout le reste), laissant l'environnement FAILED en base malgré la
   * ressource fraîchement recréée -- le passage TTL suivant (dans les ~2 minutes) détruisait alors
   * le namespace tout juste réappliqué, sans qu'aucune erreur ne soit levée nulle part.</p>
   */
  @Transactional
  public void onRetryScheduled(UUID environmentId) {
    EphemeralEnvironment env = load(environmentId);
    EnvironmentStatus from = env.getStatus();
    if (from == EnvironmentStatus.FAILED
        || from == EnvironmentStatus.EXPIRED
        || from == EnvironmentStatus.DESTROYED) {
      log.warn("onRetryScheduled: env {} était {} — résurrection BUILDING (retry CI)", environmentId, from);
      env.setStatus(EnvironmentStatus.BUILDING);
      env.setStatusReason(null);
      env.setTerminatedAt(null);
      env.setDestroyedAt(null);
      environmentRepository.save(env);
      return;
    }
    transition(environmentId, EnvironmentStatus.BUILDING, null, false);
  }

  @Transactional
  public void onReady(UUID environmentId, String publicUrl) {
    EphemeralEnvironment env = load(environmentId);
    EnvironmentStatus from = env.getStatus();
    // Resusciter si détruit trop tôt alors que le déploiement devient Ready
    if (from == EnvironmentStatus.DESTROYED || from == EnvironmentStatus.EXPIRED) {
      log.warn("onReady: env {} était {} — restauration RUNNING (TTL)", environmentId, from);
      env.setStatus(EnvironmentStatus.PENDING);
      env.setDestroyedAt(null);
      from = EnvironmentStatus.PENDING;
    }
    if (from != EnvironmentStatus.PENDING
        && from != EnvironmentStatus.BUILDING
        && from != EnvironmentStatus.DEGRADED
        && from != EnvironmentStatus.RUNNING) {
      log.debug("onReady ignoré pour env {} (état {})", environmentId, from);
      return;
    }
    if (publicUrl != null && !publicUrl.isBlank()) {
      env.setUrl(publicUrl.trim());
    }
    // TTL démarre au Ready (recalcule même si PrePersist avait posé un expiresAt provisoire)
    if (env.getReadyAt() == null) {
      env.setReadyAt(LocalDateTime.now());
    }
    int ttl = env.getTtlHours() != null && env.getTtlHours() > 0 ? env.getTtlHours() : 4;
    env.setExpiresAt(env.getReadyAt().plusHours(ttl));
    log.info("TTL env {} — prêt à {}, expire à {} ({} h)",
        environmentId, env.getReadyAt(), env.getExpiresAt(), ttl);
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
      // Colonne status_reason = varchar(255) : tronquer pour ne pas masquer l'échec réel.
      env.setStatusReason(reason.length() <= 255 ? reason : reason.substring(0, 252) + "...");
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
