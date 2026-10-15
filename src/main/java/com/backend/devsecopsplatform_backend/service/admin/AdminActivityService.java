package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.UserActivityLog;
import com.backend.devsecopsplatform_backend.entity.UserActivityType;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AlertRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserActivityLogRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminActivityEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Fil d'activité admin fusionné (pipelines + alertes + activité de compte), sans nouvelle entité —
 * cf. docs/audit-dashboard-admin.md et le plan de refonte du dashboard admin (Phase 1, backend
 * §2). Alimente la timeline de la Vue d'ensemble (globale) et celle des pages détail
 * Application/Environnement (filtrées).
 *
 * Les trois sources sont fusionnées EN MÉMOIRE, dans le même esprit que {@code AlertService}
 * (qui agrège déjà les alertes en mémoire plutôt qu'en SQL) : le volume reste faible (fenêtre
 * bornée à quelques centaines de lignes par source), donc pas besoin d'une requête SQL unifiée.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminActivityService {

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final AlertRepository alertRepository;
    private final UserActivityLogRepository userActivityLogRepository;
    private final ManagedApplicationRepository managedApplicationRepository;
    private final ObjectMapper objectMapper;

    @Transactional(readOnly = true)
    public List<AdminActivityEvent> getActivity(
            int limit,
            UUID applicationId,
            UUID environmentId,
            UUID userId,
            LocalDateTime from,
            LocalDateTime to
    ) {
        int safeLimit = limit <= 0 ? 30 : Math.min(limit, 200);
        // Fenêtre plus large que le résultat final : la fusion + le filtrage retirent des lignes,
        // et une fenêtre trop juste renverrait moins que `limit` même quand ça existe en base.
        int fetchWindow = Math.min(Math.max(safeLimit * 4, 120), 400);

        List<AdminActivityEvent> events = new ArrayList<>();
        events.addAll(pipelineEvents(fetchWindow, applicationId, environmentId, userId, from, to));

        // Les alertes n'ont pas d'environmentId propre (seul le namespace est connu, via
        // detailsJson) : la page détail Environnement obtient déjà ses événements K8s par un autre
        // appel (getNamespaceMonitoring().alerts) — ici on exclut simplement les alertes quand un
        // filtre environnementId est demandé plutôt que d'implémenter une correspondance approximative.
        if (environmentId == null) {
            events.addAll(alertEvents(fetchWindow, applicationId, userId, from, to));
        }

        // Les événements de compte n'ont aucun contexte application/environnement.
        if (applicationId == null && environmentId == null) {
            events.addAll(accountEvents(fetchWindow, userId, from, to));
        }

        return events.stream()
                .sorted(Comparator.comparing(AdminActivityEvent::occurredAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(safeLimit)
                .toList();
    }

    private List<AdminActivityEvent> pipelineEvents(
            int fetchWindow, UUID applicationId, UUID environmentId, UUID userId,
            LocalDateTime from, LocalDateTime to
    ) {
        List<PipelineExecution> raw = pipelineExecutionRepository
                .findAllWithDetailsOrderByCreatedAtDesc(PageRequest.of(0, fetchWindow));

        List<AdminActivityEvent> out = new ArrayList<>();
        for (PipelineExecution pe : raw) {
            if (pe.getCreatedAt() == null) {
                continue;
            }
            if (from != null && pe.getCreatedAt().isBefore(from)) {
                continue;
            }
            if (to != null && pe.getCreatedAt().isAfter(to)) {
                continue;
            }
            AppService service = pe.getAppService();
            if (service == null) {
                continue;
            }
            User owner = service.getCreatedBy();
            if (userId != null && (owner == null || !userId.equals(owner.getId()))) {
                continue;
            }
            ManagedApplication managedApp = service.getManagedApplication();
            UUID resolvedAppId = managedApp != null ? managedApp.getId() : service.getId();
            String resolvedAppName = managedApp != null ? managedApp.getName() : service.getName();
            if (applicationId != null && !applicationId.equals(resolvedAppId)) {
                continue;
            }
            EphemeralEnvironment env = pe.getEnvironment();
            if (environmentId != null && (env == null || !environmentId.equals(env.getId()))) {
                continue;
            }

            String branch = pe.getGitBranch() != null ? pe.getGitBranch() : "main";
            String shortSha = pe.getCommitSha() != null && pe.getCommitSha().length() >= 7
                    ? pe.getCommitSha().substring(0, 7) : pe.getCommitSha();
            String message = "Service " + service.getName() + ", branche " + branch
                    + (shortSha != null ? " (" + shortSha + ")" : "");

            out.add(new AdminActivityEvent(
                    "pipeline-" + pe.getId(),
                    "PIPELINE",
                    pe.getStatus() != null ? pe.getStatus().name() : PipelineStatus.PENDING.name(),
                    message,
                    owner != null ? owner.getUsername() : null,
                    resolvedAppId,
                    resolvedAppName,
                    env != null ? env.getId() : null,
                    env != null ? env.getEnvironmentName() : null,
                    pipelineSeverity(pe.getStatus()),
                    pe.getCreatedAt()
            ));
        }
        return out;
    }

    private List<AdminActivityEvent> alertEvents(
            int fetchWindow, UUID applicationId, UUID userId, LocalDateTime from, LocalDateTime to
    ) {
        List<Alert> raw = alertRepository.findByDeletedFalseOrderByCreatedAtDesc(PageRequest.of(0, fetchWindow));

        // Résolution des noms d'application en une seule passe (évite un findById par alerte).
        Set<UUID> appIds = new HashSet<>();
        Map<Alert, UUID> alertAppId = new HashMap<>();
        for (Alert a : raw) {
            UUID appId = extractApplicationId(a);
            if (appId != null) {
                alertAppId.put(a, appId);
                appIds.add(appId);
            }
        }
        Map<UUID, String> appNames = new HashMap<>();
        if (!appIds.isEmpty()) {
            for (ManagedApplication app : managedApplicationRepository.findAllById(appIds)) {
                appNames.put(app.getId(), app.getName());
            }
        }

        List<AdminActivityEvent> out = new ArrayList<>();
        for (Alert a : raw) {
            if (a.getCreatedAt() == null) {
                continue;
            }
            if (from != null && a.getCreatedAt().isBefore(from)) {
                continue;
            }
            if (to != null && a.getCreatedAt().isAfter(to)) {
                continue;
            }
            if (userId != null && !userId.equals(a.getRelatedUserId())) {
                continue;
            }
            UUID appId = alertAppId.get(a);
            if (applicationId != null && !applicationId.equals(appId)) {
                continue;
            }

            out.add(new AdminActivityEvent(
                    "alert-" + a.getId(),
                    "ALERT",
                    a.getType() != null ? a.getType().name() : "UNKNOWN",
                    a.getMessage(),
                    a.getRelatedUsername(),
                    appId,
                    appId != null ? appNames.get(appId) : null,
                    null,
                    null,
                    alertSeverity(a.getType()),
                    a.getCreatedAt()
            ));
        }
        return out;
    }

    private List<AdminActivityEvent> accountEvents(
            int fetchWindow, UUID userId, LocalDateTime from, LocalDateTime to
    ) {
        List<UserActivityLog> raw = userActivityLogRepository
                .findAllWithUserOrderByCreatedAtDesc(PageRequest.of(0, fetchWindow));

        List<AdminActivityEvent> out = new ArrayList<>();
        for (UserActivityLog log : raw) {
            if (log.getCreatedAt() == null) {
                continue;
            }
            if (from != null && log.getCreatedAt().isBefore(from)) {
                continue;
            }
            if (to != null && log.getCreatedAt().isAfter(to)) {
                continue;
            }
            User target = log.getUser();
            if (userId != null && (target == null || !userId.equals(target.getId()))) {
                continue;
            }

            out.add(new AdminActivityEvent(
                    "account-" + log.getId(),
                    "ACCOUNT",
                    log.getAction() != null ? log.getAction().name() : "UNKNOWN",
                    log.getDetail(),
                    log.getPerformedBy(),
                    null,
                    null,
                    null,
                    null,
                    log.getAction() == UserActivityType.ACCOUNT_DISABLED ? "WARNING" : "INFO",
                    log.getCreatedAt()
            ));
        }
        return out;
    }

    private UUID extractApplicationId(Alert a) {
        String details = a.getDetailsJson();
        if (details == null || details.isBlank()) {
            return null;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = objectMapper.readValue(details, Map.class);
            Object raw = map.get("applicationId");
            return raw != null ? UUID.fromString(String.valueOf(raw)) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String pipelineSeverity(PipelineStatus status) {
        if (status == PipelineStatus.FAILED) {
            return "CRITICAL";
        }
        if (status == PipelineStatus.CANCELED) {
            return "WARNING";
        }
        return "INFO";
    }

    private static final Set<String> CRITICAL_ALERT_TYPES = Set.of(
            "DEPLOYMENT_CRASH_LOOP", "DEPLOYMENT_OOM", "DEPLOYMENT_POD_FAILED", "DEPLOYMENT_HEALTH_FAILED",
            "BRUTE_FORCE_DETECTED", "HONEYPOT_TRIGGERED", "MALICIOUS_PAYLOAD", "UNAUTHORIZED_ACCESS",
            "IP_BLOCKED", "ACCOUNT_LOCKED"
    );
    private static final Set<String> WARNING_ALERT_TYPES = Set.of(
            "DEPLOYMENT_K8S_WARNING", "RATE_LIMIT_EXCEEDED", "SUSPICIOUS_REQUEST", "SUSPICIOUS_USER_AGENT",
            "LOGIN_FAILED", "FAILED_LOGIN_REPEATED"
    );

    private String alertSeverity(com.backend.devsecopsplatform_backend.entity.AlertType type) {
        if (type == null) {
            return "INFO";
        }
        String name = type.name();
        if (CRITICAL_ALERT_TYPES.contains(name)) {
            return "CRITICAL";
        }
        if (WARNING_ALERT_TYPES.contains(name)) {
            return "WARNING";
        }
        return "INFO";
    }
}
