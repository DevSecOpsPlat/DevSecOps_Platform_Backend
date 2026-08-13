package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AlertRepository;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.service.security.EmailService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Détecte CrashLoop / OOM / Failed / health KO / Warning K8s (FailedCreate…)
 * sur les déploiements RUNNING, persiste une alerte (dédup) et notifie le propriétaire.
 */
@Service
@Slf4j
public class DeploymentRuntimeAlertService {

    private static final List<AlertType> DEPLOYMENT_ALERT_TYPES = List.of(
            AlertType.DEPLOYMENT_CRASH_LOOP,
            AlertType.DEPLOYMENT_OOM,
            AlertType.DEPLOYMENT_POD_FAILED,
            AlertType.DEPLOYMENT_HEALTH_FAILED,
            AlertType.DEPLOYMENT_K8S_WARNING
    );

    private final AppDeploymentRepository deploymentRepository;
    private final AlertRepository alertRepository;
    private final ApplicationManagementService applicationManagementService;
    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    @Value("${deployment.alerts.enabled:true}")
    private boolean alertsEnabled;

    @Value("${deployment.alerts.dedup-minutes:30}")
    private int dedupMinutes;

    @Value("${deployment.alerts.email-enabled:true}")
    private boolean emailEnabled;

    public DeploymentRuntimeAlertService(
            AppDeploymentRepository deploymentRepository,
            AlertRepository alertRepository,
            @Lazy ApplicationManagementService applicationManagementService,
            EmailService emailService,
            ObjectMapper objectMapper
    ) {
        this.deploymentRepository = deploymentRepository;
        this.alertRepository = alertRepository;
        this.applicationManagementService = applicationManagementService;
        this.emailService = emailService;
        this.objectMapper = objectMapper;
    }

    /** Pas de @Transactional sur toute la boucle : monitoring K8s/HTTP ne doit pas bloquer Hikari. */
    public void scanRunningDeployments() {
        if (!alertsEnabled) {
            return;
        }
        List<AppDeployment> running;
        try {
            // EntityGraph charge application + createdBy (voir repository)
            running = deploymentRepository.findByStatus(AppDeploymentStatus.RUNNING);
        } catch (Exception e) {
            log.warn("Scan alertes runtime: impossible de lister les déploiements RUNNING — {}", e.getMessage());
            return;
        }
        if (running.isEmpty()) {
            return;
        }
        int raised = 0;
        for (AppDeployment deployment : running) {
            try {
                raised += scanOne(deployment);
            } catch (Exception e) {
                log.debug("Scan alertes deployment {}: {}", deployment.getId(), e.getMessage());
            }
        }
        if (raised > 0) {
            log.info("Alertes runtime: {} nouvelle(s) sur {} déploiement(s) RUNNING", raised, running.size());
        }
    }

    private int scanOne(AppDeployment deployment) {
        ManagedApplication app = deployment.getApplication();
        if (app == null || app.getId() == null) {
            return 0;
        }
        Map<String, Object> mon;
        try {
            mon = applicationManagementService.getDeploymentMonitoring(app.getId(), deployment.getId());
        } catch (Exception e) {
            return 0;
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> alerts = mon.get("alerts") instanceof List<?> list
                ? (List<Map<String, Object>>) list
                : List.of();

        User owner = app.getCreatedBy();
        int count = 0;
        for (Map<String, Object> a : alerts) {
            String severity = String.valueOf(a.getOrDefault("severity", ""));
            String message = String.valueOf(a.getOrDefault("message", "")).trim();
            if (message.isBlank()) {
                continue;
            }
            AlertType type = mapType(severity, message);
            if (type == null) {
                continue;
            }
            String workload = a.get("workload") != null ? String.valueOf(a.get("workload")) : null;
            String pod = a.get("pod") != null ? String.valueOf(a.get("pod")) : null;
            String reason = a.get("reason") != null ? String.valueOf(a.get("reason")) : null;
            String fingerprintMsg = buildMessage(app, deployment, workload, pod, message);
            if (raiseIfNew(type, fingerprintMsg, owner, app, deployment, workload, pod, severity, reason)) {
                count++;
            }
        }
        return count;
    }

    private AlertType mapType(String severity, String message) {
        String m = message.toLowerCase();
        if (m.contains("oomkilled") || m.contains("mémoire insuffisante") || m.contains("memoire insuffisante")) {
            return AlertType.DEPLOYMENT_OOM;
        }
        if (m.contains("crashloop") || m.contains("imagepull") || m.contains("errimagepull")
                || m.contains("panne de démarrage") || m.contains("panne de demarrage")) {
            return AlertType.DEPLOYMENT_CRASH_LOOP;
        }
        if (m.contains("pod failed") || "Failed".equalsIgnoreCase(message)) {
            return AlertType.DEPLOYMENT_POD_FAILED;
        }
        if (m.contains("health url") || m.startsWith("health ") || m.contains("ingress non appliqué")
                || m.contains("ingress non applique") || m.contains("healthcheckfailed")) {
            return AlertType.DEPLOYMENT_HEALTH_FAILED;
        }
        // Warnings / événements K8s (FailedCreate, FailedScheduling, Unhealthy, BackOff…)
        if (m.contains("failedcreate") || m.contains("failedscheduling") || m.contains("failedmount")
                || m.contains("failedattach") || m.contains("unhealthy") || m.contains("backoff")
                || m.contains("evicted") || m.contains("probe") || m.contains("networknotready")
                || m.contains("exceededgraceperiod") || m.contains("inspectfailed")
                || m.contains("failedkill") || m.contains("sandbox")) {
            return AlertType.DEPLOYMENT_K8S_WARNING;
        }
        // errors génériques
        if ("error".equalsIgnoreCase(severity)) {
            return AlertType.DEPLOYMENT_POD_FAILED;
        }
        // Autres warns live (Pending, not Ready, restarts, warning events génériques)
        if ("warn".equalsIgnoreCase(severity)) {
            return AlertType.DEPLOYMENT_K8S_WARNING;
        }
        return null;
    }

    private String buildMessage(
            ManagedApplication app,
            AppDeployment deployment,
            String workload,
            String pod,
            String raw
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(app.getSlug() != null ? app.getSlug() : app.getName()).append("]");
        if (deployment.getNamespace() != null) {
            sb.append(" ns=").append(deployment.getNamespace());
        }
        if (workload != null && !workload.isBlank()) {
            sb.append(" svc=").append(workload);
        }
        if (pod != null && !pod.isBlank()) {
            sb.append(" pod=").append(pod);
        }
        sb.append(" — ").append(raw);
        String out = sb.toString();
        return out.length() > 1000 ? out.substring(0, 997) + "…" : out;
    }

    private boolean raiseIfNew(
            AlertType type,
            String message,
            User owner,
            ManagedApplication app,
            AppDeployment deployment,
            String workload,
            String pod,
            String severity,
            String reason
    ) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(Math.max(5, dedupMinutes));
        if (alertRepository.existsByDeletedFalseAndTypeAndMessageAndCreatedAtAfter(type, message, since)) {
            return false;
        }

        Alert alert = new Alert();
        alert.setType(type);
        alert.setMessage(message);
        alert.setStatus(AlertStatus.NON_LUE);
        if (owner != null) {
            alert.setRelatedUserId(owner.getId());
            alert.setRelatedUsername(owner.getUsername());
        }
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("applicationId", app.getId().toString());
            details.put("deploymentId", deployment.getId().toString());
            details.put("namespace", deployment.getNamespace());
            details.put("workload", workload);
            details.put("pod", pod);
            details.put("severity", severity);
            if (reason != null && !reason.isBlank()) {
                details.put("reason", reason);
            }
            alert.setDetailsJson(objectMapper.writeValueAsString(details));
        } catch (Exception ignored) {
            // details optionnels
        }
        alertRepository.save(alert);

        if (emailEnabled && owner != null && owner.getEmail() != null) {
            String subject = "[EnviroTest] Alerte " + type.name() + " — " + app.getName();
            String body = """
                    Bonjour %s,

                    Une alerte a été détectée sur votre application managée.

                    Application : %s (%s)
                    Namespace   : %s
                    Type        : %s
                    Détail      : %s

                    Ouvrez la fiche application → onglet Alertes / Monitoring pour diagnostiquer.

                    — EnviroTest
                    """.formatted(
                    owner.getUsername(),
                    app.getName(),
                    app.getSlug(),
                    deployment.getNamespace(),
                    type.name(),
                    message
            );
            try {
                emailService.sendPlainText(owner.getEmail(), subject, body);
            } catch (Exception e) {
                log.warn("E-mail alerte runtime non envoyé: {}", e.getMessage());
            }
        }
        return true;
    }

    /**
     * Alertes live (monitoring) + historiques persistées liées à ce déploiement (24 h).
     * Monitoring K8s/HTTP hors transaction ; lecture historique en TX courte.
     */
    public Map<String, Object> listForDeployment(ManagedApplication app, AppDeployment deployment) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> live = new ArrayList<>();
        try {
            Map<String, Object> mon = applicationManagementService.getDeploymentMonitoring(
                    app.getId(), deployment.getId());
            if (mon.get("alerts") instanceof List<?> list) {
                for (Object o : list) {
                    if (o instanceof Map<?, ?> m) {
                        Map<String, Object> row = new LinkedHashMap<>();
                        m.forEach((k, v) -> row.put(String.valueOf(k), v));
                        row.put("source", "live");
                        live.add(row);
                    }
                }
            }
            out.put("health", mon.get("health"));
            out.put("summary", mon.get("summary"));
            out.put("appUrl", mon.get("appUrl"));
            out.put("events", mon.get("events"));
        } catch (Exception e) {
            out.put("liveError", e.getMessage());
        }
        out.put("live", live);

        LocalDateTime since = LocalDateTime.now().minusHours(24);
        List<Alert> persisted = alertRepository
                .findByDeletedFalseAndTypeInAndCreatedAtAfterOrderByCreatedAtDesc(DEPLOYMENT_ALERT_TYPES, since);
        String depId = deployment.getId().toString();
        String ns = deployment.getNamespace();
        List<Map<String, Object>> history = new ArrayList<>();
        for (Alert a : persisted) {
            if (!belongsToDeployment(a, depId, ns, app.getId())) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", a.getId());
            row.put("type", a.getType().name());
            row.put("message", a.getMessage());
            row.put("status", a.getStatus().name());
            row.put("createdAt", a.getCreatedAt() != null ? a.getCreatedAt().toString() : null);
            row.put("source", "history");
            row.put("severity", severityFromType(a.getType()));
            row.put("kind", kindFromType(a.getType(), a.getMessage()));
            enrichHistoryFromDetails(row, a.getDetailsJson());
            if (row.get("reason") == null) {
                row.put("reason", reasonFromType(a.getType(), a.getMessage()));
            }
            history.add(row);
        }
        out.put("history", history);
        out.put("liveCount", live.size());
        out.put("historyCount", history.size());
        return out;
    }

    private void enrichHistoryFromDetails(Map<String, Object> row, String detailsJson) {
        if (detailsJson == null || detailsJson.isBlank()) {
            return;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = objectMapper.readValue(detailsJson, Map.class);
            if (map.get("reason") != null) {
                row.put("reason", String.valueOf(map.get("reason")));
            }
            if (map.get("workload") != null) {
                row.put("workload", String.valueOf(map.get("workload")));
            }
            if (map.get("pod") != null) {
                row.put("pod", String.valueOf(map.get("pod")));
            }
            if (map.get("severity") != null) {
                row.put("severity", String.valueOf(map.get("severity")));
            }
        } catch (Exception ignored) {
            // details optionnels
        }
    }

    private static String severityFromType(AlertType type) {
        return switch (type) {
            case DEPLOYMENT_CRASH_LOOP, DEPLOYMENT_OOM, DEPLOYMENT_POD_FAILED -> "error";
            default -> "warn";
        };
    }

    private static String kindFromType(AlertType type, String message) {
        if (type == AlertType.DEPLOYMENT_HEALTH_FAILED) {
            return "health";
        }
        if (type == AlertType.DEPLOYMENT_K8S_WARNING) {
            String m = message != null ? message.toLowerCase() : "";
            if (m.contains("health url") || m.contains("ingress")) {
                return "health";
            }
            if (m.contains("pending") || m.contains("not ready") || m.contains("restarts")
                    || m.contains("crashloop") || m.contains("oom") || m.contains("imagepull")
                    || m.contains("pod failed")) {
                return "pod";
            }
            return "k8s-event";
        }
        return "pod";
    }

    private static String reasonFromType(AlertType type, String message) {
        return switch (type) {
            case DEPLOYMENT_CRASH_LOOP -> extractReasonHint(message, "CrashLoopBackOff");
            case DEPLOYMENT_OOM -> "OOMKilled";
            case DEPLOYMENT_POD_FAILED -> "PodFailed";
            case DEPLOYMENT_HEALTH_FAILED -> "HealthCheckFailed";
            case DEPLOYMENT_K8S_WARNING -> extractReasonHint(message, "K8sWarning");
            default -> type.name();
        };
    }

    private static String extractReasonHint(String message, String fallback) {
        if (message == null || message.isBlank()) {
            return fallback;
        }
        int dash = message.indexOf(" — ");
        if (dash > 0 && dash < 48) {
            String head = message.substring(0, dash).trim();
            // strip prefix like "[slug] ns=… svc=… pod=…"
            int lastSep = head.lastIndexOf(" — ");
            if (lastSep >= 0) {
                head = head.substring(lastSep + 3).trim();
            }
            // Prefer token after last " — " in full message already handled; try reason at end of prefix block
            String[] parts = message.split(" — ", 2);
            if (parts.length >= 1) {
                String left = parts[0];
                int idx = left.lastIndexOf(' ');
                // e.g. "... pod=x — FailedCreate — msg" already split; for "FailedCreate — msg" left is FailedCreate
                if (!left.contains("=") && left.length() < 48) {
                    return left.trim();
                }
            }
            if (!head.contains("=") && head.length() < 48) {
                return head;
            }
        }
        String lower = message.toLowerCase();
        if (lower.contains("failedcreate")) return "FailedCreate";
        if (lower.contains("failedscheduling")) return "FailedScheduling";
        if (lower.contains("crashloop")) return "CrashLoopBackOff";
        if (lower.contains("imagepull")) return "ImagePullBackOff";
        if (lower.contains("health url")) return "HealthCheckFailed";
        if (lower.contains("ingress")) return "IngressNotApplied";
        return fallback;
    }

    private boolean belongsToDeployment(Alert a, String deploymentId, String namespace, UUID appId) {
        String details = a.getDetailsJson();
        if (details != null && !details.isBlank()) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = objectMapper.readValue(details, Map.class);
                if (deploymentId.equals(String.valueOf(map.get("deploymentId")))) {
                    return true;
                }
                if (appId != null && appId.toString().equals(String.valueOf(map.get("applicationId")))) {
                    return true;
                }
            } catch (Exception ignored) {
                // fallback message
            }
        }
        String msg = a.getMessage() != null ? a.getMessage() : "";
        return namespace != null && msg.contains("ns=" + namespace);
    }
}
