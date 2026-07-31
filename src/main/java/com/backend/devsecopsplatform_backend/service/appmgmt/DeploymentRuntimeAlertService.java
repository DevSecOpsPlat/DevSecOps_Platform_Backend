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
 * Détecte CrashLoop / OOM / Failed / health KO sur les déploiements RUNNING,
 * persiste une alerte (dédup) et notifie le propriétaire par e-mail.
 */
@Service
@Slf4j
public class DeploymentRuntimeAlertService {

    private static final List<AlertType> DEPLOYMENT_ALERT_TYPES = List.of(
            AlertType.DEPLOYMENT_CRASH_LOOP,
            AlertType.DEPLOYMENT_OOM,
            AlertType.DEPLOYMENT_POD_FAILED,
            AlertType.DEPLOYMENT_HEALTH_FAILED
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

    @Transactional
    public void scanRunningDeployments() {
        if (!alertsEnabled) {
            return;
        }
        List<AppDeployment> running;
        try {
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
            String fingerprintMsg = buildMessage(app, deployment, workload, pod, message);
            if (raiseIfNew(type, fingerprintMsg, owner, app, deployment, workload, pod, severity)) {
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
        if (m.contains("health url") || m.startsWith("health ")) {
            return AlertType.DEPLOYMENT_HEALTH_FAILED;
        }
        // errors génériques (hors warn)
        if ("error".equalsIgnoreCase(severity)) {
            return AlertType.DEPLOYMENT_POD_FAILED;
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
            String severity
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
     */
    @Transactional(readOnly = true)
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
            history.add(row);
        }
        out.put("history", history);
        out.put("liveCount", live.size());
        out.put("historyCount", history.size());
        return out;
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
