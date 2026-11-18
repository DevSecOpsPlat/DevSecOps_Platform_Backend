package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.QualityGateSnapshot;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.QualityGateSnapshotRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Résumé « post-déploiement » d'une application : DAST (ZAP) et smoke test, lus à partir du
 * DÉPLOIEMENT et non de l'environnement d'un service.
 *
 * <p>Pourquoi : dans un déploiement d'application, ZAP analyse l'adresse publique de toute
 * l'application, et seul le premier service porte l'environnement. Lire le DAST « par
 * environnement de service » laissait les autres services sans résultat (« Aucun déploiement
 * DAST pour ce service ») et perdait le résultat après la reconstruction d'un service.</p>
 */
@Service
@RequiredArgsConstructor
public class PostDeployService {

    private static final Set<String> JOB_RUNNING = Set.of(
            "running", "pending", "created", "preparing", "waiting_for_resource", "scheduled");

    private final ManagedApplicationRepository appRepository;
    private final AppDeploymentRepository deploymentRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final QualityGateSnapshotRepository snapshotRepository;
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public Map<String, Object> summary(UUID appId, UUID deploymentId) {
        ManagedApplication app = appRepository.findByIdAndCreatedBy(appId, currentUser())
                .orElseThrow(() -> new AppValidationException("Application introuvable ou accès refusé."));
        List<AppDeployment> all = deploymentRepository.findByApplication_IdOrderByCreatedAtDesc(appId);

        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> list = new ArrayList<>();
        for (AppDeployment d : all.subList(0, Math.min(15, all.size()))) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", d.getId());
            row.put("namespace", d.getNamespace());
            row.put("status", d.getStatus() != null ? d.getStatus().name() : null);
            row.put("createdAt", d.getCreatedAt());
            row.put("deployedAt", d.getDeployedAt());
            list.add(row);
        }
        out.put("deployments", list);

        List<Map<String, Object>> services = new ArrayList<>();
        for (AppService s : app.getServices()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", s.getId());
            row.put("name", s.getName());
            row.put("role", s.getRole() != null ? s.getRole().name() : null);
            services.add(row);
        }
        out.put("services", services);

        AppDeployment deployment = deploymentId != null
                ? all.stream().filter(d -> deploymentId.equals(d.getId())).findFirst().orElse(null)
                : all.stream().filter(d -> d.getStatus() == AppDeploymentStatus.RUNNING).findFirst()
                        .orElse(all.isEmpty() ? null : all.get(0));
        if (deployment == null) {
            out.put("deploymentId", null);
            return out;
        }
        out.put("deploymentId", deployment.getId());
        out.put("namespace", deployment.getNamespace());
        out.put("status", deployment.getStatus() != null ? deployment.getStatus().name() : null);
        out.put("deployedAt", deployment.getDeployedAt());
        out.put("createdAt", deployment.getCreatedAt());

        Map<String, Object> state = deployment.getServicesState() != null ? deployment.getServicesState() : Map.of();
        out.put("smokeTest", state.get("smokeTest"));
        out.put("appUrl", primaryUrl(state));
        out.put("dast", resolveDast(deployment));
        return out;
    }

    /** Adresse publique de l'application (service FRONTEND en priorité). */
    @SuppressWarnings("unchecked")
    private static String primaryUrl(Map<String, Object> state) {
        if (!(state.get("services") instanceof Map<?, ?> services)) {
            return null;
        }
        String any = null;
        for (Object v : services.values()) {
            if (!(v instanceof Map<?, ?> m)) continue;
            Object url = m.get("externalUrl");
            if (url == null || String.valueOf(url).isBlank()) continue;
            if ("FRONTEND".equals(String.valueOf(m.get("role")))) {
                return String.valueOf(url);
            }
            if (any == null) any = String.valueOf(url);
        }
        return any;
    }

    /**
     * Dernier résultat ZAP exploitable du déploiement : snapshots des pipelines de ce déploiement
     * (pipeline initial lié à l'environnement + dernier pipeline, ex. reconstruction d'un service).
     * Sans résultat : état du job ZAP du dernier pipeline (en cours, échec, jamais lancé).
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> resolveDast(AppDeployment deployment) {
        Map<String, Object> dast = new LinkedHashMap<>();
        Set<Long> pipelines = new LinkedHashSet<>();
        if (deployment.getGitlabPipelineId() != null) {
            pipelines.add(deployment.getGitlabPipelineId());
        }
        List<QualityGateSnapshot> candidates = new ArrayList<>();
        UUID envId = deployment.getEphemeralEnvironmentId();
        if (envId != null) {
            environmentRepository.findById(envId)
                    .map(EphemeralEnvironment::getPipelineExecution)
                    .map(PipelineExecution::getGitlabPipelineId)
                    .ifPresent(pipelines::add);
            candidates.addAll(snapshotRepository.findAllByEnvironmentIdOrderByCreatedAtDesc(envId));
        }
        if (!pipelines.isEmpty()) {
            candidates.addAll(snapshotRepository.findAllByGitlabPipelineIdIn(pipelines));
        }
        QualityGateSnapshot best = candidates.stream()
                .filter(s -> s.getPayload() != null && s.getPayload().get("metrics") instanceof Map<?, ?> m
                        && Boolean.TRUE.equals(m.get("dastEvaluable")))
                .max(Comparator.comparing(PostDeployService::snapshotTime))
                .orElse(null);

        if (best != null) {
            Map<String, Object> metrics = (Map<String, Object>) best.getPayload().get("metrics");
            int critical = intVal(metrics.get("dastCritical"));
            int high = intVal(metrics.get("dastHigh"));
            int medium = intVal(metrics.get("dastMedium"));
            int low = 0;
            if (best.getPayload().get("toolMetrics") instanceof List<?> tools) {
                for (Object t : tools) {
                    if (t instanceof Map<?, ?> tm && "zap".equals(String.valueOf(tm.get("id")))) {
                        low = intVal(tm.get("low"));
                        critical = Math.max(critical, intVal(tm.get("critical")));
                        high = Math.max(high, intVal(tm.get("high")));
                        medium = Math.max(medium, intVal(tm.get("medium")));
                    }
                }
            }
            dast.put("state", critical + high + medium + low == 0 ? "ok" : "findings");
            dast.put("critical", critical);
            dast.put("high", high);
            dast.put("medium", medium);
            dast.put("low", low);
            dast.put("pipelineId", best.getGitlabPipelineId());
            dast.put("evaluatedAt", snapshotTime(best));
            // Les findings ZAP sont importés dans DefectDojo sous le service qui a reçu le résultat.
            dast.put("findingsServiceId", best.getApplicationId());
            dast.put("branch", best.getBranch());
            return dast;
        }

        Long latest = deployment.getGitlabPipelineId();
        dast.put("pipelineId", latest);
        String zapStatus = latest != null ? zapJobStatus(latest) : null;
        if (zapStatus == null || zapStatus.equals("skipped") || zapStatus.equals("manual")) {
            dast.put("state", "never");
        } else if (JOB_RUNNING.contains(zapStatus)) {
            dast.put("state", "running");
        } else if (zapStatus.equals("success")) {
            // Job terminé mais aucun résultat exploitable reçu (import / ingestion en échec).
            dast.put("state", "unavailable");
        } else {
            dast.put("state", "failed");
        }
        return dast;
    }

    @SuppressWarnings("unchecked")
    private String zapJobStatus(Long pipelineId) {
        for (PipelineExecution pe : pipelineExecutionRepository.findAllByGitlabPipelineIdOrderByCreatedAtAsc(pipelineId)) {
            Map<String, Object> stages = pe.getStagesJson();
            if (stages == null || !(stages.get("jobs") instanceof List<?> jobs)) continue;
            for (Object j : jobs) {
                if (j instanceof Map<?, ?> job && String.valueOf(job.get("name")).toLowerCase().contains("zap")) {
                    return String.valueOf(job.get("status")).toLowerCase();
                }
            }
        }
        return null;
    }

    private static Instant snapshotTime(QualityGateSnapshot s) {
        if (s.getEvaluatedAt() != null) return s.getEvaluatedAt();
        return s.getCreatedAt() != null ? s.getCreatedAt() : Instant.EPOCH;
    }

    private static int intVal(Object o) {
        if (o instanceof Number n) return n.intValue();
        try {
            return o == null ? 0 : Integer.parseInt(String.valueOf(o));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new AppValidationException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new AppValidationException("Utilisateur non trouvé."));
    }
}
