package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.entity.application.AppService;
import com.backend.devsecopsplatform_backend.entity.environment.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.pipeline.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.user.User;
import com.backend.devsecopsplatform_backend.entity.deployment.AppDeployment;
import com.backend.devsecopsplatform_backend.repository.deployment.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.repository.application.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.environment.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.pipeline.PipelineExecutionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Environnements « visibles » par un service.
 * <p>
 * Un déploiement d'application gérée ne crée qu'un seul {@link EphemeralEnvironment}, rattaché au
 * service représentant (le premier de la liste). Les autres services du même déploiement n'ont
 * qu'une {@link PipelineExecution} : sans cette résolution, leur page ne voyait jamais le
 * déploiement courant et affichait « Session expirée » sur un ancien environnement.
 */
@Component
@RequiredArgsConstructor
public class ServiceEnvironmentResolver {

    private final EphemeralEnvironmentRepository environmentRepository;
    private final AppServiceRepository appServiceRepository;
    private final AppDeploymentRepository appDeploymentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;

    /**
     * Environnements du service, plus ceux des déploiements de son application gérée auxquels il a
     * participé. Triés du plus récent au plus ancien, sans doublon.
     *
     * @param requestedBy si non nul, ne garde que les environnements demandés par cet utilisateur
     */
    @Transactional(readOnly = true)
    public List<EphemeralEnvironment> environmentsForService(UUID serviceId, User requestedBy) {
        Map<UUID, EphemeralEnvironment> byId = new LinkedHashMap<>();
        for (EphemeralEnvironment e : environmentRepository.findByService_Id(serviceId)) {
            byId.put(e.getId(), e);
        }
        for (EphemeralEnvironment e : managedDeploymentEnvironments(serviceId)) {
            byId.putIfAbsent(e.getId(), e);
        }
        return byId.values().stream()
                .filter(e -> requestedBy == null || isRequestedBy(e, requestedBy))
                .sorted(Comparator.comparing(EphemeralEnvironment::getCreatedAt,
                        Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
    }

    /** Vrai si l'environnement appartient à un autre service de la même application (déploiement d'app). */
    public static boolean isSharedFromApplication(EphemeralEnvironment env, UUID serviceId) {
        return env != null && env.getService() != null && serviceId != null
                && !serviceId.equals(env.getService().getId());
    }

    private static boolean isRequestedBy(EphemeralEnvironment e, User user) {
        return e.getRequestedBy() != null && user.getId() != null
                && user.getId().equals(e.getRequestedBy().getId());
    }

    /**
     * Environnements créés par les déploiements de l'application gérée du service, limités aux
     * déploiements auxquels ce service a pris part (il possède une exécution sur le même pipeline).
     */
    @Transactional(readOnly = true)
    public List<EphemeralEnvironment> managedDeploymentEnvironments(UUID serviceId) {
        AppService svc = appServiceRepository.findById(serviceId).orElse(null);
        if (svc == null || svc.getManagedApplication() == null) {
            return List.of();
        }
        List<AppDeployment> deployments =
                appDeploymentRepository.findByApplication_IdOrderByCreatedAtDesc(svc.getManagedApplication().getId());
        if (deployments.isEmpty()) {
            return List.of();
        }

        Set<Long> pipelineIds = deployments.stream()
                .map(AppDeployment::getGitlabPipelineId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Set<Long> participated = pipelineIds.isEmpty()
                ? Set.of()
                : pipelineExecutionRepository.findByAppService_IdAndGitlabPipelineIdIn(serviceId, pipelineIds).stream()
                        .map(PipelineExecution::getGitlabPipelineId)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());

        String serviceKey = svc.getId().toString();
        String serviceName = svc.getName();
        List<UUID> envIds = deployments.stream()
                .filter(d -> d.getEphemeralEnvironmentId() != null)
                .filter(d -> (d.getGitlabPipelineId() != null && participated.contains(d.getGitlabPipelineId()))
                        || mentionsService(d, serviceKey, serviceName))
                .map(AppDeployment::getEphemeralEnvironmentId)
                .distinct()
                .toList();
        if (envIds.isEmpty()) {
            return List.of();
        }
        return environmentRepository.findAllById(envIds);
    }

    private static boolean mentionsService(AppDeployment d, String serviceId, String serviceName) {
        Map<String, Object> state = d.getServicesState();
        if (state == null || state.isEmpty()) {
            return false;
        }
        if (state.containsKey(serviceId) || (serviceName != null && state.containsKey(serviceName))) {
            return true;
        }
        Object services = state.get("services");
        if (services instanceof Map<?, ?> m) {
            return m.containsKey(serviceId) || (serviceName != null && m.containsKey(serviceName));
        }
        return false;
    }
}
