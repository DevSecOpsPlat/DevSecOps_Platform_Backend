package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import com.backend.devsecopsplatform_backend.repository.AppDeploymentRepository;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import com.backend.devsecopsplatform_backend.service.appmgmt.K8sManifestApplyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Monitoring cluster-wide réservé admin (console `/admin/monitoring`, protégée globalement par
 * {@code hasAuthority("ROLE_ADMIN")} sur {@code /api/admin/**} — voir SecurityConfig). Distinct de
 * {@link com.backend.devsecopsplatform_backend.service.appmgmt.ApplicationManagementService},
 * qui reste scopé par propriétaire (un utilisateur normal ne voit que ses propres apps) — ici on
 * lit tous les environnements RUNNING de tous les utilisateurs, tous les nœuds du cluster.
 * Chantier "monitoring persistant", 18 août 2026.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminMonitoringService {

    private final AppDeploymentRepository deploymentRepository;
    private final K8sManifestApplyService k8sManifestApplyService;

    /** Capacité de tous les nœuds du cluster (CPU/MEM/disque) — même donnée que le garde-fou de déploiement. */
    public Map<String, Object> getClusterNodes() {
        return k8sManifestApplyService.getClusterCapacity();
    }

    /**
     * Une ligne par environnement RUNNING, tous utilisateurs confondus — résumé léger (pas de
     * metrics-server/kubelet par ligne, cf. {@link K8sManifestApplyService#getNamespacePodSummary}).
     * Signale aussi les déploiements "orphelins" : un `AppDeployment` RUNNING qui n'est plus le
     * plus récent de son appli — invisible dans le portail utilisateur (le bouton Arrêter n'agit
     * que sur le dernier déploiement), trouvé et corrigé à la source le 18 août 2026 pour les
     * nouveaux déploiements, mais d'éventuels restes antérieurs ne sont visibles que depuis ici.
     */
    public List<Map<String, Object>> getNamespacesSummary() {
        List<AppDeployment> running = deploymentRepository.findByStatus(AppDeploymentStatus.RUNNING);
        Map<UUID, AppDeployment> latestByApp = running.stream()
                .filter(d -> d.getApplication() != null)
                .collect(Collectors.toMap(
                        d -> d.getApplication().getId(),
                        d -> d,
                        (a, b) -> a.getCreatedAt().isAfter(b.getCreatedAt()) ? a : b
                ));

        // En parallèle : un appel K8s (pods + events) par déploiement RUNNING, sinon la latence
        // grandit avec le nombre d'environnements (retour utilisateur du 19 août 2026 : "20s avant
        // que ça s'affiche" — la boucle nœuds était la cause principale, celle-ci contribuait aussi).
        List<Map<String, Object>> out = running.parallelStream().map(d -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("namespace", d.getNamespace());
            row.put("deploymentId", d.getId());
            row.put("createdAt", d.getCreatedAt());
            if (d.getApplication() != null) {
                row.put("appId", d.getApplication().getId());
                row.put("appName", d.getApplication().getName());
                row.put("ownerUsername", d.getApplication().getCreatedBy() != null
                        ? d.getApplication().getCreatedBy().getUsername() : null);
                AppDeployment latest = latestByApp.get(d.getApplication().getId());
                row.put("orphaned", latest == null || !latest.getId().equals(d.getId()));
            } else {
                row.put("orphaned", false);
            }
            try {
                row.putAll(k8sManifestApplyService.getNamespacePodSummary(d.getNamespace()));
            } catch (Exception e) {
                log.debug("getNamespacesSummary {}: {}", d.getNamespace(), e.getMessage());
            }
            return row;
        }).collect(Collectors.toCollection(ArrayList::new));
        out.sort(Comparator.comparing((Map<String, Object> r) -> Boolean.TRUE.equals(r.get("orphaned"))).reversed()
                .thenComparing(r -> String.valueOf(r.get("appName"))));
        return out;
    }

    /**
     * Détail complet d'UN namespace, pour le clic depuis le tableau résumé — pas de vérification
     * de propriétaire (contrairement au chemin utilisateur normal) : l'admin peut inspecter
     * n'importe quel environnement de n'importe quel utilisateur, protection déjà assurée par le
     * rôle ADMIN sur toute la route {@code /api/admin/**}.
     */
    public Map<String, Object> getNamespaceDetail(String namespace) {
        AppDeployment deployment = deploymentRepository.findByNamespace(namespace)
                .orElseThrow(() -> new AppValidationException("Namespace introuvable : " + namespace));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("namespace", namespace);
        out.put("deploymentId", deployment.getId());
        if (deployment.getApplication() != null) {
            out.put("appId", deployment.getApplication().getId());
            out.put("appName", deployment.getApplication().getName());
            out.put("ownerUsername", deployment.getApplication().getCreatedBy() != null
                    ? deployment.getApplication().getCreatedBy().getUsername() : null);
        }
        out.put("status", deployment.getStatus());
        out.putAll(k8sManifestApplyService.getNamespaceMonitoring(namespace));
        return out;
    }
}
