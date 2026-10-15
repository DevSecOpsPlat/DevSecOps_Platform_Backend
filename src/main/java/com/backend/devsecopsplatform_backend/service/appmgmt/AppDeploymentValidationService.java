package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.DeployPreviewResponse;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Validation de cohérence avant déploiement (architecture.md §3.2).
 *
 * <p>Erreurs bloquantes → {@link AppValidationException} (HTTP 400). Les incohérences
 * mineures sont renvoyées sous forme d'avertissements / infos (preview + logs deploy).</p>
 */
@Service
public class AppDeploymentValidationService {

    // Mêmes clés de config que AppDeploymentService — quota namespace appliqué au déploiement.
    @Value("${deployment.namespace.resource-quota.enabled:true}")
    private boolean namespaceResourceQuotaEnabled;

    @Value("${deployment.namespace.cpu-quota:4}")
    private String namespaceCpuQuota;

    @Value("${deployment.namespace.memory-quota:8Gi}")
    private String namespaceMemoryQuota;

    /**
     * Valide l'application et renvoie la liste des avertissements non bloquants.
     *
     * @throws AppValidationException si une règle bloquante est violée.
     */
    public List<String> validate(ManagedApplication app) {
        DeployPreviewResponse preview = buildPreview(app, 4, true);
        if (!preview.getBlockingErrors().isEmpty()) {
            throw new AppValidationException(preview.getBlockingErrors().get(0));
        }
        return new ArrayList<>(preview.getWarnings());
    }

    /**
     * Aperçu non bloquant pour peupler la modale de déploiement (infos + warnings + confirmation).
     */
    public DeployPreviewResponse preview(ManagedApplication app, int ttlHours) {
        return buildPreview(app, ttlHours, false);
    }

    private DeployPreviewResponse buildPreview(ManagedApplication app, int ttlHours, boolean throwOnBlock) {
        List<String> infos = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<String> blocking = new ArrayList<>();
        boolean requiresConfirmation = false;

        List<AppService> services = app.getServices() != null ? app.getServices() : List.of();
        List<AppDatabase> databases = app.getDatabases() != null ? app.getDatabases() : List.of();

        Map<UUID, AppDatabase> dbById = new HashMap<>();
        for (AppDatabase db : databases) {
            dbById.put(db.getId(), db);
        }
        Map<UUID, AppService> svcById = new HashMap<>();
        for (AppService svc : services) {
            svcById.put(svc.getId(), svc);
        }

        if (services.isEmpty()) {
            String msg = "L'application ne contient aucun service à déployer.";
            if (throwOnBlock) {
                throw new AppValidationException(msg);
            }
            blocking.add(msg);
        }

        for (AppService svc : services) {
            UUID dbDep = svc.getDependsOnDatabaseId();
            if (dbDep != null) {
                if (databases.isEmpty()) {
                    String msg = "Un backend nécessite une base de données. Ajoutez d'abord une base ou retirez la dépendance.";
                    if (throwOnBlock) {
                        throw new AppValidationException(msg);
                    }
                    blocking.add(msg);
                } else if (!dbById.containsKey(dbDep)) {
                    String msg = "Le service « " + svc.getName() + " » référence une base de données inexistante "
                            + "dans cette sélection.";
                    if (throwOnBlock) {
                        throw new AppValidationException(msg);
                    }
                    blocking.add(msg);
                }
            } else if (svc.getRole() == AppServiceRole.BACKEND) {
                warnings.add("Backend « " + svc.getName()
                        + " » : aucune BD associée — ce backend sera déployé sans persistance des données.");
                requiresConfirmation = true;
            }

            UUID svcDep = svc.getDependsOnServiceId();
            if (svcDep != null && !svcById.containsKey(svcDep)) {
                // Absent du jeu déployé (sous-ensemble) → warning, pas blocage.
                warnings.add("Le service « " + svc.getName()
                        + " » dépend d'un autre service non inclus dans ce déploiement "
                        + "(URL / API distante peut être absente). Vous pouvez ignorer ce point volontairement.");
            }
        }

        // Collision de port exposé
        Map<Integer, String> portToService = new HashMap<>();
        for (AppService svc : services) {
            if (svc.getRole() == AppServiceRole.WORKER || svc.getExposedPort() == null) {
                continue;
            }
            String previous = portToService.putIfAbsent(svc.getExposedPort(), svc.getName());
            if (previous != null) {
                warnings.add("Les services « " + previous + " » et « " + svc.getName()
                        + " » exposent le même port " + svc.getExposedPort()
                        + " (collision d'ingress possible).");
            }
        }

        // Isolation namespace, TTL et ordre de démarrage : redondants avec le formulaire (TTL déjà
        // saisi) et le panneau pipeline (progression détaillée, cf. deployPhase structuré) — retirés
        // de la preview modale suite retour utilisateur (jugés inutiles ici, 17 août 2026).
        int ttl = Math.max(1, Math.min(ttlHours, 72));
        if (databases.isEmpty() && services.stream().anyMatch(s -> s.getRole() == AppServiceRole.BACKEND
                || s.getRole() == AppServiceRole.WORKER)) {
            infos.add("Aucune base dans cette sélection — les services démarreront sans dépendance stockage.");
        }
        if (services.stream().anyMatch(s -> s.getRole() == AppServiceRole.FRONTEND)
                && services.stream().noneMatch(s -> s.getRole() == AppServiceRole.BACKEND)) {
            warnings.add("Frontend sans backend dans la sélection — les appels API peuvent échouer "
                    + "si le front pointe vers une URL backend absente.");
        }

        List<UUID> resolvedIds = services.stream()
                .map(AppService::getId)
                .collect(Collectors.toList());

        // Empreinte ressources demandée vs quota namespace — évite de confirmer un déploiement
        // qui dépassera immédiatement le ResourceQuota (cf. audit-deploiement.md, quick win #3).
        // Multiplié par replicas : un pod ne demande pas les ressources du Deployment, il en
        // demande N fois plus si N replicas — un service à 3 replicas × 3 cores demande 9 cores,
        // pas 3 (bug réel découvert le 18 août 2026 : le test utilisateur avait 3 replicas sur un
        // nœud à 2 cores au total, largement sous-estimé par ce calcul avant correction).
        double requestedCpuCores = services.stream()
                .mapToDouble(s -> K8sManifestApplyService.parseCpuToCores(s.getCpuRequest())
                        * replicasOrOne(s.getReplicas()))
                .sum();
        long requestedMemoryBytes = services.stream()
                .mapToLong(s -> K8sManifestApplyService.parseMemoryToBytes(s.getMemoryRequest())
                        * replicasOrOne(s.getReplicas()))
                .sum();
        double quotaCpuCores = namespaceResourceQuotaEnabled
                ? K8sManifestApplyService.parseCpuToCores(namespaceCpuQuota) : 0;
        long quotaMemoryBytes = namespaceResourceQuotaEnabled
                ? K8sManifestApplyService.parseMemoryToBytes(namespaceMemoryQuota) : 0;
        if (namespaceResourceQuotaEnabled && quotaCpuCores > 0 && requestedCpuCores > quotaCpuCores) {
            warnings.add("Requests CPU demandées (" + formatCores(requestedCpuCores)
                    + ") supérieures au quota namespace (" + formatCores(quotaCpuCores)
                    + ") — le déploiement risque un FailedCreate faute de capacité.");
        }
        if (namespaceResourceQuotaEnabled && quotaMemoryBytes > 0 && requestedMemoryBytes > quotaMemoryBytes) {
            warnings.add("Requests mémoire demandées (" + formatMi(requestedMemoryBytes)
                    + ") supérieures au quota namespace (" + formatMi(quotaMemoryBytes)
                    + ") — le déploiement risque un FailedCreate faute de capacité.");
        }

        return DeployPreviewResponse.builder()
                .infos(infos)
                .warnings(warnings)
                .blockingErrors(blocking)
                .requiresConfirmation(requiresConfirmation)
                .ttlHours(ttl)
                .selectedServiceCount(services.size())
                .selectedDatabaseCount(databases.size())
                .resolvedServiceIds(resolvedIds)
                .quotaEnabled(namespaceResourceQuotaEnabled)
                .requestedCpuMillicores((int) Math.round(requestedCpuCores * 1000))
                .requestedMemoryBytes(requestedMemoryBytes)
                .quotaCpuMillicores((int) Math.round(quotaCpuCores * 1000))
                .quotaMemoryBytes(quotaMemoryBytes)
                .build();
    }

    private static int replicasOrOne(Integer replicas) {
        return replicas != null && replicas > 0 ? replicas : 1;
    }

    private static String formatCores(double cores) {
        if (cores < 1) {
            return Math.round(cores * 1000) + "m";
        }
        return (Math.round(cores * 100) / 100.0) + " cores";
    }

    private static String formatMi(long bytes) {
        double gi = bytes / (1024.0 * 1024.0 * 1024.0);
        if (gi >= 1) {
            return (Math.round(gi * 100) / 100.0) + "Gi";
        }
        return Math.round(bytes / (1024.0 * 1024.0)) + "Mi";
    }

    /**
     * Construit une vue mémoire (shadow) filtrée : services choisis + BD liées.
     * Ne mute pas les collections JPA de {@code realApp}.
     */
    public ManagedApplication buildShadow(ManagedApplication realApp, List<UUID> serviceIds) {
        if (serviceIds == null || serviceIds.isEmpty()) {
            return realApp;
        }

        Set<UUID> wanted = new HashSet<>(serviceIds);
        List<AppService> selected = realApp.getServices().stream()
                .filter(s -> wanted.contains(s.getId()))
                .collect(Collectors.toList());

        if (selected.isEmpty()) {
            throw new AppValidationException("Aucun des services demandés n'appartient à ce projet.");
        }
        if (selected.size() != wanted.size()) {
            throw new AppValidationException("Un ou plusieurs serviceIds sont introuvables dans ce projet.");
        }

        Set<UUID> dbIds = new HashSet<>();
        for (AppService svc : selected) {
            if (svc.getDependsOnDatabaseId() != null) {
                dbIds.add(svc.getDependsOnDatabaseId());
            }
        }
        List<AppDatabase> selectedDbs = realApp.getDatabases().stream()
                .filter(d -> dbIds.contains(d.getId()))
                .collect(Collectors.toList());

        ManagedApplication shadow = new ManagedApplication();
        shadow.setId(realApp.getId());
        shadow.setName(realApp.getName());
        shadow.setSlug(realApp.getSlug());
        shadow.setCustomHostname(realApp.getCustomHostname());
        shadow.setDescription(realApp.getDescription());
        shadow.setCreatedBy(realApp.getCreatedBy());
        shadow.setServices(selected);
        shadow.setDatabases(selectedDbs);
        return shadow;
    }
}
