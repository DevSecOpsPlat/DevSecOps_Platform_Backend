package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Topologie des services managés : vagues de déploiement (tri topologique)
 * et détection de cycles de dépendances.
 */
public final class ServiceTopology {

    private ServiceTopology() {
    }

    /**
     * Vague = 1 + profondeur max des dépendances service.
     * Les services sans {@code dependsOnServiceId} sont en vague 1 (après les bases = vague 0).
     * Un service qui dépend d'un autre est déployé après celui-ci.
     *
     * <p>Note : {@code dependsOnDatabaseId} n'augmente pas la vague service —
     * les bases sont toujours appliquées en vague 0 avant tout service.</p>
     */
    public static Map<Integer, List<AppService>> computeWaves(ManagedApplication app) {
        Map<UUID, AppService> byId = new HashMap<>();
        for (AppService svc : app.getServices()) {
            if (svc.getId() != null) {
                byId.put(svc.getId(), svc);
            }
        }

        Map<UUID, Integer> depthCache = new HashMap<>();
        Map<Integer, List<AppService>> waves = new LinkedHashMap<>();

        for (AppService svc : app.getServices()) {
            int depth = depthOf(svc, byId, depthCache, new HashSet<>());
            int wave = depth + 1; // 1-based among services
            waves.computeIfAbsent(wave, k -> new ArrayList<>()).add(svc);
        }
        return waves;
    }

    private static int depthOf(
            AppService svc,
            Map<UUID, AppService> byId,
            Map<UUID, Integer> cache,
            Set<UUID> visiting
    ) {
        if (svc.getId() != null && cache.containsKey(svc.getId())) {
            return cache.get(svc.getId());
        }
        UUID depId = svc.getDependsOnServiceId();
        if (depId == null) {
            if (svc.getId() != null) {
                cache.put(svc.getId(), 0);
            }
            return 0;
        }
        if (svc.getId() != null && !visiting.add(svc.getId())) {
            // Cycle — profondeur 0 ici ; assertNoCycle lève l'erreur métier.
            return 0;
        }
        AppService dep = byId.get(depId);
        int d = dep == null ? 0 : 1 + depthOf(dep, byId, cache, visiting);
        if (svc.getId() != null) {
            visiting.remove(svc.getId());
            cache.put(svc.getId(), d);
        }
        return d;
    }

    /**
     * Détecte un cycle dans le graphe {@code dependsOnServiceId}.
     * {@code pendingEdgeFrom} / {@code pendingEdgeTo} : arête en cours d'ajout (création/édition).
     */
    public static void assertNoCycle(
            ManagedApplication app,
            UUID pendingEdgeFrom,
            UUID pendingEdgeTo
    ) {
        if (pendingEdgeTo == null) {
            return;
        }
        Map<UUID, UUID> edges = new HashMap<>();
        for (AppService svc : app.getServices()) {
            if (svc.getId() != null && svc.getDependsOnServiceId() != null) {
                edges.put(svc.getId(), svc.getDependsOnServiceId());
            }
        }
        if (pendingEdgeFrom != null) {
            edges.put(pendingEdgeFrom, pendingEdgeTo);
        }

        Set<UUID> visiting = new HashSet<>();
        Set<UUID> done = new HashSet<>();
        for (UUID start : edges.keySet()) {
            if (hasCycleFrom(start, edges, visiting, done)) {
                throw new AppValidationException(
                        "Cycle de dépendances détecté entre services. "
                                + "Un service ne peut pas dépendre (directement ou indirectement) de lui-même.");
            }
        }
    }

    private static boolean hasCycleFrom(
            UUID node,
            Map<UUID, UUID> edges,
            Set<UUID> visiting,
            Set<UUID> done
    ) {
        if (done.contains(node)) {
            return false;
        }
        if (!visiting.add(node)) {
            return true;
        }
        UUID next = edges.get(node);
        if (next != null && hasCycleFrom(next, edges, visiting, done)) {
            return true;
        }
        visiting.remove(node);
        done.add(node);
        return false;
    }
}
