package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
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
     * Les bases sont en vague 0, les backends/workers commencent en vague 1 et les frontends
     * en vague 2. Une dépendance impose toujours une vague strictement postérieure.
     *
     * <p>Note : {@code dependsOnDatabaseId} n'augmente pas la vague service —
     * les bases sont toujours appliquées en vague 0 avant tout service.</p>
     */
    public static Map<Integer, List<AppService>> computeWaves(ManagedApplication app) {
        assertNoCycle(app, null, null);
        Map<UUID, AppService> byId = new HashMap<>();
        for (AppService svc : app.getServices()) {
            if (svc.getId() != null) {
                byId.put(svc.getId(), svc);
            }
        }

        Map<UUID, Integer> waveCache = new HashMap<>();
        Map<Integer, List<AppService>> waves = new LinkedHashMap<>();

        for (AppService svc : app.getServices()) {
            int wave = waveOf(svc, byId, waveCache, new HashSet<>());
            waves.computeIfAbsent(wave, k -> new ArrayList<>()).add(svc);
        }
        return waves;
    }

    private static int waveOf(
            AppService svc,
            Map<UUID, AppService> byId,
            Map<UUID, Integer> cache,
            Set<UUID> visiting
    ) {
        if (svc.getId() != null && cache.containsKey(svc.getId())) {
            return cache.get(svc.getId());
        }
        if (svc.getId() != null && !visiting.add(svc.getId())) {
            throw new AppValidationException("Cycle de dépendances détecté entre services.");
        }

        int wave = svc.getRole() == AppServiceRole.FRONTEND ? 2 : 1;
        UUID depId = svc.getDependsOnServiceId();
        AppService dep = depId != null ? byId.get(depId) : null;
        if (dep != null) {
            if (svc.getRole() != AppServiceRole.FRONTEND && dep.getRole() == AppServiceRole.FRONTEND) {
                throw new AppValidationException(
                        "Un backend ou worker ne peut pas dépendre d'un frontend.");
            }
            wave = Math.max(wave, waveOf(dep, byId, cache, visiting) + 1);
        }
        if (svc.getId() != null) {
            visiting.remove(svc.getId());
            cache.put(svc.getId(), wave);
        }
        return wave;
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
