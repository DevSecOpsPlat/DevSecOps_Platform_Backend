package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Validation de cohérence avant déploiement (architecture.md §3.2).
 *
 * <p>Erreurs bloquantes → {@link AppValidationException} (HTTP 400). Les incohérences
 * mineures (collision de port) sont renvoyées sous forme d'avertissements.</p>
 */
@Service
public class AppDeploymentValidationService {

    /**
     * Valide l'application et renvoie la liste des avertissements non bloquants.
     *
     * @throws AppValidationException si une règle bloquante est violée.
     */
    public List<String> validate(ManagedApplication app) {
        List<String> warnings = new ArrayList<>();
        List<AppService> services = app.getServices();
        List<AppDatabase> databases = app.getDatabases();

        Map<UUID, AppDatabase> dbById = new HashMap<>();
        for (AppDatabase db : databases) {
            dbById.put(db.getId(), db);
        }
        Map<UUID, AppService> svcById = new HashMap<>();
        for (AppService svc : services) {
            svcById.put(svc.getId(), svc);
        }

        if (services.isEmpty()) {
            throw new AppValidationException("L'application ne contient aucun service à déployer.");
        }

        for (AppService svc : services) {
            UUID dbDep = svc.getDependsOnDatabaseId();
            if (dbDep != null) {
                if (databases.isEmpty()) {
                    throw new AppValidationException(
                            "Un backend nécessite une base de données. Ajoutez d'abord une base ou retirez la dépendance.");
                }
                if (!dbById.containsKey(dbDep)) {
                    throw new AppValidationException(
                            "Le service « " + svc.getName() + " » référence une base de données inexistante "
                                    + "dans cette application.");
                }
            } else if (svc.getRole() == AppServiceRole.BACKEND && databases.isEmpty()) {
                // Un backend sans BD n'est pas bloquant, mais on le signale (cf. §5 avertissement inline).
                warnings.add("Le backend « " + svc.getName() + " » n'est lié à aucune base de données.");
            }

            UUID svcDep = svc.getDependsOnServiceId();
            if (svcDep != null && !svcById.containsKey(svcDep)) {
                throw new AppValidationException(
                        "Le service « " + svc.getName() + " » dépend d'un service qui n'appartient pas "
                                + "à cette application.");
            }
        }

        // Collision de port exposé entre services exposés externellement (avertissement, pas blocage).
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

        return warnings;
    }
}
