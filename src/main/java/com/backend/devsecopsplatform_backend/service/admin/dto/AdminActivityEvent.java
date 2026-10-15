package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Un événement du fil d'activité admin, fusionné depuis trois sources indépendantes
 * (PipelineExecution, Alert, UserActivityLog) — cf. docs/audit-dashboard-admin.md et le plan de
 * refonte du dashboard admin (Phase 1). Volontairement une donnée brute (type d'événement, pas de
 * libellé déjà traduit) : le frontend possède déjà les tables de libellés par type d'alerte / type
 * d'activité de compte, pas de raison de les dupliquer côté backend.
 */
public record AdminActivityEvent(
        String id,
        /** PIPELINE | ALERT | ACCOUNT */
        String kind,
        /** Nom brut de l'enum source : PipelineStatus, AlertType ou UserActivityType. */
        String eventType,
        /** Texte descriptif déjà lisible (message d'alerte, détail d'activité de compte, ou résumé
         * de pipeline construit ici faute de champ dédié sur PipelineExecution). */
        String message,
        String actorUsername,
        UUID applicationId,
        String applicationName,
        UUID environmentId,
        String environmentName,
        /** INFO | WARNING | CRITICAL */
        String severity,
        LocalDateTime occurredAt
) {}
