package com.backend.devsecopsplatform_backend.configuration;

import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManagerFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Nettoyage de l'ancien workflow d'approbation, exécuté au démarrage (idempotent) :
 * conversion des statuts vers ACTIVE / DISABLED et suppression des colonnes obsolètes.
 * La table user_activity_log est créée automatiquement par Hibernate (ddl-auto=update).
 */
@Component("legacyAccountStatusMigration")
@RequiredArgsConstructor
@Slf4j
public class LegacyAccountStatusMigration {

    private final JdbcTemplate jdbcTemplate;

    /* Injecté uniquement pour garantir que le schéma Hibernate est créé avant ce nettoyage. */
    @SuppressWarnings("unused")
    private final EntityManagerFactory entityManagerFactory;

    @PostConstruct
    public void migrate() {
        // L'ancienne contrainte CHECK (générée par Hibernate) n'autorise que les anciens statuts.
        jdbcTemplate.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_account_status_check");

        int activated = jdbcTemplate.update(
                "UPDATE users SET account_status = 'ACTIVE' WHERE account_status IN ('APPROVED', 'PENDING')");
        int disabled = jdbcTemplate.update(
                "UPDATE users SET account_status = 'DISABLED' WHERE account_status IN ('REJECTED', 'SUSPENDED')");

        jdbcTemplate.execute(
                "ALTER TABLE users ADD CONSTRAINT users_account_status_check CHECK (account_status IN ('ACTIVE', 'DISABLED'))");

        jdbcTemplate.execute("ALTER TABLE users DROP COLUMN IF EXISTS validated_by");
        jdbcTemplate.execute("ALTER TABLE users DROP COLUMN IF EXISTS validated_at");
        jdbcTemplate.execute("ALTER TABLE users DROP COLUMN IF EXISTS rejection_reason");

        if (activated > 0 || disabled > 0) {
            log.info("Statuts de comptes migrés : {} -> ACTIVE, {} -> DISABLED", activated, disabled);
        }
    }
}
