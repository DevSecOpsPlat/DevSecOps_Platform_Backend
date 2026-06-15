package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.AlertType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Colonnes sécurité sur {@code users} et {@code login_attempts} — idempotent.
 */
@RequiredArgsConstructor
@Slf4j
public class SecuritySchemaMigration {

    private final JdbcTemplate jdbcTemplate;

    public void migrate() {
        addUserSecurityColumns();
        addLoginAttemptColumns();
        alignAlertsTypeCheck();
        backfillLegacyUsers();
        log.info("Schéma sécurité vérifié (users, login_attempts, alerts).");
    }

    private void addUserSecurityColumns() {
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'users'
                  ) THEN
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS activation_token VARCHAR(64);
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS activation_token_expires_at TIMESTAMP;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP;
                  END IF;
                END $$
                """);
    }

    private void addLoginAttemptColumns() {
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'login_attempts'
                  ) THEN
                    ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
                  END IF;
                END $$
                """);
    }

    /**
     * Hibernate ddl-auto=update n'actualise pas les CHECK PostgreSQL sur {@code alerts.type}.
     */
    private void alignAlertsTypeCheck() {
        String allowedTypes = Arrays.stream(AlertType.values())
                .map(t -> "'" + t.name() + "'")
                .collect(Collectors.joining(", "));
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'alerts'
                  ) THEN
                    ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_type_check;
                    ALTER TABLE alerts ADD CONSTRAINT alerts_type_check CHECK (type IN (%s));
                  END IF;
                END $$
                """.formatted(allowedTypes));
        log.info("Contrainte alerts_type_check alignée sur AlertType ({} valeurs).", AlertType.values().length);
    }

    private void backfillLegacyUsers() {
        Integer count = jdbcTemplate.queryForObject("""
                SELECT COUNT(*) FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'users'
                """, Integer.class);
        if (count == null || count == 0) {
            return;
        }
        int updated = jdbcTemplate.update("""
                UPDATE users
                SET activated_at = COALESCE(created_at, NOW())
                WHERE activated_at IS NULL
                  AND activation_token IS NULL
                """);
        if (updated > 0) {
            log.info("{} compte(s) existant(s) marqué(s) comme activés.", updated);
        }
    }
}
