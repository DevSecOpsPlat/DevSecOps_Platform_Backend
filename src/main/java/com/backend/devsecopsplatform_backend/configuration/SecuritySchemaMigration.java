package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.TwoFactorMethod;
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
        addUserTwoFactorColumns();
        alignTwoFactorMethodCheck();
        alignAlertsTypeCheck();
        alignAuditLogActionCheck();
        ensureBlockedIpsTable();
        addPipelineQualityGateColumn();
        ensureQualityGateSnapshotsTable();
        backfillLegacyUsers();
        log.info("Schéma sécurité vérifié (users, login_attempts, alerts, audit_log, blocked_ips).");
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
                    CREATE INDEX IF NOT EXISTS idx_login_ip_attempted_at ON login_attempts (ip_address, attempted_at);
                  END IF;
                END $$
                """);
    }

    private void addUserTwoFactorColumns() {
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'users'
                  ) THEN
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc VARCHAR(512);
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled_at TIMESTAMP;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_method VARCHAR(10);
                    UPDATE users
                    SET two_factor_method = 'TOTP'
                    WHERE two_factor_method IS NULL
                      AND totp_enabled = true
                      AND totp_secret_enc IS NOT NULL
                      AND totp_secret_enc <> '';
                  END IF;
                END $$
                """);
    }

    /**
     * Hibernate ddl-auto=update crée {@code users_two_factor_method_check} sans mettre à jour
     * les valeurs autorisées quand l'enum Java évolue (ex. ajout de EMAIL).
     */
    public void alignTwoFactorMethodCheck() {
        String allowed = Arrays.stream(TwoFactorMethod.values())
                .map(m -> "'" + m.name() + "'")
                .collect(Collectors.joining(", "));
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'users'
                  ) THEN
                    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_two_factor_method_check;
                    ALTER TABLE users ADD CONSTRAINT users_two_factor_method_check
                      CHECK (two_factor_method IS NULL OR two_factor_method IN (%s));
                  END IF;
                END $$
                """.formatted(allowed));
        log.info("Contrainte users_two_factor_method_check alignée ({} valeurs).", TwoFactorMethod.values().length);
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

    /**
     * Hibernate ddl-auto=update n'actualise pas les CHECK PostgreSQL sur {@code audit_log.action}.
     */
    private void alignAuditLogActionCheck() {
        String allowedActions = Arrays.stream(AuditAction.values())
                .map(a -> "'" + a.name() + "'")
                .collect(Collectors.joining(", "));
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'audit_log'
                  ) THEN
                    ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_action_check;
                    ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (%s));
                  END IF;
                END $$
                """.formatted(allowedActions));
        log.info("Contrainte audit_log_action_check alignée sur AuditAction ({} valeurs).", AuditAction.values().length);
    }

    private void ensureBlockedIpsTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                  id UUID PRIMARY KEY,
                  ip_address VARCHAR(45) NOT NULL,
                  reason VARCHAR(500) NOT NULL,
                  blocked_until TIMESTAMP NOT NULL,
                  source VARCHAR(20) NOT NULL DEFAULT 'AUTO',
                  active BOOLEAN NOT NULL DEFAULT true,
                  created_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
                """);
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip_address ON blocked_ips (ip_address)");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip_until ON blocked_ips (blocked_until)");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip_active ON blocked_ips (active)");
        log.info("Table blocked_ips vérifiée.");
    }

    private void addPipelineQualityGateColumn() {
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
                  ) THEN
                    ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS quality_gate_json JSONB;
                  END IF;
                END $$
                """);
    }

    private void ensureQualityGateSnapshotsTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS quality_gate_snapshots (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    application_id UUID NOT NULL,
                    environment_id UUID NOT NULL,
                    pipeline_execution_id UUID NOT NULL UNIQUE,
                    branch VARCHAR(255) NOT NULL,
                    gitlab_pipeline_id BIGINT,
                    source VARCHAR(32) NOT NULL,
                    evaluated_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    payload JSONB NOT NULL
                )
                """);
        jdbcTemplate.execute("""
                CREATE INDEX IF NOT EXISTS idx_qg_snap_env_created
                    ON quality_gate_snapshots (environment_id, created_at DESC)
                """);
        jdbcTemplate.execute("""
                CREATE INDEX IF NOT EXISTS idx_qg_snap_app_branch_created
                    ON quality_gate_snapshots (application_id, branch, created_at DESC)
                """);
        log.info("Table quality_gate_snapshots vérifiée.");
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
