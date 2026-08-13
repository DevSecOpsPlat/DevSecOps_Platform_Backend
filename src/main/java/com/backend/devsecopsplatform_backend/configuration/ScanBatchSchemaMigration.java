package com.backend.devsecopsplatform_backend.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

/**
 * Migration idempotente : table {@code scan_batches} + colonnes lot / commit sur
 * {@code pipeline_executions}. Invoquée depuis {@link SecuritySchemaMigration}
 * (même mécanisme d'ordonnancement que le reste du schéma sécurité).
 */
@RequiredArgsConstructor
@Slf4j
public class ScanBatchSchemaMigration {

    private final JdbcTemplate jdbcTemplate;

    public void migrate() {
        ensureScanBatchesTable();
        addPipelineExecutionLotColumns();
        dropSoloGitlabPipelineUniqueConstraints();
        ensureGitlabServiceUniqueIfClean();
        log.info("Schéma scan_batches / pipeline_executions (lot) vérifié.");
    }

    private void ensureScanBatchesTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS scan_batches (
                  id UUID PRIMARY KEY,
                  managed_application_id UUID NOT NULL,
                  status VARCHAR(30) NOT NULL,
                  gitlab_pipeline_id BIGINT,
                  expected_service_count INTEGER NOT NULL DEFAULT 0,
                  triggered_by UUID NOT NULL,
                  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                  finished_at TIMESTAMP,
                  verdict VARCHAR(40),
                  security_score INTEGER,
                  grade VARCHAR(2),
                  verdict_payload_json jsonb
                )
                """);
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'scan_batches'
                  ) THEN
                    ALTER TABLE scan_batches
                      ADD COLUMN IF NOT EXISTS expected_service_count INTEGER NOT NULL DEFAULT 0;
                  END IF;
                END $$
                """);
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'scan_batches'
                  ) AND EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'applications'
                  ) THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_constraint WHERE conname = 'fk_scan_batch_app'
                    ) THEN
                      ALTER TABLE scan_batches
                        ADD CONSTRAINT fk_scan_batch_app
                        FOREIGN KEY (managed_application_id) REFERENCES applications(id);
                    END IF;
                  END IF;
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'users'
                  ) THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_constraint WHERE conname = 'fk_scan_batch_triggered_by'
                    ) THEN
                      ALTER TABLE scan_batches
                        ADD CONSTRAINT fk_scan_batch_triggered_by
                        FOREIGN KEY (triggered_by) REFERENCES users(id);
                    END IF;
                  END IF;
                END $$
                """);
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_scan_batch_app ON scan_batches (managed_application_id)");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_scan_batch_gitlab ON scan_batches (gitlab_pipeline_id)");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_scan_batch_status ON scan_batches (status)");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_scan_batch_created ON scan_batches (created_at)");
    }

    private void addPipelineExecutionLotColumns() {
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
                  ) THEN
                    ALTER TABLE pipeline_executions
                      ADD COLUMN IF NOT EXISTS scan_batch_id UUID;
                    ALTER TABLE pipeline_executions
                      ADD COLUMN IF NOT EXISTS commit_sha VARCHAR(64);
                    ALTER TABLE pipeline_executions
                      ADD COLUMN IF NOT EXISTS checked_head_sha VARCHAR(64);
                    ALTER TABLE pipeline_executions
                      ADD COLUMN IF NOT EXISTS head_checked_at TIMESTAMP;
                  END IF;
                END $$
                """);
        jdbcTemplate.execute("""
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
                  ) AND EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'scan_batches'
                  ) THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_constraint WHERE conname = 'fk_pipeline_scan_batch'
                    ) THEN
                      ALTER TABLE pipeline_executions
                        ADD CONSTRAINT fk_pipeline_scan_batch
                        FOREIGN KEY (scan_batch_id) REFERENCES scan_batches(id);
                    END IF;
                  END IF;
                END $$
                """);
        jdbcTemplate.execute(
                "CREATE INDEX IF NOT EXISTS idx_pipeline_scan_batch ON pipeline_executions (scan_batch_id)");
    }

    /**
     * Supprime toute UNIQUE portant uniquement sur {@code gitlab_pipeline_id}
     * (nom Hibernate / Postgres variable — découverte via {@code pg_constraint}).
     */
    private void dropSoloGitlabPipelineUniqueConstraints() {
        Boolean tableExists = jdbcTemplate.queryForObject("""
                SELECT EXISTS (
                  SELECT 1 FROM information_schema.tables
                  WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
                )
                """, Boolean.class);
        if (!Boolean.TRUE.equals(tableExists)) {
            return;
        }

        List<String> constraintNames = jdbcTemplate.queryForList("""
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = 'public'
                  AND t.relname = 'pipeline_executions'
                  AND c.contype = 'u'
                  AND (
                    SELECT array_agg(a.attname::text ORDER BY x.ordinality)
                    FROM unnest(c.conkey) WITH ORDINALITY AS x(attnum, ordinality)
                    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = x.attnum
                  ) = ARRAY['gitlab_pipeline_id']::text[]
                """, String.class);

        for (String name : constraintNames) {
            log.warn("Suppression contrainte UNIQUE solo sur gitlab_pipeline_id : {}", name);
            jdbcTemplate.execute("ALTER TABLE pipeline_executions DROP CONSTRAINT IF EXISTS " + quoteIdent(name));
        }
    }

    /**
     * Pose {@code uq_pipeline_gitlab_service} seulement si aucune donnée ne la viole.
     */
    private void ensureGitlabServiceUniqueIfClean() {
        Boolean tableExists = jdbcTemplate.queryForObject("""
                SELECT EXISTS (
                  SELECT 1 FROM information_schema.tables
                  WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
                )
                """, Boolean.class);
        if (!Boolean.TRUE.equals(tableExists)) {
            return;
        }

        Boolean already = jdbcTemplate.queryForObject("""
                SELECT EXISTS (
                  SELECT 1 FROM pg_constraint WHERE conname = 'uq_pipeline_gitlab_service'
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(already)) {
            return;
        }

        List<Map<String, Object>> dupes = jdbcTemplate.queryForList("""
                SELECT gitlab_pipeline_id, app_service_id, count(*) AS cnt
                FROM pipeline_executions
                WHERE gitlab_pipeline_id IS NOT NULL
                GROUP BY gitlab_pipeline_id, app_service_id
                HAVING count(*) > 1
                """);

        if (!dupes.isEmpty()) {
            log.warn(
                    "Contrainte uq_pipeline_gitlab_service NON posée : {} couple(s) (gitlab_pipeline_id, app_service_id) en doublon. "
                            + "Nettoyer pipeline_executions puis redémarrer. Exemples : {}",
                    dupes.size(),
                    dupes.stream().limit(5).toList()
            );
            return;
        }

        jdbcTemplate.execute("""
                ALTER TABLE pipeline_executions
                  ADD CONSTRAINT uq_pipeline_gitlab_service
                  UNIQUE (gitlab_pipeline_id, app_service_id)
                """);
        log.info("Contrainte uq_pipeline_gitlab_service posée.");
    }

    private static String quoteIdent(String ident) {
        return "\"" + ident.replace("\"", "\"\"") + "\"";
    }
}
