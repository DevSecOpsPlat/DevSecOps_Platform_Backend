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
);

CREATE INDEX IF NOT EXISTS idx_qg_snap_env_created
    ON quality_gate_snapshots (environment_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_qg_snap_app_branch_created
    ON quality_gate_snapshots (application_id, branch, created_at DESC);
