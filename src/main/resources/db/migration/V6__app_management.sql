-- Gestion des applications managées (services + bases + déploiement K8s multi-services).
-- Nouvelles tables uniquement — aucune table existante n'est modifiée (non-régression).

CREATE TABLE IF NOT EXISTS dep_application (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(120) NOT NULL,
    description TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT uq_depapp_slug UNIQUE (slug),
    CONSTRAINT fk_depapp_user FOREIGN KEY (created_by) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_depapp_created_by ON dep_application (created_by);
CREATE INDEX IF NOT EXISTS idx_depapp_slug ON dep_application (slug);

CREATE TABLE IF NOT EXISTS app_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    name VARCHAR(120) NOT NULL,
    db_family VARCHAR(20) NOT NULL,
    engine VARCHAR(20) NOT NULL,
    version VARCHAR(40) NOT NULL,
    db_name VARCHAR(120) NOT NULL,
    root_user VARCHAR(120) NOT NULL,
    root_password VARCHAR(1000) NOT NULL,
    exposed_port INTEGER NOT NULL,
    storage_size VARCHAR(20) NOT NULL DEFAULT '1Gi',
    generated_connection_url VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT fk_appdb_application FOREIGN KEY (application_id) REFERENCES dep_application (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_appdb_application ON app_database (application_id);

CREATE TABLE IF NOT EXISTS app_service (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    name VARCHAR(120) NOT NULL,
    role VARCHAR(20) NOT NULL,
    git_repository_url VARCHAR(500) NOT NULL,
    git_token VARCHAR(2000),
    git_branch VARCHAR(200) NOT NULL DEFAULT 'main',
    dockerfile_path VARCHAR(255) NOT NULL DEFAULT 'Dockerfile',
    build_context VARCHAR(255) NOT NULL DEFAULT '.',
    exposed_port INTEGER NOT NULL,
    depends_on_service_id UUID,
    depends_on_database_id UUID,
    db_url_env_var VARCHAR(120),
    replicas INTEGER NOT NULL DEFAULT 1,
    health_check_path VARCHAR(255),
    cpu_request VARCHAR(20),
    cpu_limit VARCHAR(20),
    memory_request VARCHAR(20),
    memory_limit VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT fk_appsvc_application FOREIGN KEY (application_id) REFERENCES dep_application (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_appsvc_application ON app_service (application_id);

CREATE TABLE IF NOT EXISTS service_env_var (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_service_id UUID NOT NULL,
    var_key VARCHAR(200) NOT NULL,
    var_value VARCHAR(4000),
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT fk_envvar_service FOREIGN KEY (app_service_id) REFERENCES app_service (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_envvar_service ON service_env_var (app_service_id);

CREATE TABLE IF NOT EXISTS app_deployment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    namespace VARCHAR(200) NOT NULL,
    status VARCHAR(20) NOT NULL,
    gitlab_pipeline_id BIGINT,
    deployed_at TIMESTAMPTZ,
    services_state JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT fk_appdeploy_application FOREIGN KEY (application_id) REFERENCES dep_application (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_appdeploy_application ON app_deployment (application_id);
CREATE INDEX IF NOT EXISTS idx_appdeploy_namespace ON app_deployment (namespace);
