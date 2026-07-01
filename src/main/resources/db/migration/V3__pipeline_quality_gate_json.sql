DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'pipeline_executions'
  ) THEN
    ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS quality_gate_json JSONB;
  END IF;
END $$;
