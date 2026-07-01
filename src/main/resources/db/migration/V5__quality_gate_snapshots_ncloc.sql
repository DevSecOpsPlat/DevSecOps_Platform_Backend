ALTER TABLE quality_gate_snapshots
    ADD COLUMN IF NOT EXISTS ncloc INTEGER;

COMMENT ON COLUMN quality_gate_snapshots.ncloc IS
    'Lignes de code non commentées (SonarQube) au moment du snapshot — pour score densité';
