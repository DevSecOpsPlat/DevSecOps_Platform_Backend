-- Fil de discussion : statut CLOSED à la place d'ANSWERED, table complaint_messages, suppression des colonnes mono-réponse.
-- Exécuté avant Hibernate ; idempotent pour bases neuves ou déjà migrées.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'complaints'
  ) THEN
    UPDATE complaints SET status = 'OPEN' WHERE status = 'ANSWERED';

    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'complaints' AND column_name = 'message'
    ) THEN
      ALTER TABLE complaints ALTER COLUMN message DROP NOT NULL;
    END IF;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'complaints'
  )
  AND NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'complaint_messages'
  ) THEN
    CREATE TABLE complaint_messages (
      id UUID NOT NULL PRIMARY KEY,
      complaint_id UUID NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
      author_id UUID NOT NULL REFERENCES users(id),
      body TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_complaint_msg_complaint ON complaint_messages(complaint_id);
    CREATE INDEX idx_complaint_msg_created ON complaint_messages(created_at);
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'complaint_messages'
  )
  AND EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'complaints' AND column_name = 'message'
  ) THEN
    INSERT INTO complaint_messages (id, complaint_id, author_id, body, created_at)
    SELECT gen_random_uuid(), c.id, c.author_id, c.message, COALESCE(c.created_at, now())
    FROM complaints c
    WHERE c.message IS NOT NULL AND length(trim(c.message)) > 0
      AND NOT EXISTS (SELECT 1 FROM complaint_messages m WHERE m.complaint_id = c.id);
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'complaints'
  ) THEN
    ALTER TABLE complaints DROP COLUMN IF EXISTS admin_response;
    ALTER TABLE complaints DROP COLUMN IF EXISTS responded_by;
    ALTER TABLE complaints DROP COLUMN IF EXISTS responded_at;
    ALTER TABLE complaints DROP COLUMN IF EXISTS message;
  END IF;
END $$;
