-- Anciennes bases : CHECK sur scan_type limité à CODE, IMAGE, DEPENDENCIES, …
-- L'enum Java ScanType inclut SCA, SAST, SECRETS, etc. Hibernate ddl-auto=update ne met pas à jour ces CHECK.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'security_scans'
  ) THEN
    ALTER TABLE security_scans DROP CONSTRAINT IF EXISTS security_scans_scan_type_check;
    ALTER TABLE security_scans ADD CONSTRAINT security_scans_scan_type_check CHECK (
      scan_type IN (
        'CODE', 'IMAGE', 'DEPENDENCIES', 'INFRASTRUCTURE', 'DAST',
        'SAST', 'SCA', 'SECRETS', 'CONTAINER', 'IAC', 'LICENSE', 'QUALITY'
      )
    );
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'findings'
  ) THEN
    ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_scan_type_check;
    ALTER TABLE findings ADD CONSTRAINT findings_scan_type_check CHECK (
      scan_type IN (
        'CODE', 'IMAGE', 'DEPENDENCIES', 'INFRASTRUCTURE', 'DAST',
        'SAST', 'SCA', 'SECRETS', 'CONTAINER', 'IAC', 'LICENSE', 'QUALITY'
      )
    );
  END IF;
END $$;
