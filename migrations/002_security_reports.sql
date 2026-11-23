-- Security Lab operational reports. Safe additive migration.
CREATE TABLE IF NOT EXISTS security_lab_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES security_lab_users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS security_lab_reports_user_created_idx
  ON security_lab_reports(user_id, created_at DESC);
